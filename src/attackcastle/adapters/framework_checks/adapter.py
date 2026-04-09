from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from hashlib import sha1
from pathlib import Path

from attackcastle.adapters.base import build_tool_execution
from attackcastle.adapters.nuclei.parser import parse_nuclei_jsonl
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, WebApplication, new_id, now_utc
from attackcastle.policy import risk_controls_from_context
from attackcastle.proxy import build_subprocess_env, command_text as format_command_text, nuclei_proxy_args

FRAMEWORK_TAGS: dict[str, list[str]] = {
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "laravel": ["laravel"],
    "next.js": ["nextjs", "next"],
    "nextjs": ["nextjs", "next"],
    "wordpress": ["wordpress"],
}


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class FrameworkChecksAdapter:
    name = "framework_checks"
    capability = "cms_framework_scan"
    noise_score = 5
    cost_score = 6

    def _frameworks_for_webapp(self, run_data: RunData) -> dict[str, set[str]]:
        by_webapp: dict[str, set[str]] = {}
        for technology in run_data.technologies:
            webapp_id = technology.webapp_id
            if not webapp_id:
                continue
            token = str(technology.name or "").lower()
            for key in FRAMEWORK_TAGS:
                if key in token:
                    by_webapp.setdefault(webapp_id, set()).add(key)
        for observation in run_data.observations:
            if observation.entity_type != "web_app":
                continue
            if not observation.key.startswith("tech.") or not observation.key.endswith(".detected"):
                continue
            if observation.value is not True:
                continue
            token = observation.key[len("tech.") : -len(".detected")].lower()
            token = token.replace("_", ".")
            if token in FRAMEWORK_TAGS:
                by_webapp.setdefault(observation.entity_id, set()).add(token)
        return by_webapp

    def _ensure_web_entity(
        self,
        run_data: RunData,
        result: AdapterResult,
        url: str,
        asset_id: str,
        service_id: str | None,
    ) -> str:
        for web in run_data.web_apps:
            if web.url == url:
                return web.webapp_id
        for web in result.web_apps:
            if web.url == url:
                return web.webapp_id
        web_app = WebApplication(
            webapp_id=new_id("web"),
            asset_id=asset_id,
            service_id=service_id,
            url=url,
            source_tool=self.name,
            parser_version="framework_checks_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def _build_command(
        self,
        nuclei_path: str,
        target_url: str,
        output_path: Path,
        tags: list[str],
        profile_config: dict[str, object],
        global_config: dict[str, object],
        risk_controls: dict[str, object],
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = list(profile_config.get("nuclei_args", [])) if isinstance(profile_config, dict) else []
        extra_args = list(global_config.get("nuclei", {}).get("args", [])) if isinstance(global_config, dict) else []
        command = [nuclei_path, *profile_args, *extra_args, *nuclei_proxy_args(proxy_url)]
        if tags:
            command.extend(["-tags", ",".join(tags)])
        if not bool(risk_controls.get("allow_heavy_templates", False)) and "-severity" not in command:
            command.extend(["-severity", "critical,high,medium"])
        command.extend(["-u", target_url, "-json", "-o", str(output_path)])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        frameworks = self._frameworks_for_webapp(run_data)
        nuclei_path = shutil.which("nuclei") or "nuclei"
        risk_controls = risk_controls_from_context(context)
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        web_lookup = {item.webapp_id: item for item in run_data.web_apps}
        for webapp_id, tags in list(frameworks.items())[:8]:
            web = web_lookup.get(webapp_id)
            if not web:
                continue
            out_path = context.run_store.artifact_path(self.name, f"framework_{_safe_name(web.url)}.jsonl")
            command = self._build_command(
                nuclei_path=nuclei_path,
                target_url=web.url,
                output_path=out_path,
                tags=sorted({tag for key in tags for tag in FRAMEWORK_TAGS.get(key, [])}),
                profile_config=context.profile_config,
                global_config=context.config,
                risk_controls=risk_controls,
                proxy_url=proxy_url or None,
            )
            preview_text = format_command_text(command, proxy_url or None)
            if context.secret_resolver is not None:
                preview_text = context.secret_resolver.redact_text(preview_text)
            previews.append(preview_text)
        return previews

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        nuclei_path = shutil.which("nuclei")
        risk_controls = risk_controls_from_context(context)

        if not nuclei_path:
            ended_at = now_utc()
            result.warnings.append("nuclei binary was not found in PATH. Skipping framework checks stage.")
            result.facts["framework_checks.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nuclei",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="nuclei_not_found",
                )
            )
            return result

        timeout = int(context.config.get("framework_checks", {}).get("timeout_seconds", 240))
        frameworks = self._frameworks_for_webapp(run_data)
        web_lookup = {item.webapp_id: item for item in run_data.web_apps}
        scanned_targets = 0
        issue_count = 0
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        for webapp_id, detected_keys in frameworks.items():
            web = web_lookup.get(webapp_id)
            if not web:
                continue
            framework_tags = sorted({tag for key in detected_keys for tag in FRAMEWORK_TAGS.get(key, [])})
            if not framework_tags:
                continue
            scanned_targets += 1
            service_key = f"service:{web.service_id}" if web.service_id else None
            if limiter is not None:
                limiter.throttle(target_key=web.url, service_key=service_key)
            execution_id = new_id("exec")
            output_path = context.run_store.artifact_path(self.name, f"framework_{_safe_name(web.url)}.jsonl")
            stdout_path = context.run_store.artifact_path(self.name, f"framework_{_safe_name(web.url)}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"framework_{_safe_name(web.url)}.stderr.txt")
            command = self._build_command(
                nuclei_path=nuclei_path,
                target_url=web.url,
                output_path=output_path,
                tags=framework_tags,
                profile_config=context.profile_config,
                global_config=context.config,
                risk_controls=risk_controls,
                proxy_url=proxy_url or None,
            )

            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            stdout_text = ""
            tool_started_at = now_utc()
            try:
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    env=build_subprocess_env(proxy_url or None),
                )
                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
                stdout_path.write_text(stdout_text, encoding="utf-8")
                stderr_path.write_text(stderr_text, encoding="utf-8")
                exit_code = proc.returncode
                if proc.returncode != 0:
                    status = "failed"
                    error_message = f"framework checks exited with code {proc.returncode}"
            except subprocess.TimeoutExpired:
                status = "failed"
                error_message = f"framework checks exceeded timeout of {timedelta(seconds=timeout)}"
            except Exception as exc:  # noqa: BLE001
                status = "failed"
                error_message = str(exc)
            if limiter is not None:
                limiter.record(
                    target_key=web.url,
                    service_key=service_key,
                    success=status == "completed",
                )

            issues = parse_nuclei_jsonl(output_path)
            issue_count += len(issues)
            web_entity_id = self._ensure_web_entity(
                run_data=run_data,
                result=result,
                url=web.url,
                asset_id=web.asset_id,
                service_id=web.service_id,
            )
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="framework_checks",
                snippet=(
                    "; ".join(item.get("name", "") for item in issues[:3])
                    or f"framework checks for {web.url}"
                )[:380],
                artifact_path=str(output_path if output_path.exists() else stdout_path),
                selector={"kind": "target", "url": web.url, "frameworks": list(detected_keys)},
                source_execution_id=execution_id,
                parser_version="framework_checks_v1",
                confidence=0.8,
            )
            result.evidence.append(evidence)
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="framework.scan.issue_count",
                    value=len(issues),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="framework_checks_v1",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="framework.scan.targets",
                    value=sorted(detected_keys),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="framework_checks_v1",
                )
            )
            tool_ended_at = now_utc()
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=(
                        context.secret_resolver.redact_text(format_command_text(command, proxy_url or None))
                        if context.secret_resolver is not None
                        else format_command_text(command, proxy_url or None)
                    ),
                    started_at=tool_started_at,
                    ended_at=tool_ended_at,
                    status=status,
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=exit_code,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                    raw_artifact_paths=[str(output_path)],
                    error_message=error_message,
                )
            )

        ended_at = now_utc()
        result.facts["framework_checks.available"] = True
        result.facts["framework_checks.scanned_targets"] = scanned_targets
        result.facts["framework_checks.issue_count"] = issue_count
        if scanned_targets == 0:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nuclei framework checks (no detected framework targets)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "scanned_targets": scanned_targets,
                "issues": issue_count,
            },
        )
        return result
