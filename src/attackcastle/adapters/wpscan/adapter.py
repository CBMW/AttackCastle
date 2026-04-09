from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from hashlib import sha1
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution
from attackcastle.adapters.wpscan.parser import parse_wpscan_json
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, Technology, WebApplication, new_id, now_utc
from attackcastle.normalization.correlator import collect_wordpress_targets
from attackcastle.policy import risk_controls_from_context
from attackcastle.proxy import build_subprocess_env, command_text as format_command_text, wpscan_proxy_args


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class WPScanAdapter:
    name = "wpscan"
    capability = "cms_wordpress_scan"
    noise_score = 6
    cost_score = 7

    def _build_command(
        self,
        wpscan_path: str,
        target_url: str,
        json_path: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        risk_controls: dict[str, Any],
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("wpscan_args", [])
        extra_args = global_config.get("wpscan", {}).get("args", [])
        command = [wpscan_path, *profile_args, *extra_args, *wpscan_proxy_args(proxy_url)]
        command.extend(
            [
                "--url",
                target_url,
                "--format",
                "json",
                "--output",
                str(json_path),
                "--disable-tls-checks",
            ]
        )
        if "--no-update" not in command:
            command.append("--no-update")
        if not bool(risk_controls.get("allow_heavy_templates", False)):
            for index, item in enumerate(command):
                if str(item) == "--plugins-detection" and index + 1 < len(command):
                    command[index + 1] = "passive"
        if not bool(risk_controls.get("allow_auth_bruteforce", False)):
            blocked = {"--passwords", "--usernames", "--password-attack", "--enumerate", "u,p"}
            sanitized: list[str] = []
            skip_next = False
            for item in command:
                if skip_next:
                    skip_next = False
                    continue
                token = str(item)
                if token in {"--passwords", "--usernames", "--password-attack"}:
                    skip_next = True
                    continue
                if token in blocked:
                    continue
                sanitized.append(token)
            command = sanitized
        api_token = global_config.get("wpscan", {}).get("api_token")
        if api_token and "--api-token" not in command:
            command.extend(["--api-token", str(api_token)])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        wpscan_path = shutil.which("wpscan") or "wpscan"
        risk_controls = risk_controls_from_context(context)
        targets = collect_wordpress_targets(run_data)
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        for item in targets[:10]:
            url = str(item["url"])
            json_path = context.run_store.artifact_path(self.name, f"wpscan_{_safe_name(url)}.json")
            command = self._build_command(
                wpscan_path=wpscan_path,
                target_url=url,
                json_path=json_path,
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

    def _ensure_web_entity(
        self,
        run_data: RunData,
        result: AdapterResult,
        target: dict[str, str | int],
    ) -> str:
        existing_id = str(target.get("webapp_id") or "").strip()
        if existing_id:
            return existing_id
        url = str(target["url"])
        for web_app in run_data.web_apps:
            if web_app.url == url:
                return web_app.webapp_id
        for web_app in result.web_apps:
            if web_app.url == url:
                return web_app.webapp_id
        web_app = WebApplication(
            webapp_id=new_id("web"),
            asset_id=str(target.get("asset_id") or ""),
            service_id=str(target.get("service_id") or "") or None,
            url=url,
            source_tool=self.name,
            parser_version="wpscan_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        wpscan_path = shutil.which("wpscan")

        if not wpscan_path:
            ended_at = now_utc()
            result.warnings.append("wpscan binary was not found in PATH. Skipping WordPress scan stage.")
            result.facts["wpscan.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="wpscan",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="wpscan_not_found",
                )
            )
            return result

        timeout = int(context.config.get("wpscan", {}).get("timeout_seconds", 300))
        risk_controls = risk_controls_from_context(context)
        existing_scanned = set(run_data.facts.get("wpscan.scanned_urls", []))
        scanned_urls: list[str] = []
        vulnerability_total = 0
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        for target in collect_wordpress_targets(run_data):
            url = str(target["url"])
            if url in existing_scanned:
                continue
            service_key = ""
            if target.get("service_id"):
                service_key = f"service:{target.get('service_id')}"
            if limiter is not None:
                limiter.throttle(target_key=url, service_key=service_key or None)

            execution_id = new_id("exec")
            slug = _safe_name(url)
            json_path = context.run_store.artifact_path(self.name, f"wpscan_{slug}.json")
            stdout_path = context.run_store.artifact_path(self.name, f"wpscan_{slug}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"wpscan_{slug}.stderr.txt")
            command = self._build_command(
                wpscan_path=wpscan_path,
                target_url=url,
                json_path=json_path,
                profile_config=context.profile_config,
                global_config=context.config,
                risk_controls=risk_controls,
                proxy_url=proxy_url or None,
            )

            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            tool_started_at = now_utc()
            stdout_text = ""
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
                    error_message = f"wpscan exited with code {proc.returncode}"
                    result.warnings.append(f"{error_message} for {url}")
            except subprocess.TimeoutExpired:
                status = "failed"
                error_message = f"wpscan exceeded timeout of {timedelta(seconds=timeout)}"
                result.warnings.append(f"{error_message} for {url}")
                stdout_path.write_text(stdout_text, encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                status = "failed"
                error_message = str(exc)
                result.warnings.append(f"WPScan failed for {url}: {exc}")
            if limiter is not None:
                limiter.record(
                    target_key=url,
                    service_key=service_key or None,
                    success=status == "completed",
                )

            parsed = parse_wpscan_json(json_path)
            version = parsed.get("wordpress_version")
            vulnerabilities = list(parsed.get("vulnerability_titles", []))
            interesting_findings = int(parsed.get("interesting_findings", 0))
            if len(vulnerabilities) > 200:
                vulnerabilities = vulnerabilities[:200]
            vulnerability_total += len(vulnerabilities)

            web_entity_id = self._ensure_web_entity(run_data, result, target)
            evidence_path = str(json_path if json_path.exists() else stdout_path)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="wordpress_scan",
                snippet=(
                    "; ".join(vulnerabilities[:3])
                    or f"WordPress scan for {url}"
                )[:380],
                artifact_path=evidence_path,
                selector={"kind": "target", "url": url},
                source_execution_id=execution_id,
                parser_version="wpscan_v1",
                confidence=0.9,
            )
            result.evidence.append(evidence)

            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="tech.wordpress.detected",
                    value=True,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.99,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="wpscan_v1",
                )
            )
            if version:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="tech.wordpress.version",
                        value=str(version),
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.97,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="wpscan_v1",
                    )
                )
                result.technologies.append(
                    Technology(
                        tech_id=new_id("tech"),
                        asset_id=str(target.get("asset_id") or ""),
                        webapp_id=web_entity_id,
                        name="WordPress",
                        version=str(version),
                        confidence=0.98,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="wpscan_v1",
                    )
                )

            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="wp.vulnerabilities.count",
                    value=len(vulnerabilities),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="wpscan_v1",
                )
            )
            if vulnerabilities:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="wp.vulnerabilities.titles",
                        value=vulnerabilities,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.85,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="wpscan_v1",
                    )
                )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="wp.interesting_findings.count",
                    value=interesting_findings,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="wpscan_v1",
                )
            )

            tool_ended_at = now_utc()
            rendered_command = format_command_text(command, proxy_url or None)
            if context.secret_resolver is not None:
                rendered_command = context.secret_resolver.redact_text(rendered_command)
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=rendered_command,
                    started_at=tool_started_at,
                    ended_at=tool_ended_at,
                    status=status,
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=exit_code,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                    raw_artifact_paths=[str(json_path)],
                    error_message=error_message,
                )
            )
            scanned_urls.append(url)

        ended_at = now_utc()
        scanned_set = sorted(existing_scanned.union(scanned_urls))
        result.facts.update(
            {
                "wpscan.available": True,
                "wpscan.scanned_targets": len(scanned_urls),
                "wpscan.scanned_urls": scanned_set,
                "wpscan.vulnerability_total": vulnerability_total,
            }
        )
        if not scanned_urls:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="wpscan (no new targets)",
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
                "scanned_targets": len(scanned_urls),
                "vulnerability_total": vulnerability_total,
            },
        )
        return result
