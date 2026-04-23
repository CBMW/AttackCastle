from __future__ import annotations

import shutil
import shlex
from hashlib import sha1
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import (
    build_tool_execution,
    current_worker_budget,
    emit_tool_execution_started,
    ordered_parallel_map,
    record_execution_telemetry,
    stream_command,
)
from attackcastle.adapters.targeting import filter_url_targets_for_task_inputs
from attackcastle.adapters.nikto.parser import parse_nikto_json, parse_nikto_text
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, WebApplication, new_id, now_utc
from attackcastle.normalization.correlator import collect_confirmed_web_targets
from attackcastle.proxy import build_subprocess_env, command_text, nikto_proxy_args


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class NiktoAdapter:
    name = "nikto"
    capability = "web_vuln_scan"
    noise_score = 6
    cost_score = 6

    def _build_command(
        self,
        nikto_path: str,
        target_url: str,
        json_path: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("nikto_args", [])
        extra_args = global_config.get("nikto", {}).get("args", [])
        command = [nikto_path, *profile_args, *extra_args, *nikto_proxy_args(proxy_url)]
        command.extend(["-h", target_url, "-Format", "json", "-output", str(json_path)])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        nikto_path = shutil.which("nikto") or "nikto"
        targets = collect_confirmed_web_targets(run_data)
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        for item in targets[:10]:
            url = str(item["url"])
            json_path = context.run_store.artifact_path(self.name, f"nikto_{_safe_name(url)}.json")
            command = self._build_command(
                nikto_path=nikto_path,
                target_url=url,
                json_path=json_path,
                profile_config=context.profile_config,
                global_config=context.config,
                proxy_url=proxy_url or None,
            )
            preview_text = command_text(command, proxy_url or None)
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
            parser_version="nikto_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        nikto_path = shutil.which("nikto")
        scanned_urls: list[str] = []
        failed_urls: list[str] = []
        total_issues = 0

        if not bool(context.config.get("nikto", {}).get("enabled", True)):
            ended_at = now_utc()
            result.facts["nikto.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nikto (disabled)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        if not nikto_path:
            ended_at = now_utc()
            result.warnings.append("nikto binary was not found in PATH. Skipping web vulnerability stage.")
            result.facts["nikto.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nikto",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="nikto_not_found",
                )
            )
            return result

        timeout = int(context.config.get("nikto", {}).get("timeout_seconds", 180))
        existing_scanned = set(run_data.facts.get("nikto.scanned_urls", []))
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        pending_targets = [
            target
            for target in collect_confirmed_web_targets(run_data)
            if str(target["url"]) not in existing_scanned
        ]
        pending_targets = filter_url_targets_for_task_inputs(context, pending_targets)

        def _scan_target(target: dict[str, str | int]) -> dict[str, Any]:
            partial = AdapterResult()
            url = str(target["url"])
            service_key = f"service:{target.get('service_id')}" if target.get("service_id") else ""
            if limiter is not None:
                limiter.throttle(target_key=url, service_key=service_key or None)
            execution_id = new_id("exec")
            slug = _safe_name(url)
            json_path = context.run_store.artifact_path(self.name, f"nikto_{slug}.json")
            stdout_path = context.run_store.artifact_path(self.name, f"nikto_{slug}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"nikto_{slug}.stderr.txt")
            transcript_path = context.run_store.artifact_path(self.name, f"nikto_{slug}.transcript.txt")
            command = self._build_command(
                nikto_path=nikto_path,
                target_url=url,
                json_path=json_path,
                profile_config=context.profile_config,
                global_config=context.config,
                proxy_url=proxy_url or None,
            )
            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            tool_started_at = now_utc()
            raw_command = " ".join(shlex.quote(str(item)) for item in command)
            rendered_command = (
                context.secret_resolver.redact_text(command_text(command, proxy_url or None))
                if context.secret_resolver is not None
                else command_text(command, proxy_url or None)
            )
            emit_tool_execution_started(
                context,
                execution_id=execution_id,
                tool_name=self.name,
                command=rendered_command,
                started_at=tool_started_at,
                capability=self.capability,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                transcript_path=transcript_path,
                raw_artifact_paths=[str(json_path)],
                raw_command=raw_command,
                task_instance_key=getattr(context, "task_instance_key", None),
                task_inputs=list(getattr(context, "task_inputs", []) or []),
            )
            stream_result = stream_command(
                command,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                transcript_path=transcript_path,
                timeout=timeout,
                env=build_subprocess_env(proxy_url or None),
                cancellation_token=getattr(context, "cancellation_token", None),
            )
            stdout_text = stream_result.stdout_text
            exit_code = stream_result.exit_code
            if stream_result.termination_reason != "completed":
                status = "failed"
                error_message = stream_result.termination_detail or f"nikto failed for {url}"
                partial.warnings.append(f"{error_message} for {url}")
            duration_seconds = max((now_utc() - tool_started_at).total_seconds(), 0.001)
            if limiter is not None:
                limiter.record(target_key=url, service_key=service_key or None, success=status == "completed")
            record_execution_telemetry(
                context,
                capability=self.capability,
                success=status == "completed",
                duration_seconds=duration_seconds,
                timeout=stream_result.timed_out,
            )
            parsed = parse_nikto_json(json_path)
            issues = list(parsed.get("issues", []))
            if not issues and stdout_text:
                issues = parse_nikto_text(stdout_text)
            if len(issues) > 200:
                issues = issues[:200]
            web_entity_id = self._ensure_web_entity(run_data, partial, target)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_vuln_scan",
                snippet=("; ".join(issues[:3]) or f"nikto scan for {url}")[:380],
                artifact_path=str(json_path if json_path.exists() else stdout_path),
                selector={"kind": "target", "url": url},
                source_execution_id=execution_id,
                parser_version="nikto_v1",
                confidence=0.85,
            )
            partial.evidence.append(evidence)
            partial.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.nikto.issue_count",
                    value=len(issues),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="nikto_v1",
                )
            )
            if issues:
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.nikto.issues",
                        value=issues,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="nikto_v1",
                    )
                )
            tool_ended_at = now_utc()
            partial.tool_executions.append(
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
                    transcript_path=str(transcript_path),
                    raw_artifact_paths=[str(json_path)],
                    error_message=error_message,
                    termination_reason=stream_result.termination_reason,
                    termination_detail=stream_result.termination_detail,
                    timed_out=stream_result.timed_out,
                    raw_command=raw_command,
                )
            )
            return {"url": url, "issues": issues, "partial": partial}

        remaining_targets = list(pending_targets)
        while remaining_targets:
            worker_count = current_worker_budget(
                context,
                self.capability,
                stage="enumeration",
                pending_count=len(remaining_targets),
                ceiling=len(remaining_targets),
                fallback=1,
            )
            batch = remaining_targets[:worker_count]
            remaining_targets = remaining_targets[worker_count:]
            for item in ordered_parallel_map(batch, max_workers=worker_count, worker=_scan_target):
                partial = item["partial"]
                issues = list(item["issues"])
                total_issues += len(issues)
                result.web_apps.extend(partial.web_apps)
                result.evidence.extend(partial.evidence)
                result.observations.extend(partial.observations)
                result.tool_executions.extend(partial.tool_executions)
                result.warnings.extend(partial.warnings)
                if any(getattr(execution, "status", "") == "completed" for execution in partial.tool_executions):
                    scanned_urls.append(str(item["url"]))
                else:
                    failed_urls.append(str(item["url"]))

        ended_at = now_utc()
        scanned_set = sorted(existing_scanned.union(scanned_urls))
        attempted_urls = sorted({str(item["url"]) for item in pending_targets})
        result.facts.update(
            {
                "nikto.available": True,
                "nikto.attempted_urls": attempted_urls,
                "nikto.completed_urls": scanned_set,
                "nikto.failed_urls": sorted(set(failed_urls)),
                "nikto.scanned_targets": len(scanned_urls),
                "nikto.scanned_urls": scanned_set,
                "nikto.total_issues": total_issues,
            }
        )
        if not scanned_urls:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nikto (no new targets)",
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
                "issues": total_issues,
            },
        )
        return result
