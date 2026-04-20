from __future__ import annotations

import shutil
import shlex
from datetime import timedelta
from hashlib import sha1
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import (
    batched,
    build_tool_execution,
    current_worker_budget,
    ordered_parallel_map,
    record_execution_telemetry,
    stream_command,
)
from attackcastle.adapters.targeting import filter_url_targets_for_task_inputs
from attackcastle.adapters.nuclei.parser import parse_nuclei_jsonl
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, WebApplication, new_id, now_utc
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.normalization.correlator import collect_confirmed_web_targets
from attackcastle.policy import risk_controls_from_context
from attackcastle.proxy import build_subprocess_env, command_text as format_command_text, nuclei_proxy_args


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class NucleiAdapter:
    name = "nuclei"
    capability = "web_template_scan"
    noise_score = 6
    cost_score = 6

    def _build_command(
        self,
        nuclei_path: str,
        target_url: str,
        output_path: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        risk_controls: dict[str, Any],
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("nuclei_args", [])
        extra_args = global_config.get("nuclei", {}).get("args", [])
        command = [nuclei_path, *profile_args, *extra_args, *nuclei_proxy_args(proxy_url)]
        if not bool(risk_controls.get("allow_heavy_templates", False)):
            lowered: list[str] = []
            for item in command:
                token = str(item).lower()
                if any(marker in token for marker in ("fuzz", "dos", "brute", "auth-bypass", "rce")):
                    continue
                lowered.append(str(item))
            command = lowered
            if "-severity" not in command:
                command.extend(["-severity", "critical,high,medium"])
        command.extend(["-u", target_url, "-json", "-o", str(output_path)])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        nuclei_path = shutil.which("nuclei") or "nuclei"
        risk_controls = risk_controls_from_context(context)
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        for target in collect_confirmed_web_targets(run_data)[:10]:
            url = str(target["url"])
            out_path = context.run_store.artifact_path(self.name, f"nuclei_{_safe_name(url)}.jsonl")
            command = self._build_command(
                nuclei_path=nuclei_path,
                target_url=url,
                output_path=out_path,
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

    def _ensure_web_entity(self, run_data: RunData, result: AdapterResult, target: dict[str, str | int]) -> str:
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
            parser_version="nuclei_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        nuclei_path = shutil.which("nuclei")

        if not bool(context.config.get("nuclei", {}).get("enabled", True)):
            ended_at = now_utc()
            result.facts["nuclei.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nuclei (disabled)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        if not nuclei_path:
            ended_at = now_utc()
            result.warnings.append("nuclei binary was not found in PATH. Skipping template scan stage.")
            result.facts["nuclei.available"] = False
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

        timeout = int(context.config.get("nuclei", {}).get("timeout_seconds", 300))
        risk_controls = risk_controls_from_context(context)
        existing_scanned = set(run_data.facts.get("nuclei.scanned_urls", []))
        scanned_urls: list[str] = []
        failed_urls: list[str] = []
        total_issues = 0
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
            jsonl_path = context.run_store.artifact_path(self.name, f"nuclei_{slug}.jsonl")
            stdout_path = context.run_store.artifact_path(self.name, f"nuclei_{slug}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"nuclei_{slug}.stderr.txt")
            transcript_path = context.run_store.artifact_path(self.name, f"nuclei_{slug}.transcript.txt")
            command = self._build_command(
                nuclei_path=nuclei_path,
                target_url=url,
                output_path=jsonl_path,
                profile_config=context.profile_config,
                global_config=context.config,
                risk_controls=risk_controls,
                proxy_url=proxy_url or None,
            )
            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            tool_started_at = now_utc()
            emit_runtime_event(context, "task.progress", {"adapter": self.name, "phase": "url_started", "url": url})
            stream_result = stream_command(
                command,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                transcript_path=transcript_path,
                timeout=timeout,
                env=build_subprocess_env(proxy_url or None),
                on_stdout=lambda chunk: emit_runtime_event(
                    context,
                    "tool.output",
                    {"tool_name": self.name, "stream": "stdout", "text": chunk[-400:]},
                ),
                on_stderr=lambda chunk: emit_runtime_event(
                    context,
                    "tool.output",
                    {"tool_name": self.name, "stream": "stderr", "text": chunk[-400:]},
                ),
                cancellation_token=getattr(context, "cancellation_token", None),
            )
            exit_code = stream_result.exit_code
            if stream_result.termination_reason == "timeout":
                status = "failed"
                error_message = stream_result.termination_detail or f"nuclei exceeded timeout of {timedelta(seconds=timeout)}"
                partial.warnings.append(f"{error_message} for {url}")
            elif stream_result.termination_reason != "completed" and exit_code is None:
                status = "failed"
                error_message = stream_result.termination_detail or "nuclei execution failed"
                partial.warnings.append(f"{error_message} for {url}")
            elif stream_result.termination_reason != "completed" and exit_code != 0:
                status = "failed"
                error_message = stream_result.termination_detail or f"nuclei exited with code {exit_code}"
                partial.warnings.append(f"{error_message} for {url}")
            duration_seconds = max((now_utc() - tool_started_at).total_seconds(), 0.001)
            timed_out = stream_result.timed_out
            if limiter is not None:
                limiter.record(target_key=url, service_key=service_key or None, success=status == "completed")
            record_execution_telemetry(
                context,
                capability=self.capability,
                success=status == "completed",
                duration_seconds=duration_seconds,
                timeout=timed_out,
            )
            issues = parse_nuclei_jsonl(jsonl_path)
            if len(issues) > 300:
                issues = issues[:300]
            if jsonl_path.exists():
                emit_artifact_event(
                    context,
                    artifact_path=jsonl_path,
                    kind="nuclei_jsonl",
                    source_tool=self.name,
                    caption=f"Nuclei output for {url}",
                )
            web_entity_id = self._ensure_web_entity(run_data, partial, target)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_template_scan",
                snippet=("; ".join(item["name"] for item in issues[:3]) or f"nuclei scan for {url}")[:380],
                artifact_path=str(jsonl_path if jsonl_path.exists() else stdout_path),
                selector={"kind": "target", "url": url},
                source_execution_id=execution_id,
                parser_version="nuclei_v1",
                confidence=0.85,
            )
            partial.evidence.append(evidence)
            partial.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.nuclei.issue_count",
                    value=len(issues),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.85,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="nuclei_v1",
                )
            )
            if issues:
                partial.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.nuclei.issues",
                        value=issues,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.82,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="nuclei_v1",
                    )
                )
            for issue in issues[:50]:
                template_id = issue.get("template_id")
                if template_id:
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="vuln.template.detected",
                            value=str(template_id),
                            entity_type="web_app",
                            entity_id=web_entity_id,
                            source_tool=self.name,
                            confidence=0.8,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="nuclei_v1",
                        )
                    )
            emit_runtime_event(
                context,
                "task.progress",
                {"adapter": self.name, "phase": "url_parsed", "url": url, "issues": len(issues)},
            )
            tool_ended_at = now_utc()
            partial.tool_executions.append(
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
                    transcript_path=str(transcript_path),
                    raw_artifact_paths=[str(jsonl_path)],
                    error_message=error_message,
                    termination_reason=stream_result.termination_reason,
                    termination_detail=stream_result.termination_detail,
                    timed_out=stream_result.timed_out,
                    raw_command=" ".join(shlex.quote(str(item)) for item in command),
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
                url = str(item["url"])
                issues = list(item["issues"])
                total_issues += len(issues)
                result.web_apps.extend(partial.web_apps)
                result.evidence.extend(partial.evidence)
                result.observations.extend(partial.observations)
                result.tool_executions.extend(partial.tool_executions)
                result.warnings.extend(partial.warnings)
                for evidence in partial.evidence:
                    emit_entity_event(context, "evidence", evidence, source=self.name)
                if any(getattr(execution, "status", "") == "completed" for execution in partial.tool_executions):
                    scanned_urls.append(url)
                else:
                    failed_urls.append(url)

        ended_at = now_utc()
        scanned_set = sorted(existing_scanned.union(scanned_urls))
        attempted_urls = sorted({str(item["url"]) for item in pending_targets})
        result.facts.update(
            {
                "nuclei.available": True,
                "nuclei.attempted_urls": attempted_urls,
                "nuclei.completed_urls": scanned_set,
                "nuclei.failed_urls": sorted(set(failed_urls)),
                "nuclei.scanned_targets": len(scanned_urls),
                "nuclei.scanned_urls": scanned_set,
                "nuclei.total_issues": total_issues,
            }
        )
        if not scanned_urls:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nuclei (no new targets)",
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
