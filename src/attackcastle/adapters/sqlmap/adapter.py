from __future__ import annotations

import shutil
import shlex
from hashlib import sha1
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution, current_tool_budget, emit_tool_execution_started, stream_command
from attackcastle.adapters.sqlmap.parser import parse_sqlmap_output
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, WebApplication, new_id, now_utc
from attackcastle.normalization.correlator import collect_sqlmap_targets
from attackcastle.policy import risk_controls_from_context
from attackcastle.proxy import build_subprocess_env, command_text as format_command_text, sqlmap_proxy_args


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class SQLMapAdapter:
    name = "sqlmap"
    capability = "web_injection_scan"
    noise_score = 7
    cost_score = 8

    def _build_command(
        self,
        sqlmap_path: str,
        target_url: str,
        output_dir: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        thread_override: int | None = None,
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("sqlmap_args", [])
        extra_args = global_config.get("sqlmap", {}).get("args", [])
        command = [sqlmap_path, *profile_args, *extra_args, *sqlmap_proxy_args(proxy_url)]
        command.extend(
            [
                "-u",
                target_url,
                "--batch",
                "--smart",
                "--level",
                str(global_config.get("sqlmap", {}).get("level", 1)),
                "--risk",
                str(global_config.get("sqlmap", {}).get("risk", 1)),
                "--output-dir",
                str(output_dir),
            ]
        )
        if "--flush-session" not in command and bool(global_config.get("sqlmap", {}).get("flush_session", False)):
            command.append("--flush-session")
        if thread_override is not None and "--threads" not in command:
            command.extend(["--threads", str(thread_override)])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        sqlmap_path = shutil.which("sqlmap") or "sqlmap"
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        for target in collect_sqlmap_targets(run_data)[:8]:
            url = str(target["url"])
            out_dir = context.run_store.artifact_path(self.name, f"sqlmap_{_safe_name(url)}")
            command = self._build_command(
                sqlmap_path=sqlmap_path,
                target_url=url,
                output_dir=out_dir,
                profile_config=context.profile_config,
                global_config=context.config,
                thread_override=current_tool_budget(
                    context,
                    self.capability,
                    target_count=1,
                ).get("threads"),
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
            parser_version="sqlmap_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        sqlmap_path = shutil.which("sqlmap")
        risk_controls = risk_controls_from_context(context)
        if not bool(risk_controls.get("allow_sqlmap", False)):
            ended_at = now_utc()
            result.facts["sqlmap.available"] = True
            result.facts["sqlmap.blocked_by_risk_mode"] = True
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="sqlmap",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="blocked",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="blocked_by_risk_mode",
                )
            )
            return result

        if not sqlmap_path:
            ended_at = now_utc()
            result.warnings.append("sqlmap binary was not found in PATH. Skipping injection scan stage.")
            result.facts["sqlmap.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="sqlmap",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="sqlmap_not_found",
                )
            )
            return result

        timeout = int(context.config.get("sqlmap", {}).get("timeout_seconds", 300))
        min_candidate_score = int(context.config.get("sqlmap", {}).get("min_candidate_score", 5))
        max_targets = int(risk_controls.get("max_sqlmap_targets", 6))
        existing_scanned = set(run_data.facts.get("sqlmap.scanned_urls", []))
        scanned_urls: list[str] = []
        failed_urls: list[str] = []
        injectable_urls: list[str] = []
        low_score_skipped = 0
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        sqlmap_targets = collect_sqlmap_targets(run_data)
        scored_targets: list[dict[str, str | int]] = []
        for item in sqlmap_targets:
            score = int(item.get("score", 0))
            if score < min_candidate_score:
                low_score_skipped += 1
                continue
            scored_targets.append(item)
        if max_targets > 0:
            scored_targets = scored_targets[:max_targets]

        for target in scored_targets:
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
            output_dir = context.run_store.artifact_path(self.name, f"sqlmap_{slug}")
            output_dir.mkdir(parents=True, exist_ok=True)
            stdout_path = context.run_store.artifact_path(self.name, f"sqlmap_{slug}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"sqlmap_{slug}.stderr.txt")
            transcript_path = context.run_store.artifact_path(self.name, f"sqlmap_{slug}.transcript.txt")
            command = self._build_command(
                sqlmap_path=sqlmap_path,
                target_url=url,
                output_dir=output_dir,
                profile_config=context.profile_config,
                global_config=context.config,
                thread_override=current_tool_budget(
                    context,
                    self.capability,
                    target_count=1,
                ).get("threads"),
                proxy_url=proxy_url or None,
            )

            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            stdout_text = ""
            stderr_text = ""
            tool_started_at = now_utc()
            raw_command = " ".join(shlex.quote(str(item)) for item in command)
            rendered_command = (
                context.secret_resolver.redact_text(format_command_text(command, proxy_url or None))
                if context.secret_resolver is not None
                else format_command_text(command, proxy_url or None)
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
                raw_artifact_paths=[str(output_dir)],
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
            stderr_text = stream_result.stderr_text
            exit_code = stream_result.exit_code
            if stream_result.termination_reason != "completed":
                status = "failed"
                error_message = stream_result.termination_detail or f"sqlmap failed for {url}"
                result.warnings.append(f"{error_message} for {url}")
            if limiter is not None:
                limiter.record(
                    target_key=url,
                    service_key=service_key or None,
                    success=status == "completed",
                )

            parsed = parse_sqlmap_output(stdout_text, stderr_text)
            web_entity_id = self._ensure_web_entity(run_data, result, target)
            if parsed["injectable"]:
                injectable_urls.append(url)

            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_injection_scan",
                snippet=("; ".join(parsed.get("evidence_lines", [])[:3]) or f"sqlmap scan for {url}")[:380],
                artifact_path=str(stdout_path),
                selector={"kind": "target", "url": url},
                source_execution_id=execution_id,
                parser_version="sqlmap_v1",
                confidence=0.85,
            )
            result.evidence.append(evidence)
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.sqlmap.tested",
                    value=True,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.85,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="sqlmap_v1",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.sqlmap.candidate_score",
                    value=int(target.get("score", 0)),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="sqlmap_v1",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.sqlmap.injectable",
                    value=bool(parsed["injectable"]),
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.85,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="sqlmap_v1",
                )
            )
            if parsed.get("dbms"):
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.sqlmap.dbms",
                        value=str(parsed["dbms"]),
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="sqlmap_v1",
                    )
                )

            tool_ended_at = now_utc()
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
                    transcript_path=str(transcript_path),
                    raw_artifact_paths=[str(output_dir)],
                    error_message=error_message,
                    termination_reason=stream_result.termination_reason,
                    termination_detail=stream_result.termination_detail,
                    timed_out=stream_result.timed_out,
                    raw_command=raw_command,
                )
            )
            if status == "completed":
                scanned_urls.append(url)
            else:
                failed_urls.append(url)

        ended_at = now_utc()
        scanned_set = sorted(existing_scanned.union(scanned_urls))
        attempted_urls = sorted(
            {
                str(item.get("url") or "").strip()
                for item in pending_targets[:max_targets]
                if str(item.get("url") or "").strip()
            }
        )
        result.facts.update(
            {
                "sqlmap.available": True,
                "sqlmap.attempted_urls": attempted_urls,
                "sqlmap.completed_urls": scanned_set,
                "sqlmap.failed_urls": sorted(set(failed_urls)),
                "sqlmap.scanned_targets": len(scanned_urls),
                "sqlmap.scanned_urls": scanned_set,
                "sqlmap.injectable_count": len(injectable_urls),
                "sqlmap.injectable_urls": sorted(injectable_urls),
                "sqlmap.low_score_skipped": low_score_skipped,
            }
        )
        if not scanned_urls:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="sqlmap (no new targets)",
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
                "injectable_targets": len(injectable_urls),
            },
        )
        return result
