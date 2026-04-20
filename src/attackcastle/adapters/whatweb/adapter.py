from __future__ import annotations

import shutil
import shlex
from hashlib import sha1
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import (
    build_tool_execution,
    current_worker_budget,
    ordered_parallel_map,
    record_execution_telemetry,
    stream_command,
)
from attackcastle.adapters.targeting import filter_url_targets_for_task_inputs
from attackcastle.adapters.whatweb.parser import parse_whatweb_json, parse_whatweb_text
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, Technology, WebApplication, new_id, now_utc
from attackcastle.core.runtime_events import emit_entity_event
from attackcastle.normalization.correlator import collect_confirmed_web_targets
from attackcastle.proxy import build_subprocess_env, command_text, whatweb_proxy_args


def _safe_name(value: str) -> str:
    digest = sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return digest


class WhatWebAdapter:
    name = "whatweb"
    capability = "web_fingerprint"
    noise_score = 4
    cost_score = 4

    def _build_command(
        self,
        whatweb_path: str,
        target_url: str,
        json_path: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        proxy_url: str | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("whatweb_args", [])
        extra_args = global_config.get("whatweb", {}).get("args", [])
        command = [whatweb_path, *profile_args, *extra_args, *whatweb_proxy_args(proxy_url)]
        command.extend(["--log-json", str(json_path), target_url])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        whatweb_path = shutil.which("whatweb") or "whatweb"
        targets = collect_confirmed_web_targets(run_data)
        previews: list[str] = []
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        for item in targets[:20]:
            url = str(item["url"])
            artifact_name = f"whatweb_{_safe_name(url)}.json"
            json_path = context.run_store.artifact_path(self.name, artifact_name)
            command = self._build_command(
                whatweb_path=whatweb_path,
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
            parser_version="whatweb_v1",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        whatweb_path = shutil.which("whatweb")
        execution_ids: list[str] = []
        scanned_urls: list[str] = []
        failed_urls: list[str] = []
        discovered_wordpress = 0
        discovered_framework_signals = 0

        if not bool(context.config.get("whatweb", {}).get("enabled", True)):
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="whatweb (disabled)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["whatweb.available"] = False
            return result

        if not whatweb_path:
            ended_at = now_utc()
            result.warnings.append("whatweb binary was not found in PATH. Skipping web fingerprint stage.")
            result.facts["whatweb.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="whatweb",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="whatweb_not_found",
                )
            )
            return result

        timeout = int(context.config.get("whatweb", {}).get("timeout_seconds", 45))
        existing_scanned = set(run_data.facts.get("whatweb.scanned_urls", []))
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        pending_targets = [
            target for target in collect_confirmed_web_targets(run_data) if str(target["url"]) not in existing_scanned
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
            json_path = context.run_store.artifact_path(self.name, f"whatweb_{slug}.json")
            stdout_path = context.run_store.artifact_path(self.name, f"whatweb_{slug}.stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"whatweb_{slug}.stderr.txt")
            transcript_path = context.run_store.artifact_path(self.name, f"whatweb_{slug}.transcript.txt")
            command = self._build_command(
                whatweb_path=whatweb_path,
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
                error_message = stream_result.termination_detail or f"whatweb failed for {url}"
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
            parsed_entries = parse_whatweb_json(json_path)
            if not parsed_entries and stdout_text.strip():
                parsed_entries = [parse_whatweb_text(stdout_text.strip())]
            web_entity_id = self._ensure_web_entity(run_data, partial, target)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_fingerprint",
                snippet=(stdout_text[:350] or f"whatweb scan for {url}")[:350],
                artifact_path=str(json_path) if json_path.exists() else str(stdout_path),
                selector={"kind": "target", "url": url},
                source_execution_id=execution_id,
                parser_version="whatweb_v1",
                confidence=0.9,
            )
            partial.evidence.append(evidence)
            wordpress_hits = 0
            framework_hits = 0
            for parsed in parsed_entries:
                technologies = parsed.get("technologies", [])
                if isinstance(technologies, list):
                    for item in technologies:
                        if not isinstance(item, tuple) or len(item) != 3:
                            continue
                        tech_name, tech_version, confidence = item
                        partial.technologies.append(
                            Technology(
                                tech_id=new_id("tech"),
                                asset_id=str(target.get("asset_id") or ""),
                                webapp_id=web_entity_id,
                                name=str(tech_name),
                                version=str(tech_version) if tech_version else None,
                                confidence=float(confidence),
                                source_tool=self.name,
                                source_execution_id=execution_id,
                                parser_version="whatweb_v1",
                            )
                        )
                if bool(parsed.get("wordpress_detected")):
                    wordpress_hits += 1
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="tech.wordpress.detected",
                            value=True,
                            entity_type="web_app",
                            entity_id=web_entity_id,
                            source_tool=self.name,
                            confidence=0.95,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="whatweb_v1",
                        )
                    )
                if parsed.get("wordpress_version"):
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="tech.wordpress.version",
                            value=str(parsed.get("wordpress_version")),
                            entity_type="web_app",
                            entity_id=web_entity_id,
                            source_tool=self.name,
                            confidence=0.9,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="whatweb_v1",
                        )
                    )
                framework_detections = parsed.get("framework_detections", [])
                if isinstance(framework_detections, list):
                    for framework in framework_detections:
                        if not isinstance(framework, tuple) or len(framework) != 2:
                            continue
                        framework_name = str(framework[0]).strip().lower()
                        framework_version = str(framework[1]).strip() if framework[1] else None
                        if not framework_name:
                            continue
                        framework_hits += 1
                        key_token = framework_name.replace(".", "_").replace("-", "_")
                        partial.observations.append(
                            Observation(
                                observation_id=new_id("obs"),
                                key=f"tech.{key_token}.detected",
                                value=True,
                                entity_type="web_app",
                                entity_id=web_entity_id,
                                source_tool=self.name,
                                confidence=0.9,
                                evidence_ids=[evidence.evidence_id],
                                source_execution_id=execution_id,
                                parser_version="whatweb_v1",
                            )
                        )
                        if framework_version:
                            partial.observations.append(
                                Observation(
                                    observation_id=new_id("obs"),
                                    key=f"tech.{key_token}.version",
                                    value=framework_version,
                                    entity_type="web_app",
                                    entity_id=web_entity_id,
                                    source_tool=self.name,
                                    confidence=0.85,
                                    evidence_ids=[evidence.evidence_id],
                                    source_execution_id=execution_id,
                                    parser_version="whatweb_v1",
                                )
                            )
            tool_ended_at = now_utc()
            partial.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=(
                        context.secret_resolver.redact_text(command_text(command, proxy_url or None))
                        if context.secret_resolver is not None
                        else command_text(command, proxy_url or None)
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
                    raw_artifact_paths=[str(json_path)],
                    error_message=error_message,
                    termination_reason=stream_result.termination_reason,
                    termination_detail=stream_result.termination_detail,
                    timed_out=stream_result.timed_out,
                    raw_command=" ".join(shlex.quote(str(item)) for item in command),
                )
            )
            return {
                "url": url,
                "execution_id": execution_id,
                "partial": partial,
                "wordpress_hits": wordpress_hits,
                "framework_hits": framework_hits,
            }

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
                execution_ids.extend(
                    [tool.execution_id for tool in partial.tool_executions if getattr(tool, "execution_id", None)]
                )
                discovered_wordpress += int(item["wordpress_hits"])
                discovered_framework_signals += int(item["framework_hits"])
                result.web_apps.extend(partial.web_apps)
                result.evidence.extend(partial.evidence)
                result.observations.extend(partial.observations)
                result.technologies.extend(partial.technologies)
                result.tool_executions.extend(partial.tool_executions)
                result.warnings.extend(partial.warnings)
                for evidence in partial.evidence:
                    emit_entity_event(context, "evidence", evidence, source=self.name)
                if any(getattr(execution, "status", "") == "completed" for execution in partial.tool_executions):
                    scanned_urls.append(str(item["url"]))
                else:
                    failed_urls.append(str(item["url"]))

        ended_at = now_utc()
        scanned_set = sorted(existing_scanned.union(scanned_urls))
        attempted_urls = sorted({str(item["url"]) for item in pending_targets})
        result.facts.update(
            {
                "whatweb.available": True,
                "whatweb.attempted_urls": attempted_urls,
                "whatweb.completed_urls": scanned_set,
                "whatweb.failed_urls": sorted(set(failed_urls)),
                "whatweb.scanned_targets": len(scanned_urls),
                "whatweb.scanned_urls": scanned_set,
                "whatweb.wordpress_hits": discovered_wordpress,
                "whatweb.framework_signals": discovered_framework_signals,
            }
        )
        if not execution_ids:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="whatweb (no new targets)",
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
                "wordpress_hits": discovered_wordpress,
            },
        )
        return result
