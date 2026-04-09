from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import shutil
import subprocess
from dataclasses import dataclass

from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Asset, Evidence, EvidenceArtifact, Observation, RunData, TaskArtifactRef, TaskResult, new_id, now_utc
from attackcastle.scope.expansion import is_ip_literal

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PARSER_VERSION = "resolve_hosts_v1"


@dataclass(slots=True)
class ResolveHostnameResult:
    ips: list[str]
    stdout: str
    stderr: str
    exit_code: int | None
    termination_reason: str
    termination_detail: str | None = None
    timed_out: bool = False


def _normalize_hostname(value: str | None) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _extract_ipv4_lines(output: str) -> list[str]:
    ips: list[str] = []
    for raw_line in output.splitlines():
        candidate = raw_line.strip()
        if not IPV4_RE.match(candidate):
            continue
        if candidate not in ips:
            ips.append(candidate)
    return ips


def _resolve_hostname_result(hostname: str) -> ResolveHostnameResult:
    try:
        completed = subprocess.run(
            ["dig", hostname, "+short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ResolveHostnameResult(
            ips=[],
            stdout="",
            stderr="",
            exit_code=None,
            termination_reason="timeout",
            termination_detail="command exceeded timeout of 5s",
            timed_out=True,
        )
    except FileNotFoundError:
        return ResolveHostnameResult(
            ips=[],
            stdout="",
            stderr="",
            exit_code=None,
            termination_reason="missing_dependency",
            termination_detail="dig was not found in PATH",
        )
    except OSError as exc:
        return ResolveHostnameResult(
            ips=[],
            stdout="",
            stderr="",
            exit_code=None,
            termination_reason="spawn_failure",
            termination_detail=str(exc),
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    ips = _extract_ipv4_lines(stdout)
    if completed.returncode == 0:
        return ResolveHostnameResult(
            ips=ips,
            stdout=stdout,
            stderr=stderr,
            exit_code=completed.returncode,
            termination_reason="completed",
        )
    detail = stderr.strip() or f"dig exited with code {completed.returncode}"
    return ResolveHostnameResult(
        ips=ips,
        stdout=stdout,
        stderr=stderr,
        exit_code=completed.returncode,
        termination_reason="nonzero_exit",
        termination_detail=detail,
    )


def resolve_hostname(hostname: str) -> list[str]:
    return _resolve_hostname_result(hostname).ips


class ResolveHostsAdapter:
    name = "resolve-hosts"
    capability = "dns_resolution"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"dig {hostname} +short" for hostname in self._collect_hostnames(run_data)[:20]]

    def _collect_hostnames(self, run_data: RunData) -> list[str]:
        hostnames: set[str] = set()
        for target in run_data.scope:
            if target.target_type not in {
                TargetType.DOMAIN,
                TargetType.WILDCARD_DOMAIN,
                TargetType.URL,
                TargetType.HOST_PORT,
            }:
                continue
            candidate = _normalize_hostname(target.host or target.value)
            if candidate and not is_ip_literal(candidate):
                hostnames.add(candidate)
        for asset in run_data.assets:
            candidate = _normalize_hostname(asset.name)
            if candidate and not is_ip_literal(candidate):
                hostnames.add(candidate)
        return sorted(hostnames)

    @staticmethod
    def _log(context: AdapterContext, message: str) -> None:
        logger = getattr(context, "logger", None)
        if logger is None:
            return
        logger.info(message)

    @staticmethod
    def _emit_live_result(context: AdapterContext, partial: AdapterResult) -> None:
        for asset in partial.assets:
            emit_entity_event(context, "asset", asset, source=asset.source_tool)
        for observation in partial.observations:
            emit_entity_event(context, "observation", observation, source=observation.source_tool)
        for evidence in partial.evidence:
            emit_entity_event(context, "evidence", evidence, source=evidence.source_tool)
        for artifact in partial.evidence_artifacts:
            emit_runtime_event(
                context,
                "artifact.available",
                {
                    "artifact_path": artifact.path,
                    "kind": artifact.kind,
                    "source_tool": artifact.source_tool,
                    "caption": artifact.caption or "",
                    "artifact_id": artifact.artifact_id,
                    "source_task_id": artifact.source_task_id,
                    "source_execution_id": artifact.source_execution_id,
                },
            )
        for task_result in partial.task_results:
            emit_runtime_event(context, "task_result.recorded", {"result": task_result})
        for execution in partial.tool_executions:
            emit_runtime_event(context, "tool_execution.recorded", {"execution": execution})

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        hostnames = self._collect_hostnames(run_data)
        if not hostnames:
            return result

        if shutil.which("dig") is None:
            warning = "dig binary was not found in PATH. Skipping resolve-hosts stage."
            started_at = now_utc()
            ended_at = now_utc()
            execution_id = new_id("exec")
            task_id = new_id("task")
            result.warnings.append(warning)
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="dig",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=None,
                    error_message=warning,
                    termination_reason="missing_dependency",
                    termination_detail=warning,
                )
            )
            result.task_results.append(
                TaskResult(
                    task_id=task_id,
                    task_type="ResolveHosts",
                    status="skipped",
                    command="dig",
                    exit_code=None,
                    started_at=started_at,
                    finished_at=ended_at,
                    warnings=[warning],
                    termination_reason="missing_dependency",
                    termination_detail=warning,
                )
            )
            return result

        asset_groups: dict[str, list[Asset]] = {}
        for asset in run_data.assets:
            candidate = _normalize_hostname(asset.name)
            if candidate and not is_ip_literal(candidate):
                asset_groups.setdefault(candidate, []).append(asset)

        max_workers = max(1, min(8, len(hostnames)))
        resolved_count = 0
        emit_runtime_event(
            context,
            "task.progress",
            {"adapter": self.name, "phase": "batch_started", "host_count": len(hostnames), "workers": max_workers},
        )
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_resolve_hostname_result, hostname): hostname for hostname in hostnames
            }
            for future in as_completed(future_map):
                hostname = future_map[future]
                resolution = future.result()
                partial = AdapterResult()
                emit_runtime_event(
                    context,
                    "task.progress",
                    {"adapter": self.name, "phase": "hostname_started", "hostname": hostname},
                )
                command = ["dig", hostname, "+short"]
                command_text = " ".join(command)
                task_id = new_id("task")
                execution_id = new_id("exec")
                slug = hostname.replace("*", "_").replace(".", "_")
                stdout_path = context.run_store.artifact_path(self.name, f"{slug}_stdout.txt")
                stderr_path = context.run_store.artifact_path(self.name, f"{slug}_stderr.txt")
                transcript_path = context.run_store.artifact_path(self.name, f"{slug}_transcript.txt")

                self._log(context, f"[resolve-hosts] resolving {hostname}")
                started_at = now_utc()
                ended_at = now_utc()

                stdout_path.write_text(resolution.stdout, encoding="utf-8")
                stderr_path.write_text(resolution.stderr, encoding="utf-8")
                transcript_path.write_text(
                    resolution.stdout
                    + (
                        ("\n" if resolution.stdout and resolution.stderr else "") + resolution.stderr
                        if resolution.stderr
                        else ""
                    ),
                    encoding="utf-8",
                )

                status = "completed" if resolution.termination_reason == "completed" else "failed"
                partial.tool_executions.append(
                    build_tool_execution(
                        tool_name=self.name,
                        command=command_text,
                        started_at=started_at,
                        ended_at=ended_at,
                        status=status,
                        execution_id=execution_id,
                        capability=self.capability,
                        exit_code=resolution.exit_code,
                        stdout_path=str(stdout_path),
                        stderr_path=str(stderr_path),
                        transcript_path=str(transcript_path),
                        error_message=resolution.termination_detail if status != "completed" else None,
                        termination_reason=resolution.termination_reason,
                        termination_detail=resolution.termination_detail,
                        timed_out=resolution.timed_out,
                    )
                )

                warnings: list[str] = []
                if resolution.termination_reason != "completed" and resolution.termination_detail:
                    warnings.append(resolution.termination_detail)

                task_result = TaskResult(
                    task_id=task_id,
                    task_type="ResolveHosts",
                    status=status,
                    command=command_text,
                    exit_code=resolution.exit_code,
                    started_at=started_at,
                    finished_at=ended_at,
                    transcript_path=str(transcript_path),
                    raw_artifacts=[
                        TaskArtifactRef(artifact_type="stdout", path=str(stdout_path)),
                        TaskArtifactRef(artifact_type="stderr", path=str(stderr_path)),
                    ],
                    parsed_entities=[{"type": "ResolvedHost", "fqdn": hostname, "ips": list(resolution.ips)}],
                    metrics={
                        "ipv4_count": len(resolution.ips),
                        "lines_parsed": len([line for line in resolution.stdout.splitlines() if line.strip()]),
                    },
                    warnings=warnings,
                    termination_reason=resolution.termination_reason,
                    termination_detail=resolution.termination_detail,
                    timed_out=resolution.timed_out,
                )
                partial.task_results.append(task_result)
                partial.evidence_artifacts.extend(
                    [
                        EvidenceArtifact(
                            artifact_id=new_id("artifact"),
                            kind="stdout",
                            path=str(stdout_path),
                            source_tool=self.name,
                            caption=f"ResolveHosts stdout for {hostname}",
                            source_task_id=task_id,
                            source_execution_id=execution_id,
                        ),
                        EvidenceArtifact(
                            artifact_id=new_id("artifact"),
                            kind="stderr",
                            path=str(stderr_path),
                            source_tool=self.name,
                            caption=f"ResolveHosts stderr for {hostname}",
                            source_task_id=task_id,
                            source_execution_id=execution_id,
                        ),
                    ]
                )

                if not resolution.ips:
                    self._log(context, f"[resolve-hosts] {hostname} returned no IP")
                    result.tool_executions.extend(partial.tool_executions)
                    result.task_results.extend(partial.task_results)
                    result.evidence_artifacts.extend(partial.evidence_artifacts)
                    self._emit_live_result(context, partial)
                    continue

                resolved_count += 1
                evidence = Evidence(
                    evidence_id=new_id("evidence"),
                    source_tool=self.name,
                    kind="dns_resolution",
                    snippet=f"{hostname} -> {', '.join(resolution.ips)}",
                    artifact_path=str(stdout_path),
                    selector={"kind": "line"},
                    source_execution_id=execution_id,
                    parser_version=PARSER_VERSION,
                    confidence=1.0,
                )
                partial.evidence.append(evidence)

                for ip in resolution.ips:
                    self._log(context, f"[resolve-hosts] {hostname} -> {ip}")

                seen_asset_ids: set[str] = set()
                for asset in asset_groups.get(hostname, []):
                    if asset.asset_id in seen_asset_ids:
                        continue
                    seen_asset_ids.add(asset.asset_id)
                    merged_ips = list(asset.resolved_ips)
                    for ip in resolution.ips:
                        if ip not in merged_ips:
                            merged_ips.append(ip)
                    partial.assets.append(
                        Asset(
                            asset_id=asset.asset_id,
                            kind=asset.kind,
                            name=asset.name,
                            ip=asset.ip or resolution.ips[0],
                            resolved_ips=merged_ips,
                            parent_asset_id=asset.parent_asset_id,
                            source_tool=asset.source_tool,
                            source_execution_id=asset.source_execution_id or execution_id,
                            parser_version=asset.parser_version or PARSER_VERSION,
                            aliases=list(asset.aliases),
                            canonical_key=asset.canonical_key,
                        )
                    )
                    partial.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="dns.resolved_ips",
                            value=list(resolution.ips),
                            entity_type="asset",
                            entity_id=asset.asset_id,
                            source_tool=self.name,
                            confidence=1.0,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version=PARSER_VERSION,
                        )
                    )
                self._log(context, f"[resolve-hosts] {hostname} resolved {len(resolution.ips)} IP")
                emit_artifact_event(
                    context,
                    artifact_path=stdout_path,
                    kind="stdout",
                    source_tool=self.name,
                    caption=f"ResolveHosts stdout for {hostname}",
                )
                result.assets.extend(partial.assets)
                result.observations.extend(partial.observations)
                result.evidence.extend(partial.evidence)
                result.tool_executions.extend(partial.tool_executions)
                result.task_results.extend(partial.task_results)
                result.evidence_artifacts.extend(partial.evidence_artifacts)
                self._emit_live_result(context, partial)

        result.facts["resolve_hosts.hostname_count"] = len(hostnames)
        result.facts["resolve_hosts.resolved_count"] = resolved_count
        emit_runtime_event(
            context,
            "task.progress",
            {"adapter": self.name, "phase": "batch_completed", "host_count": len(hostnames), "resolved_count": resolved_count},
        )
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "hostnames": len(hostnames),
                "resolved": resolved_count,
            },
        )
        return result
