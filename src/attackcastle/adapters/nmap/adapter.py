from __future__ import annotations

import shlex
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution, current_tool_budget, emit_tool_execution_started, stream_command
from attackcastle.adapters.nmap.parser import parse_nmap_xml
from attackcastle.adapters.probe_strategy import host_probe_context
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData, new_id, now_utc
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.scope.compiler import classify_cloud_provider
from attackcastle.scope.expansion import collect_resolved_host_scan_targets


def _safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value)[:60]


class NmapAdapter:
    name = "nmap"
    noise_score = 4
    cost_score = 7

    def __init__(self, scan_mode: str = "port_discovery") -> None:
        self.scan_mode = scan_mode
        self.capability = "service_detection" if scan_mode == "service_detection" else "network_port_scan"

    def _collect_scope_targets(self, run_data: RunData) -> list[str]:
        return collect_resolved_host_scan_targets(run_data)

    @staticmethod
    def _normalize_target(value: str) -> str:
        item = str(value or "").strip()
        return item if "." in item and item.replace(".", "").isdigit() else item.lower()

    def _strip_port_flags(self, command: list[str]) -> list[str]:
        cleaned = list(command)
        for flag in ("--top-ports", "-p"):
            while flag in cleaned:
                index = cleaned.index(flag)
                del cleaned[index]
                if index < len(cleaned):
                    del cleaned[index]
        cleaned = [item for item in cleaned if item not in {"-F", "-p-"}]
        return cleaned

    def _strip_service_detection_flags(self, command: list[str]) -> list[str]:
        flags_with_values = {
            "--script",
            "--script-args",
            "--script-help",
            "--script-trace",
            "--script-updatedb",
            "--script-timeout",
            "--version-intensity",
            "--version-trace",
        }
        flags_without_values = {
            "-sV",
            "-sC",
            "-A",
            "--version-light",
            "--version-all",
            "--allports",
        }
        cleaned: list[str] = []
        index = 0
        while index < len(command):
            item = command[index]
            if item in flags_without_values:
                index += 1
                continue
            if item in flags_with_values:
                index += 2
                continue
            if any(item.startswith(f"{flag}=") for flag in flags_with_values):
                index += 1
                continue
            cleaned.append(item)
            index += 1
        return cleaned

    def _build_command(
        self,
        nmap_path: str,
        targets: list[str],
        xml_output: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        ports: list[int] | None = None,
        udp_top_ports: int = 0,
        parallelism: int | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("nmap_args", [])
        extra_args = global_config.get("nmap", {}).get("args", [])
        command = [nmap_path, *profile_args, *extra_args]
        if self.scan_mode == "port_discovery":
            command = self._strip_service_detection_flags(command)
        elif not any(item in command for item in ("-sV", "-A", "--version-light", "--version-all")):
            command.append("-sV")

        # Masscan previously skipped ICMP-based host discovery. Keep Nmap aligned
        # with that behavior so we do not miss hosts that block probes.
        if "-sn" not in command and "-Pn" not in command:
            command.append("-Pn")

        if parallelism is not None and parallelism > 0 and "--min-parallelism" not in command:
            command.extend(["--min-parallelism", str(parallelism)])

        if udp_top_ports > 0:
            command = self._strip_port_flags(command)
            if "-sU" not in command:
                command.append("-sU")
            command.extend(["--top-ports", str(udp_top_ports)])
        elif ports:
            command = self._strip_port_flags(command)
            command.extend(["-p", ",".join(str(port) for port in ports)])
        elif "--top-ports" not in command and "-p-" not in command and "-p" not in command:
            max_ports = global_config.get("scan", {}).get("max_ports")
            if max_ports:
                command.extend(["--top-ports", str(max_ports)])

        command.extend(["-oX", str(xml_output), *targets])
        return command

    def _service_targets(self, run_data: RunData) -> dict[str, list[int]]:
        assets_by_id = {asset.asset_id: asset for asset in run_data.assets}
        grouped: dict[str, set[int]] = {}
        for service in run_data.services:
            if str(service.protocol or "tcp").lower() not in {"tcp", ""}:
                continue
            if int(service.port or 0) <= 0:
                continue
            asset = assets_by_id.get(service.asset_id)
            target = ""
            if asset is not None:
                target = str(asset.ip or asset.name or "").strip()
                target = host_probe_context(run_data, target).target or target
            if not target:
                target = str(service.asset_id or "").strip()
            if not target:
                continue
            grouped.setdefault(target, set()).add(int(service.port))
        return {target: sorted(ports) for target, ports in grouped.items() if ports}

    def _pending_service_targets(self, run_data: RunData) -> dict[str, list[int]]:
        completed = {
            str(item).strip()
            for item in run_data.facts.get("nmap.service_scanned_targets", [])
            if str(item).strip()
        }
        pending: dict[str, list[int]] = {}
        for target, ports in self._service_targets(run_data).items():
            key = f"{self._normalize_target(target)}:{','.join(str(port) for port in ports)}"
            if key not in completed:
                pending[target] = ports
        return pending

    def _pending_targets(self, context: AdapterContext, run_data: RunData) -> list[str]:
        if context.task_inputs:
            return [str(item).strip() for item in context.task_inputs if str(item).strip()]
        known_targets = self._collect_scope_targets(run_data)
        existing_scanned = {
            self._normalize_target(item)
            for item in run_data.facts.get("nmap.scanned_targets", [])
            if str(item).strip()
        }
        return [
            target
            for target in known_targets
            if self._normalize_target(target) not in existing_scanned
        ]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()

        nmap_config = context.config.get("nmap", {})
        mode_enabled_key = "service_detection_enabled" if self.scan_mode == "service_detection" else "port_discovery_enabled"
        if not bool(nmap_config.get("enabled", True)) or not bool(nmap_config.get(mode_enabled_key, True)):
            ended_at = now_utc()
            result.facts["nmap.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=f"nmap ({self.scan_mode} disabled)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        nmap_path = shutil.which("nmap")
        if not nmap_path:
            ended_at = now_utc()
            result.warnings.append("nmap binary was not found in PATH. Skipping Nmap stage.")
            result.facts["nmap.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nmap",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=None,
                    error_message="nmap_not_found",
                )
            )
            return result

        timeout = int(
            context.config.get("nmap", {}).get(
                "timeout_seconds",
                context.config.get("scan", {}).get("default_timeout_seconds", 120),
            )
        )
        udp_top_ports = int(context.config.get("nmap", {}).get("udp_top_ports", 0))
        jobs: list[dict[str, Any]] = []
        existing_scanned = {
            self._normalize_target(item)
            for item in run_data.facts.get("nmap.scanned_targets", [])
            if str(item).strip()
        }
        targets = self._pending_targets(context, run_data) if self.scan_mode != "service_detection" else []
        task_suffix = _safe_slug(context.task_instance_key or "_".join(targets) or "batch")
        if self.scan_mode == "service_detection":
            service_targets = self._pending_service_targets(run_data)
            for target, ports in service_targets.items():
                service_suffix = _safe_slug(context.task_instance_key or f"{target}_{'_'.join(str(port) for port in ports)}")
                jobs.append(
                    {
                        "targets": [target],
                        "ports": ports,
                        "udp_top_ports": 0,
                        "xml_path": context.run_store.artifact_path(self.name, f"nmap_services_{service_suffix}.xml"),
                        "stdout_path": context.run_store.artifact_path(self.name, f"nmap_services_stdout_{service_suffix}.txt"),
                        "stderr_path": context.run_store.artifact_path(self.name, f"nmap_services_stderr_{service_suffix}.txt"),
                        "transcript_path": context.run_store.artifact_path(
                            self.name,
                            f"nmap_services_transcript_{service_suffix}.txt",
                        ),
                    }
                )
        elif targets:
            jobs.append(
                {
                    "targets": targets,
                    "ports": None,
                    "udp_top_ports": 0,
                    "xml_path": context.run_store.artifact_path(self.name, f"nmap_output_{task_suffix}.xml"),
                    "stdout_path": context.run_store.artifact_path(self.name, f"nmap_stdout_{task_suffix}.txt"),
                    "stderr_path": context.run_store.artifact_path(self.name, f"nmap_stderr_{task_suffix}.txt"),
                    "transcript_path": context.run_store.artifact_path(
                        self.name,
                        f"nmap_transcript_{task_suffix}.txt",
                    ),
                }
            )
        result.facts["nmap.scan_mode"] = self.scan_mode
        udp_targets = targets
        if self.scan_mode != "service_detection" and udp_top_ports > 0 and udp_targets:
            jobs.append(
                {
                    "targets": udp_targets,
                    "ports": None,
                    "udp_top_ports": udp_top_ports,
                    "xml_path": context.run_store.artifact_path(self.name, f"nmap_output_udp_{task_suffix}.xml"),
                    "stdout_path": context.run_store.artifact_path(self.name, f"nmap_stdout_udp_{task_suffix}.txt"),
                    "stderr_path": context.run_store.artifact_path(self.name, f"nmap_stderr_udp_{task_suffix}.txt"),
                    "transcript_path": context.run_store.artifact_path(
                        self.name,
                        f"nmap_transcript_udp_{task_suffix}.txt",
                    ),
                }
            )

        if not jobs:
            ended_at = now_utc()
            result.warnings.append("No targets available for Nmap stage.")
            result.facts["nmap.available"] = True
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=f"nmap ({self.scan_mode} no targets)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        discovered_hosts_total = 0
        parsed_any = False
        completed_jobs = 0
        completed_targets: set[str] = set()
        completed_service_targets: set[str] = set()
        provider_edges: dict[str, str] = {}

        for job in jobs:
            execution_id = new_id("exec")
            command = self._build_command(
                nmap_path=nmap_path,
                targets=job["targets"],
                xml_output=job["xml_path"],
                profile_config=context.profile_config,
                global_config=context.config,
                ports=job["ports"],
                udp_top_ports=int(job.get("udp_top_ports", 0)),
                parallelism=current_tool_budget(
                    context,
                    self.capability,
                    target_count=len(job["targets"]),
                ).get("threads"),
            )

            status = "completed"
            exit_code: int | None = None
            error_message: str | None = None
            tool_started_at = now_utc()
            raw_command = " ".join(shlex.quote(item) for item in command)
            emit_tool_execution_started(
                context,
                execution_id=execution_id,
                tool_name=self.name,
                command=raw_command,
                started_at=tool_started_at,
                capability=self.capability,
                stdout_path=job["stdout_path"],
                stderr_path=job["stderr_path"],
                transcript_path=job["transcript_path"],
                raw_artifact_paths=[str(job["xml_path"])],
                raw_command=raw_command,
                task_instance_key=getattr(context, "task_instance_key", None),
                task_inputs=list(getattr(context, "task_inputs", []) or []),
            )
            emit_runtime_event(
                context,
                "task.progress",
                {
                    "adapter": self.name,
                    "phase": "job_started",
                    "targets": job["targets"],
                    "ports": job["ports"] or [],
                    "udp_top_ports": int(job.get("udp_top_ports", 0)),
                },
            )
            stream_result = stream_command(
                command,
                stdout_path=job["stdout_path"],
                stderr_path=job["stderr_path"],
                transcript_path=job["transcript_path"],
                timeout=timeout,
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
                error_message = stream_result.termination_detail or f"nmap exceeded timeout of {timedelta(seconds=timeout)}"
                result.errors.append(error_message)
            elif stream_result.termination_reason != "completed" and exit_code is None:
                status = "failed"
                error_message = stream_result.termination_detail or "nmap execution failed"
                result.errors.append(error_message)
            elif stream_result.termination_reason != "completed" and exit_code != 0:
                status = "failed"
                error_message = stream_result.termination_detail or f"nmap exited with code {exit_code}"
                result.warnings.append(error_message)

            if job["xml_path"].exists():
                emit_artifact_event(
                    context,
                    artifact_path=job["xml_path"],
                    kind="nmap_xml",
                    source_tool=self.name,
                    caption="Nmap XML output",
                )
                parsed = parse_nmap_xml(
                    job["xml_path"],
                    source_tool=self.name,
                    source_execution_id=execution_id,
                    parser_version="nmap_xml_v1",
                )
                result.assets.extend(parsed["assets"])
                result.services.extend(parsed["services"])
                result.observations.extend(parsed["observations"])
                result.evidence.extend(parsed["evidence"])
                discovered_hosts_total += int(parsed["facts"].get("nmap.discovered_hosts", 0))
                parsed_any = parsed_any or bool(parsed["facts"].get("nmap.parsed"))
                for asset in parsed["assets"]:
                    provider = classify_cloud_provider(getattr(asset, "name", None))
                    if provider:
                        provider_edges[getattr(asset, "name", "")] = provider
                for asset in parsed["assets"]:
                    emit_entity_event(context, "asset", asset, source=self.name)
                for service in parsed["services"]:
                    emit_entity_event(context, "service", service, source=self.name)
                for evidence in parsed["evidence"]:
                    emit_entity_event(context, "evidence", evidence, source=self.name)
                emit_runtime_event(
                    context,
                    "task.progress",
                    {
                        "adapter": self.name,
                        "phase": "job_parsed",
                        "targets": job["targets"],
                        "services": len(parsed["services"]),
                    },
                )

            tool_ended_at = now_utc()
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=raw_command,
                    started_at=tool_started_at,
                    ended_at=tool_ended_at,
                    status=status,
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=exit_code,
                    stdout_path=str(job["stdout_path"]),
                    stderr_path=str(job["stderr_path"]),
                    transcript_path=str(job["transcript_path"]),
                    raw_artifact_paths=[str(job["xml_path"])],
                    raw_command=raw_command,
                    error_message=error_message,
                    termination_reason=stream_result.termination_reason,
                    termination_detail=stream_result.termination_detail,
                    timed_out=stream_result.timed_out,
                )
            )
            completed_jobs += 1
            if status == "completed":
                completed_targets.update(self._normalize_target(item) for item in job["targets"])
                if self.scan_mode == "service_detection":
                    for item in job["targets"]:
                        ports = ",".join(str(port) for port in job["ports"] or [])
                        completed_service_targets.add(f"{self._normalize_target(item)}:{ports}")

        ended_at = now_utc()
        result.facts["nmap.available"] = True
        result.facts["nmap.parsed"] = parsed_any
        result.facts["nmap.discovered_hosts"] = discovered_hosts_total
        if self.scan_mode == "service_detection":
            existing_service_scanned = {
                str(item).strip()
                for item in run_data.facts.get("nmap.service_scanned_targets", [])
                if str(item).strip()
            }
            result.facts["nmap.service_detection_runs"] = completed_jobs
            result.facts["nmap.service_scanned_targets"] = sorted(existing_service_scanned.union(completed_service_targets))
        else:
            result.facts["nmap.port_discovery_runs"] = completed_jobs
        result.facts["nmap.udp_top_ports"] = udp_top_ports
        result.facts["nmap.provider_edges"] = provider_edges
        attempted_targets = {self._normalize_target(item) for item in targets}
        completed_set = existing_scanned.union(item for item in completed_targets if item)
        if self.scan_mode != "service_detection":
            result.facts["nmap.attempted_targets"] = sorted(attempted_targets)
            result.facts["nmap.completed_targets"] = sorted(completed_set)
            result.facts["nmap.failed_targets"] = sorted(attempted_targets.difference(completed_targets))
            result.facts["nmap.scanned_targets"] = sorted(completed_set)

        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "scan_mode": result.facts.get("nmap.scan_mode"),
                "job_count": completed_jobs,
                "discovered_hosts": discovered_hosts_total,
            },
        )
        if not result.tool_executions:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nmap",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
        return result

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        nmap_path = shutil.which("nmap") or "nmap"
        if self.scan_mode == "service_detection":
            service_targets = self._pending_service_targets(run_data)
            commands: list[str] = []
            for target, ports in list(service_targets.items())[:50]:
                xml_output = context.run_store.artifact_path(self.name, f"nmap_services_{_safe_slug(target)}.xml")
                command = self._build_command(
                    nmap_path=nmap_path,
                    targets=[target],
                    xml_output=xml_output,
                    profile_config=context.profile_config,
                    global_config=context.config,
                    ports=ports,
                    parallelism=current_tool_budget(
                        context,
                        self.capability,
                        target_count=1,
                    ).get("threads"),
                )
                if command:
                    commands.append(" ".join(shlex.quote(item) for item in command))
            return commands
        targets = self._pending_targets(context, run_data)
        if not targets:
            return []
        commands: list[str] = []
        for target in targets[:50]:
            xml_output = context.run_store.artifact_path(self.name, f"nmap_output_{_safe_slug(target)}.xml")
            command = self._build_command(
                nmap_path=nmap_path,
                targets=[target],
                xml_output=xml_output,
                profile_config=context.profile_config,
                global_config=context.config,
                parallelism=current_tool_budget(
                    context,
                    self.capability,
                    target_count=1,
                ).get("threads"),
            )
            if command:
                commands.append(" ".join(shlex.quote(item) for item in command))
        return commands
