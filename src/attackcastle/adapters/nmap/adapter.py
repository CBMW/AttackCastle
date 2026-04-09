from __future__ import annotations

import shlex
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution, current_tool_budget, stream_command
from attackcastle.adapters.nmap.parser import parse_nmap_xml
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData, new_id, now_utc
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.scope.expansion import collect_host_scan_targets, is_ip_literal


def _safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value)[:60]


class NmapAdapter:
    name = "nmap"
    capability = "network_port_scan"
    noise_score = 4
    cost_score = 7

    def _collect_scope_targets(self, run_data: RunData) -> list[str]:
        return collect_host_scan_targets(run_data)

    def _ports_from_masscan(self, run_data: RunData) -> dict[str, list[int]]:
        mapping = run_data.facts.get("masscan.open_ports_by_host")
        if not isinstance(mapping, dict):
            return {}

        normalized: dict[str, list[int]] = {}
        for host, ports in mapping.items():
            host_text = str(host).strip()
            if not host_text:
                continue
            if not is_ip_literal(host_text):
                continue
            if not isinstance(ports, list):
                continue
            normalized_ports = sorted(
                {
                    int(port)
                    for port in ports
                    if isinstance(port, (int, str))
                    and str(port).isdigit()
                    and 0 < int(port) <= 65535
                }
            )
            if normalized_ports:
                normalized[host_text] = normalized_ports
        return normalized

    def _strip_port_flags(self, command: list[str]) -> list[str]:
        cleaned = list(command)
        for flag in ("--top-ports", "-p"):
            while flag in cleaned:
                index = cleaned.index(flag)
                del cleaned[index]
                if index < len(cleaned):
                    del cleaned[index]
        cleaned = [item for item in cleaned if item != "-p-"]
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

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()

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

        timeout = int(context.config.get("scan", {}).get("default_timeout_seconds", 120))
        udp_top_ports = int(context.config.get("nmap", {}).get("udp_top_ports", 0))
        masscan_ports = self._ports_from_masscan(run_data)
        jobs: list[dict[str, Any]] = []
        if masscan_ports:
            for host, ports in masscan_ports.items():
                slug = _safe_slug(host)
                jobs.append(
                    {
                        "targets": [host],
                        "ports": ports,
                        "udp_top_ports": 0,
                        "xml_path": context.run_store.artifact_path(self.name, f"nmap_output_{slug}.xml"),
                        "stdout_path": context.run_store.artifact_path(self.name, f"nmap_stdout_{slug}.txt"),
                        "stderr_path": context.run_store.artifact_path(self.name, f"nmap_stderr_{slug}.txt"),
                    }
                )
            result.facts["nmap.scan_mode"] = "targeted_from_masscan"
        else:
            targets = self._collect_scope_targets(run_data)
            if targets:
                jobs.append(
                    {
                        "targets": targets,
                        "ports": None,
                        "udp_top_ports": 0,
                        "xml_path": context.run_store.artifact_path(self.name, "nmap_output.xml"),
                        "stdout_path": context.run_store.artifact_path(self.name, "nmap_stdout.txt"),
                        "stderr_path": context.run_store.artifact_path(self.name, "nmap_stderr.txt"),
                    }
                )
            result.facts["nmap.scan_mode"] = "full_scope"
        udp_targets = self._collect_scope_targets(run_data)
        if udp_top_ports > 0 and udp_targets:
            jobs.append(
                {
                    "targets": udp_targets,
                    "ports": None,
                    "udp_top_ports": udp_top_ports,
                    "xml_path": context.run_store.artifact_path(self.name, "nmap_output_udp.xml"),
                    "stdout_path": context.run_store.artifact_path(self.name, "nmap_stdout_udp.txt"),
                    "stderr_path": context.run_store.artifact_path(self.name, "nmap_stderr_udp.txt"),
                }
            )

        if not jobs:
            ended_at = now_utc()
            result.warnings.append("No targets available for Nmap stage.")
            result.facts["nmap.available"] = True
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="nmap (no targets)",
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
            exit_code, _stdout_text, _stderr_text, stream_error = stream_command(
                command,
                stdout_path=job["stdout_path"],
                stderr_path=job["stderr_path"],
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
            )
            if stream_error:
                status = "failed"
                error_message = f"nmap exceeded timeout of {timedelta(seconds=timeout)}"
                result.errors.append(error_message)
            elif exit_code is None:
                status = "failed"
                error_message = "nmap execution failed"
                result.errors.append(error_message)
            elif exit_code != 0:
                status = "failed"
                error_message = f"nmap exited with code {exit_code}"
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
                    command=" ".join(shlex.quote(item) for item in command),
                    started_at=tool_started_at,
                    ended_at=tool_ended_at,
                    status=status,
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=exit_code,
                    stdout_path=str(job["stdout_path"]),
                    stderr_path=str(job["stderr_path"]),
                    raw_artifact_paths=[str(job["xml_path"])],
                    error_message=error_message,
                )
            )
            completed_jobs += 1

        ended_at = now_utc()
        result.facts["nmap.available"] = True
        result.facts["nmap.parsed"] = parsed_any
        result.facts["nmap.discovered_hosts"] = discovered_hosts_total
        result.facts["nmap.service_detection_runs"] = completed_jobs
        result.facts["nmap.udp_top_ports"] = udp_top_ports

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
        commands: list[str] = []
        masscan_ports = self._ports_from_masscan(run_data)
        if masscan_ports:
            for host, ports in list(masscan_ports.items())[:25]:
                xml_output = context.run_store.artifact_path(
                    self.name, f"nmap_output_{_safe_slug(host)}.xml"
                )
                command = self._build_command(
                    nmap_path=nmap_path,
                    targets=[host],
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
                commands.append(" ".join(shlex.quote(item) for item in command))
            return commands

        xml_output = context.run_store.artifact_path(self.name, "nmap_output.xml")
        command = self._build_command(
            nmap_path=nmap_path,
            targets=self._collect_scope_targets(run_data),
            xml_output=xml_output,
            profile_config=context.profile_config,
            global_config=context.config,
            parallelism=current_tool_budget(
                context,
                self.capability,
                target_count=len(self._collect_scope_targets(run_data)),
            ).get("threads"),
        )
        if command:
            commands.append(" ".join(shlex.quote(item) for item in command))
        return commands
