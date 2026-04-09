from __future__ import annotations

import shlex
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution, current_tool_budget, stream_command
from attackcastle.adapters.masscan.parser import parse_masscan_json
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData, new_id, now_utc
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.scope.expansion import collect_network_targets


class MasscanAdapter:
    name = "masscan"
    capability = "network_fast_scan"
    noise_score = 5
    cost_score = 5

    def _collect_targets(self, run_data: RunData) -> list[str]:
        return collect_network_targets(run_data)

    def _build_command(
        self,
        masscan_path: str,
        targets: list[str],
        json_output: Path,
        profile_config: dict[str, Any],
        global_config: dict[str, Any],
        rate_override: int | None = None,
    ) -> list[str]:
        profile_args = profile_config.get("masscan_args", [])
        extra_args = global_config.get("masscan", {}).get("args", [])
        command = [masscan_path, *profile_args, *extra_args]

        configured_ports = str(global_config.get("masscan", {}).get("ports", "1-65535"))
        if "-p" not in command and "--ports" not in command:
            command.extend(["-p", configured_ports])

        configured_rate = rate_override if rate_override is not None else global_config.get("masscan", {}).get("rate")
        if configured_rate and "--rate" not in command:
            command.extend(["--rate", str(configured_rate)])

        if "--wait" not in command:
            command.extend(["--wait", "0"])

        command.extend(["-oJ", str(json_output), *targets])
        return command

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        targets = self._collect_targets(run_data)
        if not targets:
            return []
        masscan_path = shutil.which("masscan") or "masscan"
        json_output = context.run_store.artifact_path(self.name, "masscan_output.json")
        tool_budget = current_tool_budget(context, self.capability, target_count=len(targets))
        command = self._build_command(
            masscan_path=masscan_path,
            targets=targets,
            json_output=json_output,
            profile_config=context.profile_config,
            global_config=context.config,
            rate_override=tool_budget.get("rate"),
        )
        return [" ".join(shlex.quote(item) for item in command)]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")

        masscan_path = shutil.which("masscan")
        if not masscan_path:
            ended_at = now_utc()
            result.warnings.append("masscan binary was not found in PATH. Skipping fast scan stage.")
            result.facts["masscan.available"] = False
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="masscan",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=None,
                    error_message="masscan_not_found",
                )
            )
            return result

        targets = self._collect_targets(run_data)
        if not targets:
            ended_at = now_utc()
            result.warnings.append("No IP-like targets available for masscan stage.")
            result.facts["masscan.available"] = True
            result.facts["masscan.open_ports_by_host"] = {}
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="masscan (no targets)",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="skipped",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        json_path = context.run_store.artifact_path(self.name, "masscan_output.json")
        stdout_path = context.run_store.artifact_path(self.name, "masscan_stdout.txt")
        stderr_path = context.run_store.artifact_path(self.name, "masscan_stderr.txt")
        tool_budget = current_tool_budget(context, self.capability, target_count=len(targets))
        command = self._build_command(
            masscan_path=masscan_path,
            targets=targets,
            json_output=json_path,
            profile_config=context.profile_config,
            global_config=context.config,
            rate_override=tool_budget.get("rate"),
        )
        timeout = int(context.config.get("masscan", {}).get("timeout_seconds", 300))

        status = "completed"
        exit_code: int | None = None
        error_message: str | None = None
        emit_runtime_event(
            context,
            "task.progress",
            {"adapter": self.name, "phase": "launch", "target_count": len(targets)},
        )
        exit_code, stdout_text, stderr_text, stream_error = stream_command(
            command,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
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
            error_message = f"masscan exceeded timeout of {timedelta(seconds=timeout)}"
            result.errors.append(error_message)
        elif exit_code is None:
            status = "failed"
            error_message = "masscan execution failed"
            result.errors.append(error_message)
        elif exit_code != 0:
            status = "failed"
            error_message = f"masscan exited with code {exit_code}"
            result.warnings.append(error_message)

        if json_path.exists():
            emit_artifact_event(
                context,
                artifact_path=json_path,
                kind="masscan_json",
                source_tool=self.name,
                caption="Masscan JSON output",
            )
            parsed = parse_masscan_json(
                json_path=json_path,
                source_tool=self.name,
                source_execution_id=execution_id,
                parser_version="masscan_json_v1",
            )
            result.assets.extend(parsed["assets"])
            result.services.extend(parsed["services"])
            result.observations.extend(parsed["observations"])
            result.evidence.extend(parsed["evidence"])
            result.facts.update(parsed["facts"])
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
                    "phase": "parsed",
                    "services": len(parsed["services"]),
                    "assets": len(parsed["assets"]),
                },
            )
        else:
            result.facts["masscan.open_ports_by_host"] = {}

        ended_at = now_utc()
        result.facts["masscan.available"] = True
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command=" ".join(shlex.quote(item) for item in command),
                started_at=started_at,
                ended_at=ended_at,
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
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "status": status,
                "exit_code": exit_code,
                "target_count": len(targets),
                "artifacts": [str(json_path), str(stdout_path), str(stderr_path)],
            },
        )
        return result
