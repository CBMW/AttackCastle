from __future__ import annotations

import platform
import shutil
import subprocess
from hashlib import sha1

from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import EvidenceArtifact, RunData, TaskArtifactRef, TaskResult, new_id, now_utc
from attackcastle.scope.expansion import collect_host_scan_targets


def _safe_slug(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _ping_command(target: str, timeout_seconds: int) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(max(1, timeout_seconds) * 1000), target]
    if system == "darwin":
        return ["ping", "-c", "1", "-W", str(max(1, timeout_seconds) * 1000), target]
    return ["ping", "-c", "1", "-W", str(max(1, timeout_seconds)), target]


class TargetReachabilityAdapter:
    name = "ping"
    capability = "target_reachability"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, _context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"ping -c 1 {target}" for target in collect_host_scan_targets(run_data)[:20]]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        config = context.config.get("target_reachability", {})
        if isinstance(config, dict) and not bool(config.get("enabled", True)):
            result.facts["target_reachability.available"] = False
            return result

        targets = [str(item).strip().lower().rstrip(".") for item in context.task_inputs if str(item).strip()]
        if not targets:
            targets = collect_host_scan_targets(run_data)
        seen: set[str] = set()
        targets = [target for target in targets if target and not (target in seen or seen.add(target))]
        if not targets:
            return result

        timeout_seconds = int((config or {}).get("ping_timeout_seconds", 3)) if isinstance(config, dict) else 3
        ping_path = shutil.which("ping")
        checked: list[str] = []
        reachable: list[str] = []
        unreachable: list[str] = []
        details: dict[str, dict[str, object]] = {}

        if ping_path is None:
            result.warnings.append("ping binary was not found in PATH. Reachability preflight was skipped.")
            result.facts["target_reachability.available"] = False
            return result

        for target in targets:
            command = _ping_command(target, timeout_seconds)
            command_text = " ".join(command)
            started_at = now_utc()
            stdout_text = ""
            stderr_text = ""
            exit_code: int | None = None
            termination_detail: str | None = None
            timed_out = False
            try:
                completed = subprocess.run(  # noqa: S603
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                stdout_text = completed.stdout or ""
                stderr_text = completed.stderr or ""
                exit_code = completed.returncode
            except subprocess.TimeoutExpired as exc:
                stdout_text = exc.stdout or ""
                stderr_text = exc.stderr or ""
                exit_code = None
                termination_detail = f"ping exceeded timeout of {timeout_seconds}s"
                timed_out = True
            except Exception as exc:  # noqa: BLE001
                exit_code = None
                termination_detail = str(exc)
            ended_at = now_utc()

            is_reachable = exit_code == 0
            checked.append(target)
            if is_reachable:
                reachable.append(target)
            else:
                unreachable.append(target)
            details[target] = {
                "reachable": is_reachable,
                "exit_code": exit_code,
                "termination_detail": termination_detail,
            }

            slug = _safe_slug(target)
            stdout_path = context.run_store.artifact_path(self.name, f"ping_{slug}_stdout.txt")
            stderr_path = context.run_store.artifact_path(self.name, f"ping_{slug}_stderr.txt")
            transcript_path = context.run_store.artifact_path(self.name, f"ping_{slug}_transcript.txt")
            stdout_path.write_text(stdout_text, encoding="utf-8")
            stderr_path.write_text(stderr_text, encoding="utf-8")
            transcript_path.write_text("\n".join([stdout_text, stderr_text]).strip(), encoding="utf-8")

            execution_id = new_id("exec")
            task_id = new_id("task")
            reason = "reachable" if is_reachable else "unreachable"
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command=command_text,
                    started_at=started_at,
                    ended_at=ended_at,
                    status="completed",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=exit_code,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                    transcript_path=str(transcript_path),
                    termination_reason=reason,
                    termination_detail=termination_detail,
                    timed_out=timed_out,
                    task_instance_key=context.task_instance_key,
                    task_inputs=[target],
                )
            )
            result.task_results.append(
                TaskResult(
                    task_id=task_id,
                    task_type="CheckTargetReachability",
                    status="completed",
                    command=command_text,
                    exit_code=exit_code,
                    started_at=started_at,
                    finished_at=ended_at,
                    transcript_path=str(transcript_path),
                    raw_artifacts=[
                        TaskArtifactRef(artifact_type="stdout", path=str(stdout_path)),
                        TaskArtifactRef(artifact_type="stderr", path=str(stderr_path)),
                    ],
                    parsed_entities=[
                        {
                            "type": "Reachability",
                            "target": target,
                            "reachable": is_reachable,
                        }
                    ],
                    metrics={"reachable": is_reachable},
                    termination_reason=reason,
                    termination_detail=termination_detail,
                    timed_out=timed_out,
                    task_instance_key=context.task_instance_key,
                    task_inputs=[target],
                )
            )
            result.evidence_artifacts.extend(
                [
                    EvidenceArtifact(
                        artifact_id=new_id("artifact"),
                        kind="stdout",
                        path=str(stdout_path),
                        source_tool=self.name,
                        caption=f"Ping stdout for {target}",
                        source_task_id=task_id,
                        source_execution_id=execution_id,
                    ),
                    EvidenceArtifact(
                        artifact_id=new_id("artifact"),
                        kind="stderr",
                        path=str(stderr_path),
                        source_tool=self.name,
                        caption=f"Ping stderr for {target}",
                        source_task_id=task_id,
                        source_execution_id=execution_id,
                    ),
                ]
            )

        result.facts["target_reachability.checked_targets"] = checked
        result.facts["target_reachability.reachable_targets"] = reachable
        result.facts["target_reachability.unreachable_targets"] = unreachable
        result.facts["target_reachability.details"] = details
        return result
