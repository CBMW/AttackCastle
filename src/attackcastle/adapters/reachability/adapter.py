from __future__ import annotations

import platform
import shutil
import subprocess
from hashlib import sha1

from attackcastle.adapters.base import build_tool_execution
from attackcastle.adapters.probe_strategy import host_probe_context
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import EvidenceArtifact, RunData, TaskArtifactRef, TaskResult, new_id, now_utc
from attackcastle.scope.expansion import collect_host_scan_targets


def _safe_slug(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _ping_command(target: str, timeout_seconds: int, *, ip_version: int | None = None) -> list[str]:
    system = platform.system().lower()
    version_flag = [f"-{ip_version}"] if ip_version in {4, 6} else []
    if system == "windows":
        return ["ping", *version_flag, "-n", "1", "-w", str(max(1, timeout_seconds) * 1000), target]
    if system == "darwin":
        return ["ping", *version_flag, "-c", "1", "-W", str(max(1, timeout_seconds) * 1000), target]
    return ["ping", *version_flag, "-c", "1", "-W", str(max(1, timeout_seconds)), target]


def _run_ping(command: list[str], timeout_seconds: int) -> tuple[str, str, int | None, str | None, bool]:
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=max(1, timeout_seconds) + 1,
            check=False,
        )
        return completed.stdout or "", completed.stderr or "", completed.returncode, None, False
    except subprocess.TimeoutExpired as exc:
        return (
            exc.stdout or "",
            exc.stderr or "",
            None,
            f"ping exceeded timeout of {timeout_seconds}s",
            True,
        )
    except Exception as exc:  # noqa: BLE001
        return "", "", None, str(exc), False


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
            probe_context = host_probe_context(run_data, target)
            probe_target = probe_context.target or target
            attempts: list[dict[str, object]] = []
            command = _ping_command(probe_target, timeout_seconds)
            started_at = now_utc()
            stdout_text, stderr_text, exit_code, termination_detail, timed_out = _run_ping(command, timeout_seconds)
            attempts.append(
                {
                    "probe_mode": "default",
                    "command": " ".join(command),
                    "exit_code": exit_code,
                    "termination_detail": termination_detail,
                    "timed_out": timed_out,
                }
            )

            if exit_code != 0 and probe_context.is_hostname_asset:
                ipv4_command = _ping_command(probe_target, timeout_seconds, ip_version=4)
                ipv4_stdout, ipv4_stderr, ipv4_exit, ipv4_detail, ipv4_timed_out = _run_ping(
                    ipv4_command,
                    timeout_seconds,
                )
                attempts.append(
                    {
                        "probe_mode": "ipv4_fallback",
                        "command": " ".join(ipv4_command),
                        "exit_code": ipv4_exit,
                        "termination_detail": ipv4_detail,
                        "timed_out": ipv4_timed_out,
                    }
                )
                stdout_text = "\n".join(part for part in (stdout_text, ipv4_stdout) if part)
                stderr_text = "\n".join(part for part in (stderr_text, ipv4_stderr) if part)
                if ipv4_exit == 0:
                    exit_code = 0
                    termination_detail = "IPv6 ICMP failed; IPv4 ICMP succeeded."
                    timed_out = False
                else:
                    ipv6_command = _ping_command(probe_target, timeout_seconds, ip_version=6)
                    ipv6_stdout, ipv6_stderr, ipv6_exit, ipv6_detail, ipv6_timed_out = _run_ping(
                        ipv6_command,
                        timeout_seconds,
                    )
                    attempts.append(
                        {
                            "probe_mode": "ipv6_explicit_retry",
                            "command": " ".join(ipv6_command),
                            "exit_code": ipv6_exit,
                            "termination_detail": ipv6_detail,
                            "timed_out": ipv6_timed_out,
                        }
                    )
                    stdout_text = "\n".join(part for part in (stdout_text, ipv6_stdout) if part)
                    stderr_text = "\n".join(part for part in (stderr_text, ipv6_stderr) if part)
                    termination_detail = termination_detail or ipv4_detail or ipv6_detail
                    timed_out = timed_out or ipv4_timed_out or ipv6_timed_out
            ended_at = now_utc()
            command_text = " ; ".join(str(attempt["command"]) for attempt in attempts)

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
                "attempts": attempts,
                **probe_context.metadata(protocol="icmp"),
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
                            "probe_target": probe_target,
                            "reachable": is_reachable,
                            **probe_context.metadata(protocol="icmp"),
                        }
                    ],
                    metrics={
                        "reachable": is_reachable,
                        "attempts": attempts,
                        **probe_context.metadata(protocol="icmp"),
                    },
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
