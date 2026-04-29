from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ToolCommandResult:
    command: str
    started_at: str
    ended_at: str
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool = False
    error: str | None = None
    stdout_path: str = ""
    stderr_path: str = ""
    transcript_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def shell_command_args(command: str) -> list[str]:
    if os.name == "nt":
        return ["cmd.exe", "/S", "/C", command]
    return ["/bin/sh", "-lc", command]


def run_shell_command(
    command: str,
    *,
    timeout_seconds: int = 300,
    log_dir: Path | None = None,
    artifact_prefix: str = "tool_command",
) -> ToolCommandResult:
    command = str(command or "").strip()
    started_at = _now_iso()
    if not command:
        ended_at = _now_iso()
        return ToolCommandResult(
            command="",
            started_at=started_at,
            ended_at=ended_at,
            stdout="",
            stderr="install command not configured",
            exit_code=None,
            error="install command not configured",
        )

    stdout_path = stderr_path = transcript_path = None
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = log_dir / f"{artifact_prefix}_stdout.txt"
        stderr_path = log_dir / f"{artifact_prefix}_stderr.txt"
        transcript_path = log_dir / f"{artifact_prefix}_transcript.txt"

    try:
        if os.name == "nt":
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_seconds or 300)),
                check=False,
            )
        else:
            completed = subprocess.run(
                shell_command_args(command),
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_seconds or 300)),
                check=False,
            )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        exit_code: int | None = completed.returncode
        timed_out = False
        error = None
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        exit_code = None
        timed_out = True
        error = f"command exceeded timeout of {timeout_seconds}s"
    except Exception as exc:  # noqa: BLE001
        stdout = ""
        stderr = str(exc)
        exit_code = None
        timed_out = False
        error = str(exc)

    if stdout_path is not None and stderr_path is not None and transcript_path is not None:
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        transcript_path.write_text("\n".join(part for part in (stdout, stderr) if part), encoding="utf-8")

    return ToolCommandResult(
        command=command,
        started_at=started_at,
        ended_at=_now_iso(),
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        timed_out=timed_out,
        error=error,
        stdout_path=str(stdout_path or ""),
        stderr_path=str(stderr_path or ""),
        transcript_path=str(transcript_path or ""),
    )
