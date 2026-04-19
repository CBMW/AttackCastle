from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import subprocess
import time
from pathlib import Path
from threading import Lock
from threading import Thread
from typing import Any, Callable, Iterable, Iterator, TypeVar

from attackcastle.core.models import ToolExecution, new_id, now_utc

_T = TypeVar("_T")
_R = TypeVar("_R")


@dataclass(slots=True)
class StreamCommandResult:
    exit_code: int | None
    stdout_text: str
    stderr_text: str
    error_message: str | None
    termination_reason: str
    termination_detail: str | None
    timed_out: bool


def normalize_command_termination(
    exit_code: int | None,
    error_message: str | None = None,
    *,
    missing_dependency: bool = False,
    timed_out: bool = False,
) -> tuple[str, str | None, bool]:
    detail = str(error_message or "").strip() or None
    if missing_dependency:
        return ("missing_dependency", detail or "missing required dependency", False)
    normalized_timeout = timed_out or bool(detail and "timeout" in detail.lower())
    if normalized_timeout:
        return ("timeout", detail or "command exceeded timeout", True)
    if exit_code == 0 and not detail:
        return ("completed", None, False)
    if exit_code is None:
        reason = "spawn_failure"
        if detail:
            lowered = detail.lower()
            if "signal" in lowered or "terminated" in lowered or "killed" in lowered:
                reason = "interrupted"
            elif "timeout" in lowered:
                reason = "timeout"
                normalized_timeout = True
            elif "not found" in lowered or "no such file" in lowered or "cannot find" in lowered:
                reason = "spawn_failure"
        else:
            reason = "unknown_runner_failure"
        return (reason, detail or "command failed before returning an exit code", normalized_timeout)
    if exit_code < 0:
        return ("interrupted", detail or f"terminated by signal {-exit_code}", False)
    if exit_code > 0:
        return ("nonzero_exit", detail or f"process exited with code {exit_code}", False)
    return ("completed", detail, False)


def build_tool_execution(
    tool_name: str,
    command: str,
    started_at,
    ended_at,
    status: str,
    execution_id: str | None = None,
    capability: str | None = None,
    exit_code: int | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    transcript_path: str | None = None,
    raw_artifact_paths: list[str] | None = None,
    error_message: str | None = None,
    termination_reason: str | None = None,
    termination_detail: str | None = None,
    timed_out: bool = False,
    raw_command: str | None = None,
    task_instance_key: str | None = None,
    task_inputs: list[str] | None = None,
) -> ToolExecution:
    return ToolExecution(
        execution_id=execution_id or new_id("exec"),
        tool_name=tool_name,
        command=command,
        started_at=started_at or now_utc(),
        ended_at=ended_at or now_utc(),
        exit_code=exit_code,
        status=status,
        capability=capability,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        transcript_path=transcript_path,
        raw_artifact_paths=raw_artifact_paths or [],
        error_message=error_message,
        termination_reason=termination_reason,
        termination_detail=termination_detail,
        timed_out=timed_out,
        raw_command=raw_command or command,
        task_instance_key=task_instance_key,
        task_inputs=list(task_inputs or []),
    )


def stream_command(
    command: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    transcript_path: Path | None = None,
    timeout: int,
    on_stdout=None,
    on_stderr=None,
    env: dict[str, str] | None = None,
    stdin=None,
    cancellation_token=None,
) -> StreamCommandResult:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    if transcript_path is not None:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    transcript_lock = Lock()

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        transcript_handle = transcript_path.open("w", encoding="utf-8") if transcript_path is not None else None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    env=env,
                )
            except Exception as exc:  # noqa: BLE001
                error_message = str(exc)
                termination_reason, termination_detail, normalized_timeout = normalize_command_termination(
                    None,
                    error_message,
                )
                return StreamCommandResult(
                    exit_code=None,
                    stdout_text="",
                    stderr_text="",
                    error_message=error_message,
                    termination_reason=termination_reason,
                    termination_detail=termination_detail,
                    timed_out=normalized_timeout,
                )

            def _reader(stream, sink_handle, chunk_store: list[str], callback) -> None:
                if stream is None:
                    return
                try:
                    for chunk in iter(stream.readline, ""):
                        if not chunk:
                            break
                        sink_handle.write(chunk)
                        sink_handle.flush()
                        if transcript_handle is not None:
                            with transcript_lock:
                                transcript_handle.write(chunk)
                                transcript_handle.flush()
                        chunk_store.append(chunk)
                        if callback is not None:
                            callback(chunk)
                finally:
                    stream.close()

            stdout_thread = Thread(
                target=_reader,
                args=(process.stdout, stdout_handle, stdout_chunks, on_stdout),
                daemon=True,
            )
            stderr_thread = Thread(
                target=_reader,
                args=(process.stderr, stderr_handle, stderr_chunks, on_stderr),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()

            error_message: str | None = None
            timed_out = False
            cancelled = False
            try:
                deadline = None if timeout is None else time.monotonic() + float(timeout)
                while True:
                    if process.poll() is not None:
                        break
                    if cancellation_token is not None and getattr(cancellation_token, "is_set", lambda: False)():
                        cancelled = True
                        error_message = "command cancelled by resource governor"
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except Exception:  # noqa: BLE001
                            process.kill()
                            try:
                                process.wait(timeout=1)
                            except Exception:  # noqa: BLE001
                                pass
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        process.wait(timeout=0.25)
                    except subprocess.TimeoutExpired:
                        continue
            except subprocess.TimeoutExpired:
                process.kill()
                timed_out = True
                error_message = f"command exceeded timeout of {timeout}s"
                try:
                    process.wait(timeout=1)
                except Exception:  # noqa: BLE001
                    pass
            finally:
                stdout_thread.join(timeout=2)
                stderr_thread.join(timeout=2)

            termination_reason, termination_detail, normalized_timeout = normalize_command_termination(
                process.returncode,
                error_message,
                timed_out=timed_out,
            )
            if cancelled:
                termination_reason = "interrupted"
                termination_detail = error_message
            return StreamCommandResult(
                exit_code=process.returncode,
                stdout_text="".join(stdout_chunks),
                stderr_text="".join(stderr_chunks),
                error_message=error_message,
                termination_reason=termination_reason,
                termination_detail=termination_detail,
                timed_out=normalized_timeout,
            )
        finally:
            if transcript_handle is not None:
                transcript_handle.close()


def ordered_parallel_map(
    items: Iterable[_T],
    *,
    max_workers: int,
    worker: Callable[[_T], _R],
) -> list[_R]:
    sequence = list(items)
    if not sequence:
        return []
    if max_workers <= 1:
        return [worker(item) for item in sequence]

    results: list[_R | None] = [None] * len(sequence)
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_index = {executor.submit(worker, item): index for index, item in enumerate(sequence)}
        for future in as_completed(future_to_index):
            results[future_to_index[future]] = future.result()
    return [item for item in results if item is not None]


def batched(items: Iterable[_T], size: int) -> Iterator[list[_T]]:
    batch_size = max(1, int(size))
    current: list[_T] = []
    for item in items:
        current.append(item)
        if len(current) >= batch_size:
            yield current
            current = []
    if current:
        yield current


def current_worker_budget(
    context: Any,
    capability: str,
    *,
    stage: str | None = None,
    pending_count: int = 0,
    ceiling: int | None = None,
    fallback: int = 1,
) -> int:
    controller = getattr(context, "execution_controller", None)
    if controller is None or not getattr(controller, "is_enabled", lambda: False)():
        if ceiling is None:
            return max(1, fallback)
        return max(1, min(int(ceiling), fallback))
    return int(
        controller.worker_budget(
            capability,
            stage=stage,
            pending_count=pending_count,
            ceiling=ceiling,
        )
    )


def current_tool_budget(
    context: Any,
    capability: str,
    *,
    target_count: int = 1,
) -> dict[str, int]:
    controller = getattr(context, "execution_controller", None)
    if controller is None or not getattr(controller, "is_enabled", lambda: False)():
        count = max(1, target_count)
        return {"workers": count, "threads": count, "rate": count}
    return dict(controller.tool_budget(capability, target_count=target_count))


def record_execution_telemetry(
    context: Any,
    *,
    capability: str,
    success: bool,
    duration_seconds: float | None = None,
    noisy: bool = False,
    timeout: bool = False,
    generic: bool = False,
) -> None:
    controller = getattr(context, "execution_controller", None)
    if controller is None or not getattr(controller, "is_enabled", lambda: False)():
        return
    latency_ms = None
    if duration_seconds is not None:
        latency_ms = max(0.0, float(duration_seconds)) * 1000.0
    controller.record_event(
        capability=capability,
        success=success,
        latency_ms=latency_ms,
        noisy=noisy,
        timeout=timeout,
        generic=generic,
    )
