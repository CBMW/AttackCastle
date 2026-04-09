from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
from pathlib import Path
from threading import Thread
from typing import Any, Callable, Iterable, Iterator, TypeVar

from attackcastle.core.models import ToolExecution, new_id, now_utc

_T = TypeVar("_T")
_R = TypeVar("_R")


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
    raw_artifact_paths: list[str] | None = None,
    error_message: str | None = None,
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
        raw_artifact_paths=raw_artifact_paths or [],
        error_message=error_message,
    )


def stream_command(
    command: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
    on_stdout=None,
    on_stderr=None,
    env: dict[str, str] | None = None,
    stdin=None,
) -> tuple[int | None, str, str, str | None]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        process = subprocess.Popen(
            command,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
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
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            error_message = f"command exceeded timeout of {timeout}s"
        finally:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

        return process.returncode, "".join(stdout_chunks), "".join(stderr_chunks), error_message


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
