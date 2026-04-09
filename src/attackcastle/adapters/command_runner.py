from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackcastle.adapters.base import build_tool_execution, normalize_command_termination, stream_command
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import EvidenceArtifact, TaskArtifactRef, TaskResult, ToolExecution, new_id, now_utc
from attackcastle.proxy import build_subprocess_env, command_text


@dataclass(slots=True)
class CommandSpec:
    tool_name: str
    capability: str
    task_type: str
    command: list[str]
    timeout_seconds: int
    artifact_prefix: str
    stdin: Any = None
    extra_artifacts: list[Path] = field(default_factory=list)


@dataclass(slots=True)
class CommandRunResult:
    execution: ToolExecution
    task_result: TaskResult
    evidence_artifacts: list[EvidenceArtifact]
    stdout_text: str
    stderr_text: str
    exit_code: int | None
    error_message: str | None
    command_text: str
    stdout_path: Path
    stderr_path: Path
    transcript_path: Path
    execution_id: str


def _artifact_hash(path: Path) -> str | None:
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    return digest


def run_command_spec(
    context: AdapterContext,
    spec: CommandSpec,
    *,
    proxy_url: str | None = None,
) -> CommandRunResult:
    started_at = now_utc()
    execution_id = new_id("exec")
    rendered_command = command_text(spec.command, proxy_url)
    stdout_path = context.run_store.artifact_path(spec.tool_name, f"{spec.artifact_prefix}_stdout.txt")
    stderr_path = context.run_store.artifact_path(spec.tool_name, f"{spec.artifact_prefix}_stderr.txt")
    transcript_path = context.run_store.artifact_path(spec.tool_name, f"{spec.artifact_prefix}_transcript.txt")
    task_id = new_id("task")

    if shutil.which(spec.command[0]) is None:
        warning = f"missing required tool '{spec.command[0]}' for task {spec.task_type}"
        ended_at = now_utc()
        termination_reason, termination_detail, timed_out = normalize_command_termination(
            None,
            warning,
            missing_dependency=True,
        )
        execution = build_tool_execution(
            tool_name=spec.tool_name,
            command=rendered_command,
            started_at=started_at,
            ended_at=ended_at,
            status="skipped",
            execution_id=execution_id,
            capability=spec.capability,
            exit_code=None,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            transcript_path=str(transcript_path),
            error_message=termination_detail,
            termination_reason=termination_reason,
            termination_detail=termination_detail,
            timed_out=timed_out,
        )
        task_result = TaskResult(
            task_id=task_id,
            task_type=spec.task_type,
            status="skipped",
            command=rendered_command,
            exit_code=None,
            started_at=started_at,
            finished_at=ended_at,
            transcript_path=str(transcript_path),
            raw_artifacts=[],
            parsed_entities=[],
            metrics={},
            warnings=[warning],
            termination_reason=termination_reason,
            termination_detail=termination_detail,
            timed_out=timed_out,
        )
        return CommandRunResult(
            execution=execution,
            task_result=task_result,
            evidence_artifacts=[],
            stdout_text="",
            stderr_text="",
            exit_code=None,
            error_message=warning,
            command_text=rendered_command,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            transcript_path=transcript_path,
            execution_id=execution_id,
        )

    stream_result = stream_command(
        spec.command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        transcript_path=transcript_path,
        timeout=spec.timeout_seconds,
        env=build_subprocess_env(proxy_url),
        stdin=spec.stdin,
    )
    ended_at = now_utc()
    exit_code = stream_result.exit_code
    stdout_text = stream_result.stdout_text
    stderr_text = stream_result.stderr_text
    status = "completed" if stream_result.termination_reason == "completed" else "failed"
    raw_paths = [str(path) for path in spec.extra_artifacts if path.exists()]
    execution = build_tool_execution(
        tool_name=spec.tool_name,
        command=rendered_command,
        started_at=started_at,
        ended_at=ended_at,
        status=status,
        execution_id=execution_id,
        capability=spec.capability,
        exit_code=exit_code,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        transcript_path=str(transcript_path),
        raw_artifact_paths=raw_paths,
        error_message=stream_result.termination_detail if status != "completed" else None,
        termination_reason=stream_result.termination_reason,
        termination_detail=stream_result.termination_detail,
        timed_out=stream_result.timed_out,
    )
    evidence_artifacts = [
        EvidenceArtifact(
            artifact_id=new_id("artifact"),
            kind="stdout",
            path=str(stdout_path),
            source_tool=spec.tool_name,
            caption=f"{spec.task_type} stdout",
            source_task_id=task_id,
            source_execution_id=execution_id,
            hash_sha256=_artifact_hash(stdout_path),
        ),
        EvidenceArtifact(
            artifact_id=new_id("artifact"),
            kind="stderr",
            path=str(stderr_path),
            source_tool=spec.tool_name,
            caption=f"{spec.task_type} stderr",
            source_task_id=task_id,
            source_execution_id=execution_id,
            hash_sha256=_artifact_hash(stderr_path),
        ),
    ]
    raw_refs = [
        TaskArtifactRef(artifact_type="stdout", path=str(stdout_path)),
        TaskArtifactRef(artifact_type="stderr", path=str(stderr_path)),
    ]
    for extra_path in spec.extra_artifacts:
        if not extra_path.exists():
            continue
        evidence_artifacts.append(
            EvidenceArtifact(
                artifact_id=new_id("artifact"),
                kind="raw",
                path=str(extra_path),
                source_tool=spec.tool_name,
                caption=f"{spec.task_type} raw artifact",
                source_task_id=task_id,
                source_execution_id=execution_id,
                hash_sha256=_artifact_hash(extra_path),
            )
        )
        raw_refs.append(TaskArtifactRef(artifact_type="raw", path=str(extra_path)))

    task_result = TaskResult(
        task_id=task_id,
        task_type=spec.task_type,
        status=status,
        command=rendered_command,
        exit_code=exit_code,
        started_at=started_at,
        finished_at=ended_at,
        transcript_path=str(transcript_path),
        raw_artifacts=raw_refs,
        parsed_entities=[],
        metrics={},
        warnings=[stream_result.termination_detail] if status != "completed" and stream_result.termination_detail else [],
        termination_reason=stream_result.termination_reason,
        termination_detail=stream_result.termination_detail,
        timed_out=stream_result.timed_out,
    )
    return CommandRunResult(
        execution=execution,
        task_result=task_result,
        evidence_artifacts=evidence_artifacts,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        exit_code=exit_code,
        error_message=stream_result.termination_detail,
        command_text=rendered_command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        transcript_path=transcript_path,
        execution_id=execution_id,
    )
