from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackcastle.core.models import RunData

MAX_TEXT_BYTES = 1024 * 1024


@dataclass(slots=True)
class RuleMatchContext:
    tool: str
    entity_type: str
    entity_id: str
    source_task_id: str | None = None
    source_execution_id: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    transcript_path: str | None = None
    raw_artifact_paths: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    exit_code: int | None = None
    status: str = ""
    timed_out: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    parsed_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def combined_output(self) -> str:
        return "\n".join(item for item in (self.stdout, self.stderr) if item)

    @property
    def artifact_paths(self) -> list[str]:
        ordered: list[str] = []
        for value in (
            self.stdout_path,
            self.stderr_path,
            self.transcript_path,
            *self.raw_artifact_paths,
            *[str(item) for item in self.parsed_fields.get("artifact_paths", []) if str(item).strip()],
        ):
            if value and value not in ordered:
                ordered.append(str(value))
        return ordered


def _read_text(path_value: str | None) -> str:
    if not path_value:
        return ""
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return ""
        with path.open("rb") as handle:
            data = handle.read(MAX_TEXT_BYTES + 1)
        if len(data) > MAX_TEXT_BYTES:
            data = data[:MAX_TEXT_BYTES]
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _normalize_headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key).lower(): str(item) for key, item in value.items()}
    if isinstance(value, list):
        headers: dict[str, str] = {}
        for row in value:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or row.get("header") or "").strip().lower()
            if name:
                headers[name] = str(row.get("value") or "")
        return headers
    return {}


def _context_entity_for_execution(run_data: RunData, execution_id: str | None) -> tuple[str, str]:
    if execution_id:
        for observation in run_data.observations:
            if observation.source_execution_id == execution_id:
                return observation.entity_type, observation.entity_id
    first_asset = next(iter(run_data.assets), None)
    if first_asset is not None:
        return "asset", first_asset.asset_id
    first_scope = next(iter(run_data.scope), None)
    if first_scope is not None:
        return "asset", first_scope.target_id
    return "run", run_data.metadata.run_id


def _execution_contexts(run_data: RunData) -> list[RuleMatchContext]:
    contexts: list[RuleMatchContext] = []
    task_by_execution: dict[str, Any] = {}
    for result in run_data.task_results:
        for artifact in result.raw_artifacts:
            _ = artifact
        # TaskResult does not own execution ids, so matching happens through paths below.
    for execution in run_data.tool_executions:
        entity_type, entity_id = _context_entity_for_execution(run_data, execution.execution_id)
        contexts.append(
            RuleMatchContext(
                tool=execution.tool_name,
                entity_type=entity_type,
                entity_id=entity_id,
                source_execution_id=execution.execution_id,
                stdout_path=execution.stdout_path,
                stderr_path=execution.stderr_path,
                transcript_path=execution.transcript_path,
                raw_artifact_paths=list(execution.raw_artifact_paths),
                stdout=_read_text(execution.stdout_path),
                stderr=_read_text(execution.stderr_path),
                exit_code=execution.exit_code,
                status=execution.status,
                timed_out=bool(execution.timed_out),
                parsed_fields={
                    "termination_reason": execution.termination_reason,
                    "termination_detail": execution.termination_detail,
                    "command": execution.command,
                    "raw_command": execution.raw_command,
                },
            )
        )
    return contexts


def _task_result_contexts(run_data: RunData) -> list[RuleMatchContext]:
    contexts: list[RuleMatchContext] = []
    for result in run_data.task_results:
        stdout_path = next((item.path for item in result.raw_artifacts if item.artifact_type == "stdout"), None)
        stderr_path = next((item.path for item in result.raw_artifacts if item.artifact_type == "stderr"), None)
        entity_type, entity_id = _context_entity_for_execution(run_data, None)
        contexts.append(
            RuleMatchContext(
                tool=result.task_type,
                entity_type=entity_type,
                entity_id=entity_id,
                source_task_id=result.task_id,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                transcript_path=result.transcript_path,
                raw_artifact_paths=[item.path for item in result.raw_artifacts if item.artifact_type not in {"stdout", "stderr"}],
                stdout=_read_text(stdout_path),
                stderr=_read_text(stderr_path),
                exit_code=result.exit_code,
                status=result.status,
                timed_out=bool(result.timed_out),
                parsed_fields={
                    "termination_reason": result.termination_reason,
                    "termination_detail": result.termination_detail,
                    "command": result.command,
                    "raw_command": result.raw_command,
                    "metrics": dict(result.metrics),
                    "warnings": list(result.warnings),
                },
            )
        )
    return contexts


def _http_header_contexts(run_data: RunData) -> list[RuleMatchContext]:
    contexts: list[RuleMatchContext] = []
    for observation in run_data.observations:
        if observation.key != "web.http_security_headers.analysis" or not isinstance(observation.value, dict):
            continue
        analysis = observation.value
        headers = _normalize_headers(analysis.get("headers"))
        if not headers and analysis.get("raw_headers"):
            headers = _headers_from_raw(str(analysis.get("raw_headers") or ""))
        artifact_paths: list[str] = []
        for evidence_id in observation.evidence_ids:
            evidence = next((item for item in run_data.evidence if item.evidence_id == evidence_id), None)
            if evidence and evidence.artifact_path:
                artifact_paths.append(evidence.artifact_path)
                raw_path = evidence.selector.get("raw_headers_path") if isinstance(evidence.selector, dict) else None
                if raw_path:
                    artifact_paths.append(str(raw_path))
        contexts.append(
            RuleMatchContext(
                tool=observation.source_tool,
                entity_type=observation.entity_type,
                entity_id=observation.entity_id,
                source_execution_id=observation.source_execution_id,
                headers=headers,
                status_code=int(analysis["status_code"]) if analysis.get("status_code") is not None else None,
                evidence_ids=list(observation.evidence_ids),
                parsed_fields={
                    "observation_id": observation.observation_id,
                    "url": analysis.get("url"),
                    "status_code": analysis.get("status_code"),
                    "core_missing": list(analysis.get("core_missing", [])),
                    "core_weak": list(analysis.get("core_weak", [])),
                    "artifact_paths": artifact_paths,
                },
            )
        )
    return contexts


def _headers_from_raw(raw_headers: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw_headers.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized:
            headers[normalized] = value.strip()
    return headers


def build_rule_contexts(run_data: RunData) -> list[RuleMatchContext]:
    contexts = [*_http_header_contexts(run_data), *_execution_contexts(run_data), *_task_result_contexts(run_data)]
    for evidence in run_data.evidence:
        if not evidence.artifact_path or not str(evidence.artifact_path).lower().endswith(".json"):
            continue
        try:
            payload = json.loads(Path(evidence.artifact_path).read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        headers = _normalize_headers(payload.get("headers"))
        if not headers:
            continue
        contexts.append(
            RuleMatchContext(
                tool=evidence.source_tool,
                entity_type="run",
                entity_id=run_data.metadata.run_id,
                source_execution_id=evidence.source_execution_id,
                headers=headers,
                status_code=int(payload["status_code"]) if payload.get("status_code") is not None else None,
                evidence_ids=[evidence.evidence_id],
                parsed_fields={"artifact_paths": [evidence.artifact_path], "status_code": payload.get("status_code")},
            )
        )
    return contexts

