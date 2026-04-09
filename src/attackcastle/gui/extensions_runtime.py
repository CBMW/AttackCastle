from __future__ import annotations

import json
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from attackcastle.adapters.base import build_tool_execution, stream_command
from attackcastle.core.models import RunData, to_serializable
from attackcastle.gui.extensions import ExtensionRecord, ExtensionReportPayload
from attackcastle.gui.models import ScanRequest
from attackcastle.storage.run_store import RunStore


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_artifact_rows(run_dir: Path, payload: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not isinstance(payload, list):
        return rows
    for item in payload:
        if isinstance(item, str):
            path_value = item.strip()
            label = Path(path_value).name
        elif isinstance(item, dict):
            path_value = str(item.get("path", "")).strip()
            label = str(item.get("label", "")).strip() or Path(path_value).name
        else:
            continue
        if not path_value:
            continue
        path = Path(path_value)
        if not path.is_absolute():
            path = (run_dir / path).resolve()
        rows.append({"path": str(path), "label": label})
    return rows


def _extension_env(
    *,
    request: ScanRequest,
    run_store: RunStore,
    extension_id: str,
    extension_name: str,
    output_json_path: Path,
    target_input_path: Path,
) -> dict[str, str]:
    return {
        "AC_EXTENSION_ID": extension_id,
        "AC_EXTENSION_NAME": extension_name,
        "AC_EXTENSION_RUN_DIR": str(run_store.run_dir),
        "AC_EXTENSION_DATA_DIR": str(run_store.data_dir),
        "AC_EXTENSION_REPORTS_DIR": str(run_store.reports_dir),
        "AC_EXTENSION_ARTIFACTS_DIR": str(run_store.artifacts_raw_dir),
        "AC_EXTENSION_LOGS_DIR": str(run_store.logs_dir),
        "AC_EXTENSION_WORKSPACE_ID": request.workspace_id,
        "AC_EXTENSION_WORKSPACE_NAME": request.workspace_name,
        "AC_EXTENSION_TARGET_INPUT": request.target_input,
        "AC_EXTENSION_TARGET_INPUT_PATH": str(target_input_path),
        "AC_EXTENSION_OUTPUT_JSON": str(output_json_path),
    }


def _normalize_status(payload_status: str, exit_code: int | None, error_message: str | None) -> str:
    normalized = str(payload_status or "").strip().lower()
    if normalized in {"completed", "running", "failed", "blocked", "cancelled", "skipped"}:
        return normalized
    if error_message or (exit_code not in (0, None)):
        return "failed"
    return "completed"


def run_command_hook_extensions(
    *,
    request: ScanRequest,
    records: list[ExtensionRecord],
    run_store: RunStore,
    run_data: RunData,
    event_emitter: Callable[[str, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    selected_ids = {item for item in request.enabled_extension_ids if item}
    if not selected_ids:
        return []

    target_input_path = run_store.data_dir / "gui_extension_targets.txt"
    target_input_path.write_text(request.target_input, encoding="utf-8")

    results: list[dict[str, Any]] = []
    facts_bucket = run_data.facts.setdefault("gui.extensions", [])
    if not isinstance(facts_bucket, list):
        facts_bucket = []
        run_data.facts["gui.extensions"] = facts_bucket

    for record in records:
        if record.extension_id not in selected_ids:
            continue
        manifest = record.manifest
        if manifest is None or not manifest.is_command_hook or manifest.command_hook is None:
            continue

        hook = manifest.command_hook
        output_json_path = run_store.artifact_path("extensions", f"{manifest.extension_id}.output.json")
        stdout_path = run_store.log_path(f"extension_{manifest.extension_id}.stdout.txt")
        stderr_path = run_store.log_path(f"extension_{manifest.extension_id}.stderr.txt")
        merged_env = os.environ.copy()
        merged_env.update(
            _extension_env(
                request=request,
                run_store=run_store,
                extension_id=manifest.extension_id,
                extension_name=manifest.name,
                output_json_path=output_json_path,
                target_input_path=target_input_path,
            )
        )
        merged_env.update(hook.env)
        command = [hook.command, *hook.args]
        started_at = _now_utc()
        if event_emitter is not None:
            event_emitter(
                "gui.extension.started",
                {
                    "extension_id": manifest.extension_id,
                    "extension_name": manifest.name,
                    "hook": hook.hook,
                    "command": command,
                },
            )

        exit_code, _, _, error_message = stream_command(
            command,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout=hook.timeout_seconds,
            env=merged_env,
        )
        ended_at = _now_utc()

        output_payload: dict[str, Any] = {}
        if output_json_path.exists():
            try:
                loaded = json.loads(output_json_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    output_payload = loaded
            except (OSError, ValueError, json.JSONDecodeError):
                output_payload = {}
        if not output_json_path.exists():
            output_json_path.write_text("{}", encoding="utf-8")

        report_payload = ExtensionReportPayload.from_dict(output_payload.get("report", {})) if isinstance(output_payload.get("report"), dict) else ExtensionReportPayload()
        artifact_rows = _normalize_artifact_rows(run_store.run_dir, output_payload.get("artifacts", []))
        status = _normalize_status(str(output_payload.get("status", "")), exit_code, error_message)
        raw_artifact_paths = [str(output_json_path)] + [item["path"] for item in artifact_rows]
        execution = build_tool_execution(
            tool_name=f"extension:{manifest.extension_id}",
            command=shlex.join(command),
            started_at=started_at,
            ended_at=ended_at,
            status=status,
            capability=f"gui_extension.{hook.hook}",
            exit_code=exit_code,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            raw_artifact_paths=raw_artifact_paths,
            error_message=error_message,
        )
        run_data.tool_executions.append(execution)

        result = {
            "extension_id": manifest.extension_id,
            "name": manifest.name,
            "version": manifest.version,
            "hook": hook.hook,
            "status": status,
            "summary": str(output_payload.get("summary", "")).strip() or f"{manifest.name} finished with status {status}.",
            "facts": dict(output_payload.get("facts", {})) if isinstance(output_payload.get("facts"), dict) else {},
            "report": report_payload.to_dict(),
            "artifacts": artifact_rows,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "output_json_path": str(output_json_path),
            "command": command,
        }
        facts_bucket.append(result)
        results.append(result)

        if status != "completed":
            run_data.warnings.append(f"Extension '{manifest.name}' completed with status '{status}'.")
        if status == "failed":
            message = error_message or f"Extension '{manifest.name}' failed."
            run_data.errors.append(message)
        if event_emitter is not None:
            event_emitter(
                "gui.extension.completed",
                {
                    "extension_id": manifest.extension_id,
                    "extension_name": manifest.name,
                    "hook": hook.hook,
                    "status": status,
                    "summary": result["summary"],
                },
            )

    run_data.facts["gui.extensions"] = to_serializable(facts_bucket)
    return results
