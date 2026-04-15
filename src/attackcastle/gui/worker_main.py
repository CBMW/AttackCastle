from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

from rich.console import Console

from attackcastle.app import ScanOptions, _execute_scan_plan, build_scan_plan
from attackcastle.gui.extensions_runtime import run_command_hook_extensions
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.models import ScanRequest
from attackcastle.gui.runtime import profile_to_engine_overrides, write_yaml_like_json
from attackcastle.gui.worker_protocol import build_event, now_iso


def _emit(event: str, **payload: object) -> None:
    sys.stdout.write(build_event(event, **payload) + "\n")
    sys.stdout.flush()


def _load_request(path: Path) -> ScanRequest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Worker payload must be a JSON object.")
    return ScanRequest.from_dict(payload)


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if len(args) != 1:
        sys.stderr.write("usage: python -m attackcastle.gui.worker_main <job.json>\n")
        return 2

    request_path = Path(args[0]).expanduser().resolve()
    temp_dir = Path(tempfile.mkdtemp(prefix="attackcastle-gui-"))
    try:
        request = _load_request(request_path)
        overrides = profile_to_engine_overrides(request.profile, request.performance_guard)
        override_path = write_yaml_like_json(temp_dir / "gui_profile_override.yaml", overrides)

        export_html = bool(request.profile.export_html_report)
        export_json = bool(request.profile.export_json_data)
        resume_run_dir = request.resume_run_dir.strip() or None
        output_directory = request.output_directory
        if resume_run_dir:
            output_directory = str(Path(resume_run_dir).expanduser().resolve().parent)
        options = ScanOptions(
            target_input=request.target_input,
            output_directory=output_directory,
            profile=request.profile.base_profile,
            user_config_path=str(override_path),
            max_ports=request.profile.max_ports,
            json_only=(export_json and not export_html),
            html_only=(export_html and not export_json),
            no_report=(not export_html),
            rich_ui=False,
            emit_plain_logs=False,
            audience=request.audience,
            risk_mode=request.profile.risk_mode,
            resume_run_dir=resume_run_dir,
        )
        silent_console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        plan_bundle, run_store = build_scan_plan(options, console=silent_console)
        context = plan_bundle["context"]
        context.event_emitter = (
            lambda event, payload: _emit(
                event,
                run_id=run_store.run_id,
                run_dir=str(run_store.run_dir),
                **payload,
            )
        )
        extension_store = GuiExtensionStore()
        selected_extension_records = [
            record
            for record in extension_store.list_command_hook_extensions()
            if record.extension_id in set(request.enabled_extension_ids)
        ]
        context.post_run_processors.append(
            lambda inner_context, inner_run_data, inner_run_store: run_command_hook_extensions(
                request=request,
                records=selected_extension_records,
                run_store=inner_run_store,
                run_data=inner_run_data,
                event_emitter=inner_context.event_emitter,
            )
        )
        total_tasks = len(
            [item for item in plan_bundle["plan_result"].items if getattr(item, "selected", False)]
        )
        run_store.write_json(
            "data/gui_session.json",
            {
                "scan_name": request.scan_name,
                "workspace_id": request.workspace_id,
                "workspace_name": request.workspace_name,
                "engagement_id": request.workspace_id,
                "engagement_name": request.workspace_name,
                "profile_name": request.profile.name,
                "base_profile": request.profile.base_profile,
                "started_at": now_iso(),
                "target_input": request.target_input,
                "run_id": run_store.run_id,
                "resume_run_dir": resume_run_dir or "",
                "launch_mode": request.launch_mode,
                "enabled_extension_ids": request.enabled_extension_ids,
            },
        )
        run_store.write_json("data/gui_requested_profile.json", request.profile.to_dict())
        write_yaml_like_json(run_store.data_dir / "gui_engine_overrides.yaml", overrides)
        _emit(
            "worker.ready",
            scan_name=request.scan_name,
            run_id=run_store.run_id,
            run_dir=str(run_store.run_dir),
            total_tasks=total_tasks,
            workspace_id=request.workspace_id,
            workspace_name=request.workspace_name,
        )
        outcome = _execute_scan_plan(options=options, plan_bundle=plan_bundle, run_store=run_store, console=silent_console)
        _emit(
            "worker.completed",
            scan_name=request.scan_name,
            run_id=outcome.run_id,
            run_dir=str(outcome.run_dir),
            state=outcome.state,
            duration_seconds=outcome.duration_seconds,
            findings=outcome.finding_count,
            warnings=outcome.warning_count,
            errors=outcome.error_count,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        _emit("worker.error", message=str(exc), request_path=str(request_path))
        return 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
