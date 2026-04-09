from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attackcastle.core.models import parse_datetime, run_data_from_dict, to_serializable
from attackcastle.core.migrations import migrate_payload
from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.gui.models import GuiProfile, RunSnapshot
from attackcastle.storage.run_store import RunStore

TERMINAL_TASK_STATUSES = {"completed", "skipped", "failed", "blocked", "cancelled"}
ACTIVE_TASK_STATUSES = {"running", "waiting"}
RUNTIME_CHECKPOINT_KEYS = {"_runtime_state"}


def profile_to_engine_overrides(profile: GuiProfile) -> dict[str, Any]:
    coverage_engine = {
        "enabled": True,
        "mode": profile.active_validation_mode,
        "request_replay_enabled": profile.request_replay_enabled,
        "per_target_budget": profile.validation_budget_per_target,
        "target_duration_hours": profile.target_duration_hours,
        "revisit_enabled": profile.revisit_enabled,
        "breadth_first": profile.breadth_first,
        "unauthenticated_only": profile.unauthenticated_only,
        "use_default_presets": profile.use_default_validation_presets,
        "groups": {
            "web": {"enabled": profile.enable_web_playbooks},
            "tls": {"enabled": profile.enable_tls_playbooks},
            "service": {"enabled": profile.enable_service_playbooks},
        },
        "playbooks": {
            "object_access": {"enabled": profile.enable_object_access_playbook},
            "input_reflection_injection": {"enabled": profile.enable_input_reflection_playbook},
            "api_expansion": {"enabled": profile.enable_api_expansion_playbook},
            "admin_debug_exposure": {"enabled": profile.enable_admin_debug_playbook},
            "client_artifact_exposure": {"enabled": profile.enable_client_artifact_playbook},
            "framework_component_exposure": {"enabled": profile.enable_framework_component_playbook},
            "web_misconfiguration_breadth": {"enabled": profile.enable_web_misconfiguration_playbook},
            "tls_hardening": {"enabled": profile.enable_tls_playbooks},
            "certificate_san_identity": {"enabled": profile.enable_tls_playbooks},
            "edge_header_hardening": {"enabled": profile.enable_tls_playbooks},
            "management_plane_exposure": {"enabled": profile.enable_tls_playbooks or profile.enable_service_playbooks},
            "ssh_exposure": {"enabled": profile.enable_service_playbooks},
            "ftp_exposure": {"enabled": profile.enable_service_playbooks},
            "smtp_exposure": {"enabled": profile.enable_service_playbooks},
            "dns_exposure": {"enabled": profile.enable_service_playbooks},
            "rdp_exposure": {"enabled": profile.enable_service_playbooks},
            "smb_exposure": {"enabled": profile.enable_service_playbooks},
            "vpn_remote_access_exposure": {"enabled": profile.enable_service_playbooks},
            "generic_remote_admin_exposure": {"enabled": profile.enable_service_playbooks},
            "service_version_and_cve_enrichment": {"enabled": profile.enable_service_playbooks},
        },
        "families": {
            "injection": {"enabled": True, "preset_path": profile.injection_preset_path},
            "xss": {"enabled": True, "preset_path": profile.xss_preset_path},
            "sqli": {"enabled": True, "preset_path": profile.sqli_preset_path},
            "auth_rate_limit": {
                "enabled": True,
                "preset_path": profile.auth_rate_limit_preset_path,
            },
            "misconfig": {"enabled": True, "preset_path": profile.misconfig_preset_path},
            "data_exposure": {
                "enabled": True,
                "preset_path": profile.data_exposure_preset_path,
            },
            "api_idor": {"enabled": True, "preset_path": profile.api_idor_preset_path},
            "upload": {"enabled": True, "preset_path": profile.upload_preset_path},
            "component": {"enabled": True, "preset_path": profile.component_preset_path},
            "infra": {"enabled": True, "preset_path": profile.infra_preset_path},
        },
    }
    return {
        "profile": {
            "concurrency": profile.concurrency,
            "cpu_cores": profile.cpu_cores,
            "delay_ms_between_requests": profile.delay_ms_between_requests,
        },
        "scan": {
            "max_ports": profile.max_ports,
            "risk_mode": profile.risk_mode,
        },
        "proxy": {
            "url": profile.proxy_url.strip() if profile.proxy_enabled else "",
        },
        "request_capture": {
            "enabled": True,
        },
        "coverage_engine": coverage_engine,
        "active_validation": coverage_engine,
        "adaptive_execution": {
            "enabled": profile.adaptive_execution_enabled,
            "cpu_core_cap": profile.cpu_cores,
        },
        "rate_limit": {
            "execution_mode": profile.rate_limit_mode,
        },
        "nmap": {"enabled": profile.enable_nmap},
        "whatweb": {"enabled": profile.enable_whatweb},
        "nikto": {"enabled": profile.enable_nikto},
        "nuclei": {
            "enabled": profile.enable_nuclei,
            "payload_wordlist_path": profile.payload_wordlist_path,
        },
        "wpscan": {"enabled": profile.enable_wpscan},
        "sqlmap": {
            "enabled": profile.enable_sqlmap,
            "parameter_wordlist_path": profile.parameter_wordlist_path,
            "payload_wordlist_path": profile.payload_wordlist_path,
        },
        "web_discovery": {
            "endpoint_wordlist_path": profile.endpoint_wordlist_path,
            "parameter_wordlist_path": profile.parameter_wordlist_path,
            "payload_wordlist_path": profile.payload_wordlist_path,
        },
        "web_probe": {"capture_screenshots": True},
    }


def read_json_file(path: Path) -> dict[str, Any] | list[Any] | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_yaml_like_json(path: Path, payload: dict[str, Any]) -> Path:
    import yaml

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path


def _load_run_data(run_store: RunStore):
    scan_payload = read_json_file(run_store.data_dir / "scan_data.json")
    if isinstance(scan_payload, dict):
        return run_data_from_dict(migrate_payload(scan_payload))
    checkpoint = run_store.load_latest_checkpoint()
    if checkpoint and isinstance(checkpoint.get("run_data"), dict):
        return run_data_from_dict(migrate_payload(checkpoint["run_data"]))
    return None


def _load_gui_session(run_store: RunStore) -> dict[str, Any]:
    payload = read_json_file(run_store.data_dir / "gui_session.json")
    return payload if isinstance(payload, dict) else {}


def _load_plan_total(run_store: RunStore) -> int:
    payload = read_json_file(run_store.data_dir / "plan.json")
    if not isinstance(payload, dict):
        return 0
    items = payload.get("items", [])
    return len([item for item in items if isinstance(item, dict) and item.get("selected") is True])


def _load_checkpoint_manifest(run_store: RunStore) -> list[dict[str, Any]]:
    payload = read_json_file(run_store.checkpoints_dir / "manifest.json")
    if not isinstance(payload, dict):
        return []
    checkpoints = payload.get("checkpoints", [])
    return [item for item in checkpoints if isinstance(item, dict)]


def _estimate_eta(elapsed_seconds: float, completed_tasks: int, total_tasks: int, state: str) -> float | None:
    if state in {"completed", "failed", "cancelled"}:
        return 0.0
    if completed_tasks <= 0 or total_tasks <= completed_tasks:
        return None
    per_task = elapsed_seconds / max(completed_tasks, 1)
    remaining = max(total_tasks - completed_tasks, 0)
    return round(per_task * remaining, 1)


def _build_site_map(run_data) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for observation in getattr(run_data, "observations", []):
        key = str(getattr(observation, "key", ""))
        values = getattr(observation, "value", None)
        if key not in {
            "web.discovery.urls",
            "web.discovery.js_endpoints",
            "web.discovery.graphql_endpoints",
            "web.discovery.framework_artifacts",
            "web.discovery.source_maps",
        }:
            continue
        if not isinstance(values, list):
            continue
        for item in values:
            url = str(item).strip()
            if not url:
                continue
            signature = (key, url)
            if signature in seen:
                continue
            seen.add(signature)
            rows.append(
                {
                    "source": key,
                    "url": url,
                    "entity_id": getattr(observation, "entity_id", ""),
                }
            )
    rows.sort(key=lambda item: (item["source"], item["url"]))
    return rows


def _build_artifacts(run_data) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for evidence in getattr(run_data, "evidence", []):
        path = str(getattr(evidence, "artifact_path", "") or "").strip()
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        rows.append(
            {
                "path": path,
                "kind": getattr(evidence, "kind", "artifact"),
                "source_tool": getattr(evidence, "source_tool", ""),
                "caption": getattr(evidence, "snippet", ""),
            }
        )
    for execution in getattr(run_data, "tool_executions", []):
        for path in [
            getattr(execution, "stdout_path", None),
            getattr(execution, "stderr_path", None),
            *list(getattr(execution, "raw_artifact_paths", []) or []),
        ]:
            normalized = str(path or "").strip()
            if not normalized or normalized in seen_paths:
                continue
            seen_paths.add(normalized)
            rows.append(
                {
                    "path": normalized,
                    "kind": "tool_output",
                    "source_tool": getattr(execution, "tool_name", ""),
                    "caption": getattr(execution, "status", ""),
                }
            )
    for artifact in getattr(run_data, "evidence_artifacts", []):
        normalized = str(getattr(artifact, "path", "") or "").strip()
        if not normalized or normalized in seen_paths:
            continue
        seen_paths.add(normalized)
        rows.append(
            {
                "path": normalized,
                "kind": getattr(artifact, "kind", "artifact"),
                "source_tool": getattr(artifact, "source_tool", ""),
                "caption": getattr(artifact, "caption", ""),
            }
        )
    rows.sort(key=lambda item: (item["source_tool"], item["path"]))
    return rows


def _parse_debug_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    return parse_datetime(value)


def _path_text(path: str) -> str:
    return str(Path(path).expanduser()) if str(path or "").strip() else ""


def _artifact_paths_from_task_result(result: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    transcript_path = _path_text(str(result.get("transcript_path") or ""))
    if transcript_path:
        paths.add(transcript_path)
    for artifact in result.get("raw_artifacts", []):
        if not isinstance(artifact, dict):
            continue
        normalized = _path_text(str(artifact.get("path") or ""))
        if normalized:
            paths.add(normalized)
    return paths


def _artifact_paths_from_tool_execution(execution: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for key in ("stdout_path", "stderr_path", "transcript_path"):
        normalized = _path_text(str(execution.get(key) or ""))
        if normalized:
            paths.add(normalized)
    for item in execution.get("raw_artifact_paths", []):
        normalized = _path_text(str(item or ""))
        if normalized:
            paths.add(normalized)
    return paths


def _artifact_paths_from_evidence_artifact(artifact: dict[str, Any]) -> set[str]:
    normalized = _path_text(str(artifact.get("path") or ""))
    return {normalized} if normalized else set()


def _task_sort_key(task: dict[str, Any]) -> tuple[float, float, str]:
    started_at = _parse_debug_datetime(task.get("started_at"))
    ended_at = _parse_debug_datetime(task.get("ended_at"))
    started_value = started_at.timestamp() if started_at is not None else -1.0
    ended_value = ended_at.timestamp() if ended_at is not None else -1.0
    return (ended_value, started_value, str(task.get("key") or ""))


def _execution_sort_key(row: dict[str, Any]) -> tuple[float, float, str]:
    started_at = _parse_debug_datetime(row.get("started_at"))
    ended_at = _parse_debug_datetime(row.get("ended_at"))
    started_value = started_at.timestamp() if started_at is not None else -1.0
    ended_value = ended_at.timestamp() if ended_at is not None else -1.0
    return (started_value, ended_value, str(row.get("tool_name") or row.get("execution_id") or ""))


def _result_sort_key(row: dict[str, Any]) -> tuple[float, float, str]:
    started_at = _parse_debug_datetime(row.get("started_at"))
    finished_at = _parse_debug_datetime(row.get("finished_at"))
    started_value = started_at.timestamp() if started_at is not None else -1.0
    finished_value = finished_at.timestamp() if finished_at is not None else -1.0
    return (started_value, finished_value, str(row.get("task_type") or row.get("task_id") or ""))


def _build_path_dump(path: str, label: str) -> list[str]:
    normalized = _path_text(path)
    lines = [f"{label}: {normalized or '[not recorded]'}"]
    if not normalized:
        return lines
    file_path = Path(normalized)
    if not file_path.exists():
        lines.append(f"[missing file] {normalized}")
        return lines
    if not file_path.is_file():
        lines.append(f"[not a file] {normalized}")
        return lines
    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        lines.append("[non-text content omitted]")
        return lines
    except Exception as exc:  # noqa: BLE001
        lines.append(f"[unreadable] {exc}")
        return lines
    lines.append(content if content else "[empty file]")
    return lines


def _build_termination_dump(payload: dict[str, Any]) -> list[str]:
    termination_reason = str(payload.get("termination_reason") or "").strip() or "unknown"
    termination_detail = str(payload.get("termination_detail") or "").strip() or "[none recorded]"
    lines = [f"termination_reason: {termination_reason}"]
    lines.append(f"timed_out: {bool(payload.get('timed_out', False))}")
    lines.append(f"termination_detail: {termination_detail}")
    return lines


def _match_execution_for_result(
    result: dict[str, Any],
    tool_executions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    command = str(result.get("command") or "").strip()
    started_at = _parse_debug_datetime(result.get("started_at"))
    finished_at = _parse_debug_datetime(result.get("finished_at"))
    ranked: list[tuple[int, dict[str, Any]]] = []
    for execution in tool_executions:
        score = 0
        if command and command == str(execution.get("command") or "").strip():
            score += 12
        execution_started = _parse_debug_datetime(execution.get("started_at"))
        execution_ended = _parse_debug_datetime(execution.get("ended_at"))
        if started_at is not None and execution_started is not None:
            delta = abs((execution_started - started_at).total_seconds())
            if delta <= 2:
                score += 5
            elif delta <= 30:
                score += 3
        if finished_at is not None and execution_ended is not None:
            delta = abs((execution_ended - finished_at).total_seconds())
            if delta <= 2:
                score += 5
            elif delta <= 30:
                score += 3
        if score > 0:
            ranked.append((score, execution))
    ranked.sort(key=lambda item: (-item[0], _execution_sort_key(item[1])))
    return ranked[0][1] if ranked else None


def _synthesize_task_rows(
    manifest: list[dict[str, Any]],
    task_results: list[dict[str, Any]],
    tool_executions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    visible_manifest = [item for item in manifest if str(item.get("task_key") or "") not in RUNTIME_CHECKPOINT_KEYS]
    if task_results:
        for index, result in enumerate(sorted(task_results, key=_result_sort_key), start=1):
            task_type = str(result.get("task_type") or "").strip()
            task_id = str(result.get("task_id") or "").strip()
            matched_execution = _match_execution_for_result(result, tool_executions)
            detail: dict[str, Any] = {"source": "task_result_fallback"}
            if matched_execution is not None:
                capability = str(matched_execution.get("capability") or "").strip()
                if capability:
                    detail["capability"] = capability
            termination_reason = str(result.get("termination_reason") or "").strip()
            termination_detail = str(result.get("termination_detail") or "").strip()
            if termination_reason:
                detail["termination_reason"] = termination_reason
            if termination_detail:
                detail["reason"] = termination_detail
            rows.append(
                {
                    "key": task_id or f"{task_type or 'task'}:{index}",
                    "label": task_type or task_id or f"Task {index}",
                    "status": str(result.get("status") or "unknown"),
                    "started_at": result.get("started_at") or "",
                    "ended_at": result.get("finished_at") or "",
                    "detail": detail,
                }
            )
        return rows
    if visible_manifest:
        for item in visible_manifest:
            task_key = str(item.get("task_key") or "").strip()
            status = str(item.get("status") or "unknown")
            rows.append(
                {
                    "key": task_key or status,
                    "label": task_key or status,
                    "status": status,
                    "started_at": "",
                    "ended_at": "",
                    "detail": {"source": "checkpoint_manifest"},
                }
            )
        return rows
    for index, execution in enumerate(sorted(tool_executions, key=_execution_sort_key), start=1):
        detail: dict[str, Any] = {"source": "tool_execution_fallback"}
        capability = str(execution.get("capability") or "").strip()
        if capability:
            detail["capability"] = capability
        termination_reason = str(execution.get("termination_reason") or "").strip()
        termination_detail = str(execution.get("termination_detail") or "").strip()
        if termination_reason:
            detail["termination_reason"] = termination_reason
        if termination_detail:
            detail["reason"] = termination_detail
        rows.append(
            {
                "key": str(execution.get("execution_id") or f"execution:{index}"),
                "label": str(execution.get("tool_name") or f"Execution {index}"),
                "status": str(execution.get("status") or "unknown"),
                "started_at": execution.get("started_at") or "",
                "ended_at": execution.get("ended_at") or "",
                "detail": detail,
            }
        )
    return rows


def _format_mapping_block(title: str, payload: dict[str, Any], *, skip_keys: set[str] | None = None) -> list[str]:
    skip = skip_keys or set()
    lines = [title]
    for key, value in payload.items():
        if key in skip:
            continue
        if isinstance(value, list):
            lines.append(f"- {key}: {len(value)} item(s)")
        elif isinstance(value, dict):
            lines.append(f"- {key}: {json.dumps(value, indent=2, sort_keys=True)}")
        else:
            lines.append(f"- {key}: {value}")
    return lines


def _matching_task_results(snapshot: RunSnapshot, task_row: dict[str, Any]) -> list[dict[str, Any]]:
    task_key = str(task_row.get("key") or "").strip()
    task_started = _parse_debug_datetime(task_row.get("started_at"))
    task_ended = _parse_debug_datetime(task_row.get("ended_at"))
    ranked: list[tuple[int, dict[str, Any]]] = []
    for result in snapshot.task_results:
        score = 0
        task_type = str(result.get("task_type") or "").strip()
        if task_key and task_type == task_key:
            score += 12
        command = str(result.get("command") or "")
        if task_key and task_key in command:
            score += 3
        started_at = _parse_debug_datetime(result.get("started_at"))
        finished_at = _parse_debug_datetime(result.get("finished_at"))
        if task_started is not None and started_at is not None:
            delta = abs((started_at - task_started).total_seconds())
            if delta <= 2:
                score += 5
            elif delta <= 30:
                score += 3
        if task_ended is not None and finished_at is not None:
            delta = abs((finished_at - task_ended).total_seconds())
            if delta <= 2:
                score += 5
            elif delta <= 30:
                score += 3
        if score > 0:
            ranked.append((score, result))
    ranked.sort(key=lambda item: (-item[0], _result_sort_key(item[1])))
    return [result for _score, result in ranked]


def _matching_tool_executions(
    snapshot: RunSnapshot,
    task_row: dict[str, Any] | None = None,
    *,
    preferred_tool_row: dict[str, Any] | None = None,
    matched_results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    preferred_execution_id = str((preferred_tool_row or {}).get("execution_id") or "").strip()
    preferred_paths = _artifact_paths_from_tool_execution(preferred_tool_row or {})
    task_key = str((task_row or {}).get("key") or "").strip()
    task_label = str((task_row or {}).get("label") or "").strip().lower()
    task_capability = ""
    detail = (task_row or {}).get("detail", {})
    if isinstance(detail, dict):
        task_capability = str(detail.get("capability") or "").strip()
    task_started = _parse_debug_datetime((task_row or {}).get("started_at"))
    task_ended = _parse_debug_datetime((task_row or {}).get("ended_at"))
    result_paths: set[str] = set()
    for result in matched_results or []:
        result_paths.update(_artifact_paths_from_task_result(result))

    ranked: list[tuple[int, dict[str, Any]]] = []
    for execution in snapshot.tool_executions:
        score = 0
        execution_id = str(execution.get("execution_id") or "").strip()
        execution_paths = _artifact_paths_from_tool_execution(execution)
        if preferred_execution_id and execution_id == preferred_execution_id:
            score += 100
        if preferred_paths and execution_paths.intersection(preferred_paths):
            score += 80
        if result_paths and execution_paths.intersection(result_paths):
            score += 40
        capability = str(execution.get("capability") or "").strip()
        if task_capability and capability == task_capability:
            score += 12
        command = str(execution.get("command") or "")
        lowered_command = command.lower()
        if task_key and task_key in command:
            score += 4
        if task_label and task_label in lowered_command:
            score += 2
        started_at = _parse_debug_datetime(execution.get("started_at"))
        ended_at = _parse_debug_datetime(execution.get("ended_at"))
        if task_started is not None and started_at is not None:
            delta = abs((started_at - task_started).total_seconds())
            if delta <= 2:
                score += 8
            elif delta <= 30:
                score += 5
            elif delta <= 300:
                score += 2
        if task_ended is not None and ended_at is not None:
            delta = abs((ended_at - task_ended).total_seconds())
            if delta <= 2:
                score += 8
            elif delta <= 30:
                score += 5
            elif delta <= 300:
                score += 2
        if score > 0:
            ranked.append((score, execution))
    ranked.sort(key=lambda item: (-item[0], _execution_sort_key(item[1])))
    return [execution for _score, execution in ranked]


def _matching_evidence_artifacts(
    snapshot: RunSnapshot,
    task_results: list[dict[str, Any]],
    tool_executions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    source_task_ids = {
        str(result.get("task_id") or "").strip()
        for result in task_results
        if str(result.get("task_id") or "").strip()
    }
    source_execution_ids = {
        str(execution.get("execution_id") or "").strip()
        for execution in tool_executions
        if str(execution.get("execution_id") or "").strip()
    }
    artifact_paths: set[str] = set()
    for result in task_results:
        artifact_paths.update(_artifact_paths_from_task_result(result))
    for execution in tool_executions:
        artifact_paths.update(_artifact_paths_from_tool_execution(execution))

    matched: list[dict[str, Any]] = []
    for artifact in snapshot.evidence_artifacts:
        source_task_id = str(artifact.get("source_task_id") or "").strip()
        source_execution_id = str(artifact.get("source_execution_id") or "").strip()
        artifact_path = _artifact_paths_from_evidence_artifact(artifact)
        if (
            (source_task_id and source_task_id in source_task_ids)
            or (source_execution_id and source_execution_id in source_execution_ids)
            or (artifact_path and artifact_paths.intersection(artifact_path))
        ):
            matched.append(artifact)
    matched.sort(key=lambda item: (_path_text(str(item.get("path") or "")), str(item.get("kind") or "")))
    return matched


def _select_task_row(
    snapshot: RunSnapshot,
    *,
    task_row: dict[str, Any] | None = None,
    tool_row: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if task_row is not None:
        return task_row
    if tool_row is not None:
        matched = _matching_tool_executions(snapshot, preferred_tool_row=tool_row)
        if matched:
            selected = matched[0]
            execution_started = _parse_debug_datetime(selected.get("started_at"))
            best_task: dict[str, Any] | None = None
            best_delta: float | None = None
            for candidate in snapshot.tasks:
                detail = candidate.get("detail", {})
                if not isinstance(detail, dict):
                    detail = {}
                capability = str(detail.get("capability") or "").strip()
                if capability and capability != str(selected.get("capability") or "").strip():
                    continue
                candidate_started = _parse_debug_datetime(candidate.get("started_at"))
                if execution_started is None or candidate_started is None:
                    if best_task is None:
                        best_task = candidate
                    continue
                delta = abs((candidate_started - execution_started).total_seconds())
                if best_delta is None or delta < best_delta:
                    best_task = candidate
                    best_delta = delta
            if best_task is not None:
                return best_task
    active = [row for row in snapshot.tasks if str(row.get("status") or "") in ACTIVE_TASK_STATUSES]
    if active:
        return sorted(active, key=_task_sort_key, reverse=True)[0]
    if snapshot.tasks:
        return sorted(snapshot.tasks, key=_task_sort_key, reverse=True)[0]
    return None


def resolve_current_task_debug_bundle(
    snapshot: RunSnapshot,
    *,
    task_row: dict[str, Any] | None = None,
    tool_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_task = _select_task_row(snapshot, task_row=task_row, tool_row=tool_row)
    if selected_task is None and tool_row is None:
        return {
            "title": "Current Task Debug Log",
            "task": None,
            "task_results": [],
            "tool_executions": [],
            "evidence_artifacts": [],
            "text": "No task activity has been recorded yet.",
        }

    task_results = _matching_task_results(snapshot, selected_task) if selected_task is not None else []
    tool_executions = _matching_tool_executions(
        snapshot,
        selected_task,
        preferred_tool_row=tool_row,
        matched_results=task_results,
    )
    evidence_artifacts = _matching_evidence_artifacts(snapshot, task_results, tool_executions)
    lines: list[str] = []

    if selected_task is not None:
        title = f"Current Task Debug Log: {selected_task.get('label') or selected_task.get('key') or 'Task'}"
        lines.extend(_format_mapping_block("Task", selected_task))
    else:
        title = f"Current Task Debug Log: {tool_row.get('tool_name') or 'Command'}"
        lines.append("No task row matched the selected command. Showing execution details only.")

    if task_results:
        lines.extend(["", "Task Results"])
        for index, result in enumerate(sorted(task_results, key=_result_sort_key), start=1):
            lines.extend(_format_mapping_block(f"Result {index}", result, skip_keys={"raw_artifacts"}))
            raw_artifacts = result.get("raw_artifacts", [])
            if isinstance(raw_artifacts, list) and raw_artifacts:
                lines.append("- raw_artifacts:")
                for artifact in raw_artifacts:
                    if not isinstance(artifact, dict):
                        continue
                    lines.append(f"  - {artifact.get('artifact_type')}: {artifact.get('path')}")
            lines.append("")

    if tool_executions:
        lines.extend(["", "Tool Executions"])
        for index, execution in enumerate(sorted(tool_executions, key=_execution_sort_key), start=1):
            lines.extend(
                _format_mapping_block(
                    f"Command {index}",
                    execution,
                    skip_keys={"stdout_path", "stderr_path", "transcript_path", "raw_artifact_paths"},
                )
            )
            lines.extend(_build_termination_dump(execution))
            lines.append("")
            lines.extend(_build_path_dump(str(execution.get("transcript_path") or ""), "terminal transcript"))
            lines.append("")
            lines.extend(_build_path_dump(str(execution.get("stdout_path") or ""), "stdout"))
            lines.append("")
            lines.extend(_build_path_dump(str(execution.get("stderr_path") or ""), "stderr"))
            raw_artifacts = execution.get("raw_artifact_paths", [])
            if isinstance(raw_artifacts, list):
                for artifact_index, artifact_path in enumerate(raw_artifacts, start=1):
                    lines.append("")
                    lines.extend(_build_path_dump(str(artifact_path or ""), f"raw artifact {artifact_index}"))
            lines.append("")

    if evidence_artifacts:
        lines.extend(["", "Evidence Artifacts"])
        for index, artifact in enumerate(evidence_artifacts, start=1):
            lines.extend(_format_mapping_block(f"Evidence {index}", artifact, skip_keys={"path"}))
            lines.extend(_build_path_dump(str(artifact.get("path") or ""), "artifact"))
            lines.append("")

    if not task_results and not tool_executions and not evidence_artifacts:
        lines.append("No persisted command or artifact records were matched for this task yet.")

    return {
        "title": title,
        "task": selected_task,
        "task_results": task_results,
        "tool_executions": tool_executions,
        "evidence_artifacts": evidence_artifacts,
        "text": "\n".join(lines).strip(),
    }


def build_run_debug_bundle(
    snapshot: RunSnapshot,
    *,
    task_row: dict[str, Any] | None = None,
    tool_row: dict[str, Any] | None = None,
) -> dict[str, str]:
    current_task_bundle = resolve_current_task_debug_bundle(snapshot, task_row=task_row, tool_row=tool_row)
    overview_lines = [
        f"Run ID: {snapshot.run_id}",
        f"Scan Name: {snapshot.scan_name}",
        f"State: {snapshot.state}",
        f"Workspace: {snapshot.workspace_name or 'Ad-Hoc Session'}",
        f"Target Input: {snapshot.target_input or '[none]'}",
        f"Run Directory: {snapshot.run_dir or '[none]'}",
        f"Current Task: {snapshot.current_task or 'Idle'}",
        f"Progress: {snapshot.completed_tasks}/{snapshot.total_tasks}",
        f"Elapsed Seconds: {snapshot.elapsed_seconds}",
        f"ETA Seconds: {snapshot.eta_seconds}",
        f"Warnings: {len(snapshot.warnings)}",
        f"Errors: {len(snapshot.errors)}",
        f"Execution Issues: {snapshot.execution_issues_summary.get('total_count', 0)}",
        f"Completeness: {snapshot.completeness_status}",
        "",
        "Warnings",
    ]
    overview_lines.extend([f"- {warning}" for warning in snapshot.warnings] or ["- none"])
    overview_lines.extend(["", "Errors"])
    overview_lines.extend([f"- {error}" for error in snapshot.errors] or ["- none"])
    overview_lines.extend(["", "Execution Issues"])
    if snapshot.execution_issues:
        for issue in snapshot.execution_issues:
            overview_lines.append(
                f"- {issue.get('kind')} | {issue.get('status')} | {issue.get('label')} | {issue.get('message')}"
            )
    else:
        overview_lines.append("- none")

    combined_lines = ["Task Timeline"]
    task_rows = snapshot.tasks or _synthesize_task_rows([], snapshot.task_results, snapshot.tool_executions)
    if task_rows:
        for task in sorted(task_rows, key=_task_sort_key):
            detail = task.get("detail", {})
            detail_text = json.dumps(detail, sort_keys=True) if isinstance(detail, dict) and detail else "{}"
            combined_lines.append(
                f"- {task.get('label') or task.get('key')} | status={task.get('status')} | started={task.get('started_at') or '-'} | "
                f"ended={task.get('ended_at') or '-'} | detail={detail_text}"
            )
    else:
        combined_lines.append("- No task rows recorded.")

    combined_lines.extend(["", "Task Results"])
    if snapshot.task_results:
        for result in sorted(snapshot.task_results, key=_result_sort_key):
            combined_lines.append(
                f"- {result.get('task_type') or result.get('task_id')} | status={result.get('status')} | exit={result.get('exit_code')} | "
                f"started={result.get('started_at') or '-'} | finished={result.get('finished_at') or '-'}"
            )
            combined_lines.append(f"  command: {result.get('command') or '[none]'}")
            combined_lines.extend([f"  {line}" for line in _build_termination_dump(result)])
    else:
        combined_lines.append("- No task results recorded.")

    combined_lines.extend(["", "Tool Executions"])
    if snapshot.tool_executions:
        for execution in sorted(snapshot.tool_executions, key=_execution_sort_key):
            combined_lines.append(
                f"- {execution.get('tool_name')} | status={execution.get('status')} | exit={execution.get('exit_code')} | "
                f"capability={execution.get('capability') or '-'} | started={execution.get('started_at') or '-'} | ended={execution.get('ended_at') or '-'}"
            )
            combined_lines.append(f"  command: {execution.get('command') or '[none]'}")
            combined_lines.extend([f"  {line}" for line in _build_termination_dump(execution)])
            combined_lines.extend(
                [f"  {line}" for line in _build_path_dump(str(execution.get('transcript_path') or ''), "terminal transcript")]
            )
            combined_lines.extend([f"  {line}" for line in _build_path_dump(str(execution.get('stdout_path') or ''), "stdout")])
            combined_lines.extend([f"  {line}" for line in _build_path_dump(str(execution.get('stderr_path') or ''), "stderr")])
            raw_artifacts = execution.get("raw_artifact_paths", [])
            if isinstance(raw_artifacts, list):
                for artifact_index, artifact_path in enumerate(raw_artifacts, start=1):
                    combined_lines.extend(
                        [f"  {line}" for line in _build_path_dump(str(artifact_path or ""), f"raw artifact {artifact_index}")]
                    )
    else:
        combined_lines.append("- No tool executions recorded.")

    combined_lines.extend(["", "Run Log"])
    run_log_path = str(Path(snapshot.run_dir) / "logs" / "run.log") if snapshot.run_dir else ""
    combined_lines.extend(_build_path_dump(run_log_path, "logs/run.log"))

    return {
        "title": f"Debug Log: {snapshot.scan_name}",
        "overview": "\n".join(overview_lines).strip(),
        "combined_log": "\n".join(combined_lines).strip(),
        "current_task": current_task_bundle["text"],
        "current_task_title": str(current_task_bundle.get("title") or "Current Task Debug Log"),
    }


def load_run_snapshot(run_dir: Path) -> RunSnapshot:
    run_store = RunStore.from_existing(run_dir)
    gui_session = _load_gui_session(run_store)
    run_data = _load_run_data(run_store)
    manifest = _load_checkpoint_manifest(run_store)
    summary = read_json_file(run_store.data_dir / "run_summary.json")
    summary = summary if isinstance(summary, dict) else {}

    total_tasks = _load_plan_total(run_store)
    completed_tasks = len(
        [
            item
            for item in manifest
            if str(item.get("status")) in TERMINAL_TASK_STATUSES
            and str(item.get("task_key") or "") not in RUNTIME_CHECKPOINT_KEYS
        ]
    )
    running_tasks = [
        str(item.get("task_key"))
        for item in manifest
        if str(item.get("status")) == "running" and str(item.get("task_key") or "") not in RUNTIME_CHECKPOINT_KEYS
    ]
    current_task = ", ".join(running_tasks[:2]) if running_tasks else "Idle"

    state = str(summary.get("state") or "running")
    started_at = None
    ended_at = None
    tasks: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    web_apps: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    site_map: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    login_surfaces: list[dict[str, Any]] = []
    replay_requests: list[dict[str, Any]] = []
    surface_signals: list[dict[str, Any]] = []
    attack_paths: list[dict[str, Any]] = []
    investigation_steps: list[dict[str, Any]] = []
    playbook_executions: list[dict[str, Any]] = []
    coverage_decisions: list[dict[str, Any]] = []
    validation_results: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    validation_tasks: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    screenshots: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    task_results: list[dict[str, Any]] = []
    tool_executions: list[dict[str, Any]] = []
    evidence_artifacts: list[dict[str, Any]] = []
    extensions: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    execution_issues: list[dict[str, Any]] = []
    execution_issues_summary: dict[str, Any] = {}
    completeness_status = "healthy"
    run_id = str(gui_session.get("run_id") or run_store.run_id)
    scan_name = str(gui_session.get("scan_name") or run_store.run_id)
    workspace_id = str(gui_session.get("workspace_id") or gui_session.get("engagement_id") or "")
    workspace_name = str(gui_session.get("workspace_name") or gui_session.get("engagement_name") or "")
    target_input = str(gui_session.get("target_input") or "")
    profile_name = str(gui_session.get("profile_name") or gui_session.get("base_profile") or "")

    if run_data is not None:
        run_id = run_data.metadata.run_id
        started_at = run_data.metadata.started_at
        ended_at = run_data.metadata.ended_at
        state = run_data.metadata.state.value if hasattr(run_data.metadata.state, "value") else str(run_data.metadata.state)
        tasks = list(run_data.task_states or [])
        assets = to_serializable(run_data.assets)
        web_apps = to_serializable(run_data.web_apps)
        technologies = to_serializable(run_data.technologies)
        evidence = to_serializable(run_data.evidence)
        site_map = _build_site_map(run_data)
        endpoints = to_serializable(run_data.endpoints)
        parameters = to_serializable(run_data.parameters)
        forms = to_serializable(run_data.forms)
        login_surfaces = to_serializable(run_data.login_surfaces)
        replay_requests = to_serializable(run_data.replay_requests)
        surface_signals = to_serializable(run_data.surface_signals)
        attack_paths = to_serializable(run_data.attack_paths)
        investigation_steps = to_serializable(run_data.investigation_steps)
        playbook_executions = to_serializable(run_data.playbook_executions)
        coverage_decisions = to_serializable(run_data.coverage_decisions)
        validation_results = to_serializable(run_data.validation_results)
        hypotheses = to_serializable(run_data.hypotheses)
        validation_tasks = to_serializable(run_data.validation_tasks)
        coverage_gaps = to_serializable(run_data.coverage_gaps)
        artifacts = _build_artifacts(run_data)
        screenshots = [
            {
                "path": item.get("artifact_path"),
                "caption": item.get("snippet", ""),
                "source_tool": item.get("source_tool", ""),
            }
            for item in evidence
            if str(item.get("kind")) == "web_screenshot" and item.get("artifact_path")
        ]
        services = to_serializable(run_data.services)
        findings = to_serializable(run_data.findings)
        task_results = to_serializable(run_data.task_results)
        tool_executions = to_serializable(run_data.tool_executions)
        evidence_artifacts = to_serializable(run_data.evidence_artifacts)
        raw_extensions = run_data.facts.get("gui.extensions", [])
        extensions = [dict(item) for item in raw_extensions if isinstance(item, dict)] if isinstance(raw_extensions, list) else []
        warnings = [str(item) for item in getattr(run_data, "warnings", [])]
        errors = [str(item) for item in getattr(run_data, "errors", [])]
        execution_issues = build_execution_issues(run_data)
        execution_issues_summary = summarize_execution_issues(run_data, execution_issues)
        completeness_status = str(execution_issues_summary.get("completeness_status") or "healthy")
        target_input = run_data.metadata.target_input
        profile_name = run_data.metadata.profile

    if started_at is None:
        started_at = parse_datetime(gui_session.get("started_at")) or datetime.now(timezone.utc)
    if ended_at is None and state in {"completed", "failed", "cancelled"}:
        ended_at = parse_datetime(summary.get("ended_at"))

    now = datetime.now(timezone.utc)
    elapsed_seconds = max(((ended_at or now) - started_at).total_seconds(), 0.0)
    eta_seconds = _estimate_eta(elapsed_seconds, completed_tasks, total_tasks, state)

    if tasks:
        running_task_rows = [item for item in tasks if str(item.get("status")) == "running"]
        if running_task_rows:
            current_task = str(running_task_rows[0].get("label") or running_task_rows[0].get("key") or current_task)
    elif current_task == "Idle":
        visible_manifest = [
            item for item in manifest if str(item.get("task_key") or "") not in RUNTIME_CHECKPOINT_KEYS
        ]
        if visible_manifest:
            current_task = str(visible_manifest[-1].get("task_key") or current_task)

    findings.sort(key=lambda item: (str(item.get("severity", "info")), str(item.get("title", ""))))
    assets.sort(key=lambda item: (str(item.get("kind", "")), str(item.get("name", ""))))
    services.sort(key=lambda item: (str(item.get("asset_id", "")), int(item.get("port", 0))))
    web_apps.sort(key=lambda item: str(item.get("url", "")))
    technologies.sort(key=lambda item: (str(item.get("name", "")), str(item.get("version", ""))))
    evidence.sort(key=lambda item: (str(item.get("source_tool", "")), str(item.get("kind", ""))))
    screenshots.sort(key=lambda item: str(item.get("path", "")))
    task_results.sort(key=_result_sort_key)
    tool_executions.sort(key=lambda item: (str(item.get("tool_name", "")), str(item.get("started_at", ""))))
    evidence_artifacts.sort(key=lambda item: (str(item.get("source_tool", "")), str(item.get("path", ""))))
    if not tasks:
        tasks = _synthesize_task_rows(manifest, task_results, tool_executions)
    if current_task == "Idle" and tasks:
        running_task_rows = [item for item in tasks if str(item.get("status") or "") in ACTIVE_TASK_STATUSES]
        selected_task = running_task_rows[0] if running_task_rows else sorted(tasks, key=_task_sort_key)[-1]
        current_task = str(selected_task.get("label") or selected_task.get("key") or current_task)

    return RunSnapshot(
        run_id=run_id,
        scan_name=scan_name,
        run_dir=str(run_dir),
        state=state,
        elapsed_seconds=round(elapsed_seconds, 1),
        eta_seconds=eta_seconds,
        current_task=current_task,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        target_input=target_input,
        profile_name=profile_name,
        tasks=tasks,
        assets=assets,
        web_apps=web_apps,
        technologies=technologies,
        site_map=site_map,
        endpoints=endpoints,
        parameters=parameters,
        forms=forms,
        login_surfaces=login_surfaces,
        replay_requests=replay_requests,
        surface_signals=surface_signals,
        attack_paths=attack_paths,
        investigation_steps=investigation_steps,
        playbook_executions=playbook_executions,
        coverage_decisions=coverage_decisions,
        validation_results=validation_results,
        hypotheses=hypotheses,
        validation_tasks=validation_tasks,
        coverage_gaps=coverage_gaps,
        evidence=evidence,
        artifacts=artifacts,
        screenshots=screenshots,
        services=services,
        findings=findings,
        task_results=task_results,
        tool_executions=tool_executions,
        evidence_artifacts=evidence_artifacts,
        extensions=extensions,
        warnings=warnings,
        errors=errors,
        execution_issues=execution_issues,
        execution_issues_summary=execution_issues_summary,
        completeness_status=completeness_status,
    )
