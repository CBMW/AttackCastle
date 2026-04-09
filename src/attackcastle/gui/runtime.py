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
        "masscan": {
            "enabled": profile.enable_masscan,
            "rate": profile.masscan_rate,
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
    rows.sort(key=lambda item: (item["source_tool"], item["path"]))
    return rows


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
    tool_executions: list[dict[str, Any]] = []
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
        tool_executions = to_serializable(run_data.tool_executions)
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
    tool_executions.sort(key=lambda item: (str(item.get("tool_name", "")), str(item.get("started_at", ""))))

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
        tool_executions=tool_executions,
        extensions=extensions,
        warnings=warnings,
        errors=errors,
        execution_issues=execution_issues,
        execution_issues_summary=execution_issues_summary,
        completeness_status=completeness_status,
    )
