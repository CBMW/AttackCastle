from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from rich.console import Console

from attackcastle import __version__
from attackcastle.analysis import build_evidence_bundles, build_priority_leads, refresh_autonomy_state
from attackcastle.adapters import (
    ActiveValidationAdapter,
    CVEEnricherAdapter,
    DNSAdapter,
    FrameworkChecksAdapter,
    NucleiAdapter,
    NiktoAdapter,
    NmapAdapter,
    ServiceExposureAdapter,
    SQLMapAdapter,
    SubdomainEnumAdapter,
    SurfaceIntelAdapter,
    TLSAdapter,
    RequestCaptureAdapter,
    VHostDiscoveryAdapter,
    WebDiscoveryAdapter,
    WebProbeAdapter,
    WPScanAdapter,
    WhatWebAdapter,
)
from attackcastle.config_loader import load_config
from attackcastle.core.enums import RunState, TaskStatus
from attackcastle.core.errors import ValidationError
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.lifecycle import transition_run_state
from attackcastle.core.models import (
    Asset,
    RunData,
    RunMetadata,
    SCHEMA_VERSION,
    iso,
    now_utc,
    parse_datetime,
    run_data_from_dict,
    to_serializable,
)
from attackcastle.core.migrations import migrate_payload
from attackcastle.findings.engine import FindingsEngine
from attackcastle.findings.normalizer import build_vulnerability_records
from attackcastle.logging import AuditLogger, configure_logger
from attackcastle.normalization.identity_graph import build_identity_graph
from attackcastle.orchestration import (
    AdaptiveExecutionController,
    AdaptiveRateLimiter,
    WorkflowScheduler,
    build_task_plan,
)
from attackcastle.orchestration.instance_graph import build_task_instance_graph
from attackcastle.policy import PolicyEngine, resolve_risk_mode
from attackcastle.proxy import normalize_proxy_url
from attackcastle.reporting.audience import normalize_report_audience
from attackcastle.reporting.builder import ReportBuilder
from attackcastle.quality.evidence import summarize_evidence_quality
from attackcastle.security import apply_secret_resolution
from attackcastle.scope.compiler import compile_scope
from attackcastle.scope.filters import apply_allow_deny
from attackcastle.scope.parser import parse_target_input
from attackcastle.scope.validators import ensure_output_directory, validate_scope_limits, validate_targets
from attackcastle.storage.run_store import RunStore


@dataclass
class ScanOptions:
    target_input: str
    output_directory: str
    profile: str = "prototype"
    forced_target_type: str | None = None
    user_config_path: str | None = None
    verbose: bool = False
    verbosity: int = 0
    dry_run: bool = False
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    max_hosts: int | None = None
    max_ports: int | None = None
    json_only: bool = False
    html_only: bool = False
    no_report: bool = False
    redact: bool = False
    events_jsonl: str | None = None
    audience: str = "consultant"
    resume_run_dir: str | None = None
    keep_raw_artifacts: bool | None = None
    rich_ui: bool | None = None
    emit_plain_logs: bool = True
    risk_mode: str | None = None
    asn_expansion_override: bool | None = None
    proxy_url: str | None = None
    disable_proxy: bool = False


@dataclass
class ScanOutcome:
    run_id: str
    run_dir: Path
    json_path: Path | None
    report_path: Path | None
    warning_count: int
    error_count: int
    finding_count: int
    plan_path: Path | None = None
    csv_paths: list[Path] = field(default_factory=list)
    integration_paths: list[Path] = field(default_factory=list)
    summary_path: Path | None = None
    pdf_path: Path | None = None
    manifest_path: Path | None = None
    metrics_path: Path | None = None
    timeline_path: Path | None = None
    drift_path: Path | None = None
    identity_graph_path: Path | None = None
    task_instance_graph_path: Path | None = None
    scope_graph_path: Path | None = None
    dry_run: bool = False
    state: str = "completed"
    duration_seconds: float = 0.0


def _build_run_id() -> str:
    return f"{now_utc().strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"


def _seed_scope_assets(run_data: RunData) -> None:
    if run_data.assets:
        return
    for target in run_data.scope:
        run_data.assets.append(
            Asset(
                asset_id=target.target_id,
                kind="scope_target",
                name=target.value,
                ip=target.host if target.host and "." in target.host else None,
                source_tool="scope_parser",
                canonical_key=target.value,
            )
        )


def _apply_redaction(run_data: RunData) -> RunData:
    redacted = copy.deepcopy(run_data)
    patterns = [
        (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "[redacted-ip]"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[redacted-email]"),
        (re.compile(r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|io|dev|local|internal)\b"), "[redacted-host]"),
    ]
    for evidence in redacted.evidence:
        snippet = evidence.snippet
        for pattern, replacement in patterns:
            snippet = pattern.sub(replacement, snippet)
        evidence.snippet = snippet
    return redacted


def _build_run_metrics(run_data: RunData) -> dict[str, Any]:
    task_states = run_data.task_states or []
    status_counts: dict[str, int] = {}
    retries_total = 0
    stage_durations: dict[str, float] = {}
    capability_durations: dict[str, float] = {}

    for task in task_states:
        status = str(task.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        detail = task.get("detail", {}) if isinstance(task.get("detail"), dict) else {}
        attempt = int(detail.get("attempt", 1) or 1)
        retries_total += max(0, attempt - 1)

        started = parse_datetime(task.get("started_at"))
        ended = parse_datetime(task.get("ended_at"))
        if started and ended:
            duration = max((ended - started).total_seconds(), 0.0)
            stage = str(detail.get("stage", "unknown"))
            capability = str(detail.get("capability", "unknown"))
            stage_durations[stage] = stage_durations.get(stage, 0.0) + duration
            capability_durations[capability] = capability_durations.get(capability, 0.0) + duration

    started_at = run_data.metadata.started_at
    ended_at = run_data.metadata.ended_at or now_utc()
    duration_seconds = max((ended_at - started_at).total_seconds(), 0.0)

    return {
        "run_id": run_data.metadata.run_id,
        "state": run_data.metadata.state.value
        if hasattr(run_data.metadata.state, "value")
        else str(run_data.metadata.state),
        "duration_seconds": duration_seconds,
        "task_count": len(task_states),
        "status_counts": status_counts,
        "retries_total": retries_total,
        "stage_durations_seconds": stage_durations,
        "capability_durations_seconds": capability_durations,
    }


def _build_run_timeline(run_store: RunStore) -> list[dict[str, Any]]:
    audit_path = run_store.logs_dir / "audit.jsonl"
    if not audit_path.exists():
        return []
    timeline: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
            if isinstance(event, dict):
                timeline.append(event)
        except Exception:
            continue
    return timeline


def _load_previous_run_data(run_store: RunStore) -> RunData | None:
    siblings = sorted(
        [path for path in run_store.output_root.glob("run_*") if path.is_dir()],
        key=lambda item: item.stat().st_mtime,
    )
    for candidate in reversed(siblings):
        if candidate.resolve() == run_store.run_dir.resolve():
            continue
        scan_path = candidate / "data" / "scan_data.json"
        if not scan_path.exists():
            continue
        try:
            payload = json.loads(scan_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        return run_data_from_dict(migrate_payload(payload))
    return None


def _finding_key(finding: Any) -> str:
    affected = ",".join(
        sorted(
            f"{item.get('entity_type')}:{item.get('entity_id')}"
            for item in getattr(finding, "affected_entities", [])
        )
    )
    return f"{getattr(finding, 'template_id', '')}|{affected}"


def _service_key(service: Any) -> str:
    return f"{service.asset_id}|{service.port}|{service.protocol}|{service.state}|{service.name or ''}"


def _web_key(web_app: Any) -> str:
    return f"{web_app.asset_id}|{web_app.service_id or ''}|{web_app.url}"


def _tech_key(technology: Any) -> str:
    return f"{technology.asset_id}|{technology.webapp_id or ''}|{technology.name}|{technology.version or ''}"


def _tech_family_key(technology: Any) -> str:
    return f"{technology.asset_id}|{technology.webapp_id or ''}|{technology.name}"


def _lead_key(lead: Any) -> str:
    affected = ",".join(
        sorted(
            f"{item.get('entity_type')}:{item.get('entity_id')}"
            for item in getattr(lead, "affected_entities", [])
        )
    )
    return f"{getattr(lead, 'category', '')}|{getattr(lead, 'title', '')}|{affected}"


def _file_sha256(path_value: str | None) -> str | None:
    if not path_value:
        return None
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def _screenshot_signatures(run_data: RunData) -> dict[str, str]:
    signatures: dict[str, str] = {}
    for evidence in run_data.evidence:
        if evidence.kind != "web_screenshot":
            continue
        key = str(evidence.snippet or evidence.artifact_path or evidence.evidence_id)
        digest = _file_sha256(evidence.artifact_path)
        if digest:
            signatures[key] = digest
    return signatures


def _build_drift_alerts(run_store: RunStore, run_data: RunData) -> dict[str, Any]:
    previous = _load_previous_run_data(run_store)
    if previous is None:
        return {
            "available": False,
            "baseline_run_id": None,
            "latest_run_id": run_data.metadata.run_id,
            "alerts": [],
            "changes": {},
        }

    current_findings = {
        _finding_key(item)
        for item in run_data.findings
        if item.status == "confirmed" and not item.suppressed
    }
    previous_findings = {
        _finding_key(item)
        for item in previous.findings
        if item.status == "confirmed" and not item.suppressed
    }
    current_services = {_service_key(item) for item in run_data.services}
    previous_services = {_service_key(item) for item in previous.services}
    current_web = {_web_key(item) for item in run_data.web_apps}
    previous_web = {_web_key(item) for item in previous.web_apps}
    current_tech = {_tech_key(item) for item in run_data.technologies}
    previous_tech = {_tech_key(item) for item in previous.technologies}
    current_tech_versions = {_tech_family_key(item): item.version or "" for item in run_data.technologies}
    previous_tech_versions = {_tech_family_key(item): item.version or "" for item in previous.technologies}
    current_screenshots = _screenshot_signatures(run_data)
    previous_screenshots = _screenshot_signatures(previous)
    current_high_priority_leads = {
        _lead_key(item) for item in getattr(run_data, "leads", []) if item.priority_label in {"very-high", "high"}
    }
    previous_high_priority_leads = {
        _lead_key(item) for item in getattr(previous, "leads", []) if item.priority_label in {"very-high", "high"}
    }

    changes = {
        "new_findings": sorted(current_findings - previous_findings),
        "resolved_findings": sorted(previous_findings - current_findings),
        "new_services": sorted(current_services - previous_services),
        "resolved_services": sorted(previous_services - current_services),
        "new_web_apps": sorted(current_web - previous_web),
        "resolved_web_apps": sorted(previous_web - current_web),
        "new_technologies": sorted(current_tech - previous_tech),
        "resolved_technologies": sorted(previous_tech - current_tech),
        "changed_versions": sorted(
            [
                {
                    "technology": key,
                    "previous_version": previous_tech_versions[key],
                    "current_version": current_tech_versions[key],
                }
                for key in sorted(set(current_tech_versions) & set(previous_tech_versions))
                if current_tech_versions[key] != previous_tech_versions[key]
            ],
            key=lambda item: str(item["technology"]),
        ),
        "new_high_priority_leads": sorted(current_high_priority_leads - previous_high_priority_leads),
        "resolved_high_priority_leads": sorted(previous_high_priority_leads - current_high_priority_leads),
        "new_screenshots": sorted(set(current_screenshots) - set(previous_screenshots)),
        "resolved_screenshots": sorted(set(previous_screenshots) - set(current_screenshots)),
        "changed_screenshots": sorted(
            [
                key
                for key in sorted(set(current_screenshots) & set(previous_screenshots))
                if current_screenshots[key] != previous_screenshots[key]
            ]
        ),
    }
    alerts: list[dict[str, Any]] = []
    if changes["new_findings"]:
        alerts.append(
            {
                "severity": "high",
                "title": "New confirmed findings detected",
                "count": len(changes["new_findings"]),
                "recommendation": "Review and prioritize remediation for newly introduced risk.",
            }
        )
    if changes["new_services"]:
        alerts.append(
            {
                "severity": "medium",
                "title": "New exposed services detected",
                "count": len(changes["new_services"]),
                "recommendation": "Validate expected exposure and close unnecessary ports.",
            }
        )
    if changes["new_high_priority_leads"]:
        alerts.append(
            {
                "severity": "high",
                "title": "New high-priority testing leads detected",
                "count": len(changes["new_high_priority_leads"]),
                "recommendation": "Review newly risky surfaces first during retest or recurring assessment workflows.",
            }
        )
    if changes["resolved_findings"]:
        alerts.append(
            {
                "severity": "info",
                "title": "Resolved findings observed",
                "count": len(changes["resolved_findings"]),
                "recommendation": "Confirm remediation controls remain stable.",
            }
        )
    if changes["changed_versions"]:
        alerts.append(
            {
                "severity": "medium",
                "title": "Technology version changes observed",
                "count": len(changes["changed_versions"]),
                "recommendation": "Review whether version drift introduced or removed risk on externally exposed assets.",
            }
        )
    if changes["changed_screenshots"]:
        alerts.append(
            {
                "severity": "medium",
                "title": "Screenshot-visible surface changes detected",
                "count": len(changes["changed_screenshots"]),
                "recommendation": "Review changed screenshots for login, admin, default page, and content changes between runs.",
            }
        )
    return {
        "available": True,
        "baseline_run_id": previous.metadata.run_id,
        "latest_run_id": run_data.metadata.run_id,
        "alerts": alerts,
        "changes": changes,
    }


def _load_or_create_run_data(
    options: ScanOptions,
    run_store: RunStore,
    targets: list,
) -> tuple[RunData, set[str]]:
    completed_checkpoints: set[str] = set()
    if options.resume_run_dir:
        checkpoint = run_store.load_latest_checkpoint()
        if checkpoint and isinstance(checkpoint.get("run_data"), dict):
            run_data = run_data_from_dict(migrate_payload(checkpoint["run_data"]))
            completed_checkpoints = run_store.list_completed_checkpoints()
            return run_data, completed_checkpoints
        scan_data_path = run_store.data_dir / "scan_data.json"
        if scan_data_path.exists():
            payload = json.loads(scan_data_path.read_text(encoding="utf-8"))
            run_data = run_data_from_dict(migrate_payload(payload))
            return run_data, set()

    metadata = RunMetadata(
        run_id=run_store.run_id,
        target_input=options.target_input,
        profile=options.profile,
        output_dir=str(run_store.run_dir),
        started_at=now_utc(),
        tool_version=__version__,
        schema_version=SCHEMA_VERSION,
        audience=options.audience,
    )
    run_data = RunData(metadata=metadata, scope=targets)
    _seed_scope_assets(run_data)
    run_data.facts["target_types"] = sorted({target.target_type.value for target in targets})
    return run_data, completed_checkpoints


def build_scan_plan(options: ScanOptions, console: Console | None = None) -> tuple[dict[str, Any], RunStore]:
    console = console or Console()
    options.audience = normalize_report_audience(options.audience)
    loaded_config = load_config(profile=options.profile, user_config_path=options.user_config_path)
    config, secret_resolver = apply_secret_resolution(loaded_config)
    proxy_config = config.get("proxy")
    if not isinstance(proxy_config, dict):
        proxy_config = {}
        config["proxy"] = proxy_config
    configured_proxy = proxy_config.get("url") if isinstance(proxy_config, dict) else ""
    try:
        effective_proxy = None if options.disable_proxy else normalize_proxy_url(options.proxy_url or configured_proxy)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    proxy_config["url"] = effective_proxy or ""
    if options.asn_expansion_override is not None:
        config.setdefault("scope", {})["enable_asn_expansion"] = bool(options.asn_expansion_override)
    risk_mode, risk_mode_controls = resolve_risk_mode(
        profile_name=options.profile,
        config=config,
        requested_mode=options.risk_mode,
    )
    config.setdefault("scan", {})["risk_mode"] = risk_mode
    config["risk_mode_controls"] = risk_mode_controls
    policy_engine = PolicyEngine.from_config(profile_name=options.profile, config=config)
    targets = parse_target_input(options.target_input, forced_type=options.forced_target_type)
    targets = apply_allow_deny(targets, options.allow, options.deny)
    compilation = compile_scope(targets, config)
    targets = compilation.targets
    configured_scan = config.get("scan", {})
    allow_private_scope = bool(configured_scan.get("allow_private_scope", False))
    validate_targets(targets, allow_private_scope=allow_private_scope)
    max_hosts = options.max_hosts if options.max_hosts is not None else configured_scan.get("max_hosts")
    hard_max_hosts = configured_scan.get("hard_max_hosts")
    if max_hosts is not None and hard_max_hosts is not None and int(max_hosts) > int(hard_max_hosts):
        raise ValidationError(
            f"Requested max hosts {max_hosts} exceeds hard safety ceiling {hard_max_hosts}."
        )
    validate_scope_limits(targets, max_hosts=max_hosts)

    output_root = ensure_output_directory(options.output_directory)
    run_id = _build_run_id() if not options.resume_run_dir else Path(options.resume_run_dir).name.replace("run_", "", 1)
    run_store = RunStore.from_existing(Path(options.resume_run_dir)) if options.resume_run_dir else RunStore(output_root=output_root, run_id=run_id)

    resolved_verbosity = max(int(options.verbosity or 0), 1 if options.verbose else 0)
    logger = configure_logger(
        run_store.log_path("run.log"),
        verbosity=resolved_verbosity,
        secret_resolver=secret_resolver,
    )
    events_mirror = Path(options.events_jsonl).expanduser().resolve() if options.events_jsonl else None
    audit = AuditLogger(run_store.log_path("audit.jsonl"), mirror_event_file=events_mirror)
    profile_config = config.get("profile", {})

    effective_max_ports = options.max_ports if options.max_ports is not None else configured_scan.get("max_ports")
    hard_max_ports = configured_scan.get("hard_max_ports")
    if (
        effective_max_ports is not None
        and hard_max_ports is not None
        and int(effective_max_ports) > int(hard_max_ports)
    ):
        raise ValidationError(
            f"Requested max ports {effective_max_ports} exceeds hard safety ceiling {hard_max_ports}."
        )
    if effective_max_ports:
        nmap_args = config.setdefault("nmap", {}).setdefault("args", [])
        top_ports_flag = ["--top-ports", str(effective_max_ports)]
        if not any(arg == "--top-ports" for arg in nmap_args):
            nmap_args.extend(top_ports_flag)

    run_data, _ = _load_or_create_run_data(options, run_store, targets)
    run_data.facts["scope.target_graph"] = compilation.graph
    run_data.facts["scope.compiler.summary"] = compilation.graph.get("summary", {})
    run_data.facts["scope.cloud_hosts"] = compilation.graph.get("cloud_hosts", [])
    run_data.facts["scan.risk_mode"] = risk_mode
    run_data.facts["scan.risk_mode_controls"] = risk_mode_controls
    if compilation.warnings:
        run_data.warnings.extend(compilation.warnings)
    rate_limiter = AdaptiveRateLimiter(
        config=config.get("rate_limit", {}) if isinstance(config.get("rate_limit"), dict) else {}
    )
    execution_controller = AdaptiveExecutionController(
        config=config.get("adaptive_execution", {})
        if isinstance(config.get("adaptive_execution"), dict)
        else {},
        profile_config=profile_config if isinstance(profile_config, dict) else {},
    )
    context = AdapterContext(
        profile_name=options.profile,
        config=config,
        profile_config=profile_config,
        run_store=run_store,
        logger=logger,
        audit=audit,
        policy_engine=policy_engine,
        secret_resolver=secret_resolver,
        rate_limiter=rate_limiter,
        execution_controller=execution_controller,
    )
    adapters: dict[str, Any] = {
        "subdomain_enum": SubdomainEnumAdapter(),
        "dns": DNSAdapter(),
        "nmap": NmapAdapter(),
        "web_probe": WebProbeAdapter(),
        "vhost_discovery": VHostDiscoveryAdapter(),
        "web_discovery": WebDiscoveryAdapter(),
        "request_capture": RequestCaptureAdapter(),
        "surface_intel": SurfaceIntelAdapter(),
        "tls": TLSAdapter(),
        "service_exposure": ServiceExposureAdapter(),
        "whatweb": WhatWebAdapter(),
        "nikto": NiktoAdapter(),
        "nuclei": NucleiAdapter(),
        "active_validation": ActiveValidationAdapter(),
        "framework_checks": FrameworkChecksAdapter(),
        "wpscan": WPScanAdapter(),
        "sqlmap": SQLMapAdapter(),
        "cve_enricher": CVEEnricherAdapter(),
    }

    findings_engine = FindingsEngine(
        template_dir=Path(__file__).resolve().parent / "findings" / "templates",
        minimum_confidence=config.get("findings", {}).get("minimum_confidence", 0.6),
        severity_overlays=config.get("findings", {})
        .get("severity_overlays", {})
        .get(config.get("findings", {}).get("severity_policy", "default"), {}),
        suppression_file=(
            Path(config.get("findings", {}).get("suppression_file")).expanduser().resolve()
            if config.get("findings", {}).get("suppression_file")
            else None
        ),
        minimum_evidence_completeness=config.get("findings", {}).get(
            "minimum_evidence_completeness", 0.8
        ),
        enforce_evidence_for_severities=config.get("findings", {}).get(
            "enforce_evidence_for_severities",
            ["low", "medium", "high", "critical"],
        ),
    )
    report_builder = ReportBuilder()

    def findings_runner(inner_context: AdapterContext, inner_run_data: RunData):
        generated = findings_engine.generate(inner_run_data)
        inner_run_data.facts["findings.generated"] = len(generated)
        inner_context.audit.write("findings.generated", {"count": len(generated)})
        return None

    def report_runner(inner_context: AdapterContext, inner_run_data: RunData):
        # Report generation is handled in run_scan finalization for output-mode flexibility.
        inner_context.audit.write("report.queued", {"run_id": inner_run_data.metadata.run_id})
        return None

    plan_result = build_task_plan(
        adapters=adapters,
        findings_runner=findings_runner,
        report_runner=report_runner,
        run_data=run_data,
        profile_name=options.profile,
        config=config,
        preview_context=context,
    )
    run_data.facts["plan.decision_items"] = to_serializable(plan_result.items)

    # Output mode gating.
    if options.no_report or options.json_only:
        plan_result.tasks = [task for task in plan_result.tasks if task.key != "build-report"]
        for item in plan_result.items:
            if item.key == "build-report":
                item.selected = False
                item.reason = "disabled by output mode"
    if options.html_only:
        pass

    plan_payload = {
        "run_id": run_store.run_id,
        "profile": options.profile,
        "config_sources": config.get("config_sources", {}),
        "scope_compiler": compilation.graph.get("summary", {}),
        "risk_mode": risk_mode,
        "risk_mode_controls": risk_mode_controls,
        "items": to_serializable(plan_result.items),
        "conflicts": plan_result.conflicts,
        "max_noise_limit": config.get("profile", {}).get("max_noise_score", config.get("policy", {}).get("max_noise_score")),
        "mode": {
            "json_only": options.json_only,
            "html_only": options.html_only,
            "no_report": options.no_report,
            "redact": options.redact,
        },
        "safety": {
            "max_hosts": max_hosts,
            "hard_max_hosts": hard_max_hosts,
            "max_ports": effective_max_ports,
            "hard_max_ports": hard_max_ports,
        },
        "policy": {
            "policy_file": config.get("policy", {}).get("policy_file"),
            "max_services_discovered": config.get("policy", {}).get("max_services_discovered"),
            "max_errors_before_pause": config.get("policy", {}).get("max_errors_before_pause"),
            "rule_count": len(config.get("policy", {}).get("rules", []))
            if isinstance(config.get("policy", {}).get("rules"), list)
            else 0,
        },
        "distributed": {
            "enabled": bool(config.get("distributed", {}).get("enabled", False)),
            "worker_mode": str(config.get("distributed", {}).get("mode", "standalone")),
        },
        "rate_limit": config.get("rate_limit", {}),
        "adaptive_execution": execution_controller.snapshot(),
    }
    return {
        "config": config,
        "context": context,
        "run_data": run_data,
        "plan_result": plan_result,
        "plan_payload": plan_payload,
        "report_builder": report_builder,
        "findings_engine": findings_engine,
        "adapters": adapters,
    }, run_store


def _execute_scan_plan(
    options: ScanOptions,
    plan_bundle: dict[str, Any],
    run_store: RunStore,
    console: Console,
) -> ScanOutcome:
    config = plan_bundle["config"]
    context = plan_bundle["context"]
    run_data: RunData = plan_bundle["run_data"]
    plan_result = plan_bundle["plan_result"]
    plan_payload = plan_bundle["plan_payload"]
    report_builder: ReportBuilder = plan_bundle["report_builder"]

    run_store.acquire_lock()
    report_result: dict[str, Any] | None = None
    json_path: Path | None = None
    report_path: Path | None = None
    manifest_path: Path | None = None
    summary_path: Path | None = None
    csv_paths: list[Path] = []
    integration_paths: list[Path] = []
    pdf_path: Path | None = None
    metrics_path: Path | None = None
    timeline_path: Path | None = None
    drift_path: Path | None = None
    identity_graph_path: Path | None = None
    task_instance_graph_path: Path | None = None

    try:
        plan_path = run_store.write_json("data/plan.json", plan_payload)
        transition_run_state(run_data, RunState.PLANNED, "plan_generated")
        if options.dry_run:
            run_data.metadata.ended_at = now_utc()
            transition_run_state(run_data, RunState.COMPLETED, "dry_run")
            run_store.write_json("data/run_summary.json", {"run_id": run_store.run_id, "dry_run": True})
            manifest_path = run_store.write_manifest(tool_version=__version__, schema_version=SCHEMA_VERSION)
            return ScanOutcome(
                run_id=run_store.run_id,
                run_dir=run_store.run_dir,
                json_path=None,
                report_path=None,
                warning_count=len(run_data.warnings),
                error_count=len(run_data.errors),
                finding_count=len([finding for finding in run_data.findings if finding.status == "confirmed"]),
                plan_path=plan_path,
                manifest_path=manifest_path,
                dry_run=True,
                state=run_data.metadata.state.value
                if hasattr(run_data.metadata.state, "value")
                else str(run_data.metadata.state),
                duration_seconds=max(
                    (run_data.metadata.ended_at - run_data.metadata.started_at).total_seconds(),
                    0.0,
                ),
            )

        transition_run_state(run_data, RunState.RUNNING, "workflow_started")
        logger = context.logger
        logger.info(
            "Starting scan run_id=%s profile=%s target=%s",
            run_store.run_id,
            options.profile,
            options.target_input,
        )

        completed_checkpoints = run_store.list_completed_checkpoints() if options.resume_run_dir else set()
        scheduler = WorkflowScheduler(
            console=console,
            use_rich_progress=(
                options.rich_ui if options.rich_ui is not None else bool(getattr(console, "is_terminal", False))
            ),
            emit_plain_logs=options.emit_plain_logs,
        )
        task_states = scheduler.execute(
            tasks=plan_result.tasks,
            context=context,
            run_data=run_data,
            completed_task_keys=completed_checkpoints,
        )
        run_data.task_states = to_serializable(task_states)
        refresh_autonomy_state(run_data, config)
        run_data.metadata.ended_at = now_utc()

        statuses = {item.status for item in task_states}
        if TaskStatus.CANCELLED.value in statuses:
            transition_run_state(run_data, RunState.CANCELLED, "cancelled")
        elif any(status in {TaskStatus.FAILED.value, TaskStatus.BLOCKED.value} for status in statuses):
            transition_run_state(run_data, RunState.FAILED, "task_failure_or_block")
        else:
            transition_run_state(run_data, RunState.COMPLETED, "workflow_complete")

        output_run_data = _apply_redaction(run_data) if options.redact else run_data
        if getattr(context, "rate_limiter", None) is not None:
            output_run_data.facts["rate_limit.telemetry"] = context.rate_limiter.snapshot()
        if getattr(context, "execution_controller", None) is not None:
            adaptive_snapshot = context.execution_controller.snapshot()
            output_run_data.facts["adaptive_execution.startup_budget"] = adaptive_snapshot.get("startup_budget")
            output_run_data.facts["adaptive_execution.timeline"] = adaptive_snapshot.get("timeline", [])
            output_run_data.facts["adaptive_execution.current_state"] = adaptive_snapshot.get("current_state", {})
            output_run_data.facts["adaptive_execution.downgrade_reasons"] = adaptive_snapshot.get(
                "downgrade_reasons",
                [],
            )
        output_run_data.facts["evidence.quality"] = summarize_evidence_quality(output_run_data.evidence)
        output_run_data.facts["vulnerability_records"] = build_vulnerability_records(output_run_data)
        output_run_data.leads = build_priority_leads(output_run_data)
        output_run_data.evidence_bundles = build_evidence_bundles(output_run_data)
        refresh_autonomy_state(output_run_data, config)
        output_run_data.facts["lead.count"] = len(output_run_data.leads)
        output_run_data.facts["lead.high_priority_count"] = len(
            [item for item in output_run_data.leads if item.priority_label in {"very-high", "high"}]
        )
        output_run_data.facts["evidence_bundle.count"] = len(output_run_data.evidence_bundles)
        output_run_data.facts["hypothesis.count"] = len(output_run_data.hypotheses)
        output_run_data.facts["validation_queue.count"] = len(output_run_data.validation_tasks)
        identity_graph = build_identity_graph(output_run_data)
        task_instance_graph = build_task_instance_graph(output_run_data)
        drift_alerts = _build_drift_alerts(run_store, output_run_data)
        output_run_data.facts["identity_graph.summary"] = identity_graph.get("summary", {})
        output_run_data.facts["task_instance_graph.summary"] = task_instance_graph.get("summary", {})
        output_run_data.facts["drift.available"] = bool(drift_alerts.get("available"))
        output_run_data.facts["drift.alert_count"] = len(drift_alerts.get("alerts", []))
        output_run_data.facts["drift.alerts"] = drift_alerts.get("alerts", [])
        output_run_data.facts["drift.changes"] = drift_alerts.get("changes", {})

        identity_graph_path = run_store.write_json("data/asset_identity_graph.json", identity_graph)
        task_instance_graph_path = run_store.write_json("data/task_instance_graph.json", task_instance_graph)
        drift_path = run_store.write_json("data/drift_alerts.json", drift_alerts)
        scope_graph_path: Path | None = None
        scope_graph_payload = output_run_data.facts.get("scope.target_graph", {})
        if isinstance(scope_graph_payload, dict):
            scope_graph_path = run_store.write_json("data/scope_target_graph.json", scope_graph_payload)
        for processor in getattr(context, "post_run_processors", []):
            processor(context, output_run_data, run_store)
        if not options.html_only:
            json_path = run_store.write_json("data/scan_data.json", output_run_data)

        if not options.no_report and not options.json_only:
            report_result = report_builder.build(
                output_run_data,
                run_store,
                audience=options.audience,
                export_csv=config.get("report", {}).get("exports", {}).get("csv", True),
                export_json_summary=config.get("report", {}).get("exports", {}).get("json_summary", True),
                export_pdf=config.get("report", {}).get("exports", {}).get("pdf", False),
                export_integrations=config.get("integrations", {}).get("export_bundle", True),
            )
            report_path = report_result["report_path"]
            csv_paths = report_result.get("csv_paths", [])
            summary_path = report_result.get("summary_path")
            pdf_path = report_result.get("pdf_path")
            integration_paths = report_result.get("integration_paths", [])

        run_store.write_json(
            "data/run_summary.json",
            {
                "run_id": run_store.run_id,
                "started_at": iso(run_data.metadata.started_at),
                "ended_at": iso(run_data.metadata.ended_at),
                "state": run_data.metadata.state.value
                if hasattr(run_data.metadata.state, "value")
                else str(run_data.metadata.state),
                "warning_count": len(run_data.warnings),
                "error_count": len(run_data.errors),
                "finding_count": len(
                    [
                        finding
                        for finding in run_data.findings
                        if finding.status == "confirmed" and not finding.suppressed
                    ]
                ),
                "json_path": str(json_path) if json_path else None,
                "report_path": str(report_path) if report_path else None,
                "integration_paths": [str(path) for path in integration_paths],
                "plan_path": str(plan_path),
                "metrics_path": str(run_store.run_dir / "data" / "run_metrics.json"),
                "timeline_path": str(run_store.run_dir / "data" / "run_timeline.json"),
                "drift_path": str(drift_path) if drift_path else None,
                "identity_graph_path": str(identity_graph_path) if identity_graph_path else None,
                "task_instance_graph_path": str(task_instance_graph_path)
                if task_instance_graph_path
                else None,
                "scope_graph_path": str(scope_graph_path) if scope_graph_path else None,
            },
        )
        metrics_path = run_store.write_json("data/run_metrics.json", _build_run_metrics(run_data))
        timeline_path = run_store.write_json("data/run_timeline.json", _build_run_timeline(run_store))

        effective_keep_raw = (
            options.keep_raw_artifacts
            if options.keep_raw_artifacts is not None
            else bool(config.get("retention", {}).get("keep_raw_artifacts", True))
        )
        run_store.apply_retention(keep_raw_artifacts=effective_keep_raw)
        manifest_path = run_store.write_manifest(tool_version=__version__, schema_version=SCHEMA_VERSION)

        logger.info(
            "Completed scan run_id=%s findings=%s candidates=%s warnings=%s errors=%s state=%s",
            run_store.run_id,
            len(
                [
                    finding
                    for finding in run_data.findings
                    if finding.status == "confirmed" and not finding.suppressed
                ]
            ),
            len([finding for finding in run_data.findings if finding.status == "candidate"]),
            len(run_data.warnings),
            len(run_data.errors),
            run_data.metadata.state.value if hasattr(run_data.metadata.state, "value") else run_data.metadata.state,
        )
        return ScanOutcome(
            run_id=run_store.run_id,
            run_dir=run_store.run_dir,
            json_path=json_path,
            report_path=report_path,
            warning_count=len(run_data.warnings),
            error_count=len(run_data.errors),
            finding_count=len(
                [
                    finding
                    for finding in run_data.findings
                    if finding.status == "confirmed" and not finding.suppressed
                ]
            ),
            plan_path=plan_path,
            csv_paths=csv_paths,
            integration_paths=integration_paths,
            summary_path=summary_path,
            pdf_path=pdf_path,
            manifest_path=manifest_path,
            metrics_path=metrics_path,
            timeline_path=timeline_path,
            drift_path=drift_path,
            identity_graph_path=identity_graph_path,
            task_instance_graph_path=task_instance_graph_path,
            dry_run=False,
            state=run_data.metadata.state.value
            if hasattr(run_data.metadata.state, "value")
            else str(run_data.metadata.state),
            duration_seconds=max(
                ((run_data.metadata.ended_at or now_utc()) - run_data.metadata.started_at).total_seconds(),
                0.0,
            ),
        )
    finally:
        run_store.release_lock()


def run_scan(
    target_input: str,
    output_directory: str,
    profile: str = "prototype",
    forced_target_type: str | None = None,
    user_config_path: str | None = None,
    verbose: bool = False,
    verbosity: int = 0,
    console: Console | None = None,
    dry_run: bool = False,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    max_hosts: int | None = None,
    max_ports: int | None = None,
    json_only: bool = False,
    html_only: bool = False,
    no_report: bool = False,
    redact: bool = False,
    events_jsonl: str | None = None,
    audience: str = "consultant",
    resume_run_dir: str | None = None,
    keep_raw_artifacts: bool | None = None,
    rich_ui: bool | None = None,
    emit_plain_logs: bool = True,
    risk_mode: str | None = None,
    asn_expansion_override: bool | None = None,
    proxy_url: str | None = None,
    disable_proxy: bool = False,
) -> ScanOutcome:
    options = ScanOptions(
        target_input=target_input,
        output_directory=output_directory,
        profile=profile,
        forced_target_type=forced_target_type,
        user_config_path=user_config_path,
        verbose=verbose,
        verbosity=verbosity,
        dry_run=dry_run,
        allow=allow or [],
        deny=deny or [],
        max_hosts=max_hosts,
        max_ports=max_ports,
        json_only=json_only,
        html_only=html_only,
        no_report=no_report,
        redact=redact,
        events_jsonl=events_jsonl,
        audience=audience,
        resume_run_dir=resume_run_dir,
        keep_raw_artifacts=keep_raw_artifacts,
        rich_ui=rich_ui,
        emit_plain_logs=emit_plain_logs,
        risk_mode=risk_mode,
        asn_expansion_override=asn_expansion_override,
        proxy_url=proxy_url,
        disable_proxy=disable_proxy,
    )
    console = console or Console()

    plan_bundle, run_store = build_scan_plan(options, console=console)
    return _execute_scan_plan(options=options, plan_bundle=plan_bundle, run_store=run_store, console=console)
