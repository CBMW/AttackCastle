from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.tree import Tree

from attackcastle.adapters import (
    CVEEnricherAdapter,
    DNSAdapter,
    FrameworkChecksAdapter,
    NucleiAdapter,
    NiktoAdapter,
    NmapAdapter,
    ServiceExposureAdapter,
    SQLMapAdapter,
    SubdomainEnumAdapter,
    TLSAdapter,
    WebDiscoveryAdapter,
    WebProbeAdapter,
    WPScanAdapter,
    WhatWebAdapter,
)
from attackcastle.app import ScanOptions, ScanOutcome, build_scan_plan, run_scan
from attackcastle.cli_ux import (
    UXConfig,
    build_console,
    render_banner,
    render_next_steps,
    render_operator_notice,
    render_safety_contract,
    render_task_graph,
)
from attackcastle.config_loader import explain_config_key, load_config, load_config_layers
from attackcastle.core.errors import ValidationError
from attackcastle.core.migrations import migrate_payload
from attackcastle.core.models import now_utc, run_data_from_dict
from attackcastle.findings.schema import lint_templates
from attackcastle.logging import verify_audit_chain
from attackcastle.orchestration import (
    build_shard_plan,
    claim_next_shard,
    complete_shard,
    initialize_worker_queue,
    queue_status,
)
from attackcastle.policy import resolve_risk_mode
from attackcastle.readiness import (
    EXTERNAL_DEPENDENCY_SPECS as READINESS_EXTERNAL_DEPENDENCY_SPECS,
    ReadinessReport,
    assess_readiness,
    capability_tool as readiness_capability_tool,
    dependency_install_support,
    external_dependency_rows as readiness_external_dependency_rows,
    missing_dependency_message as readiness_missing_dependency_message,
    missing_dependency_rows as readiness_missing_dependency_rows,
)
from attackcastle.reporting import ReportBuilder, build_trend_report
from attackcastle.security import redact_sensitive_config
from attackcastle.scope.filters import load_targets_from_scope_file
from attackcastle.scope.parser import parse_target_input, summarize_target_input
from attackcastle.scope.validators import validate_targets
from attackcastle.storage.run_store import RunStore

DOCS_URL = "https://github.com/attackcastle/attackcastle/blob/main/README.md"
OUTPUT_FORMATS = {"text", "json", "ndjson"}
UI_MODES = {"operator", "automation"}
UI_THEMES = {"professional", "contrast", "plain"}
UI_ROLES = {"operator", "manager", "qa"}
PROFILE_DIR = Path(__file__).resolve().parent / "config" / "profiles"
EXTERNAL_DEPENDENCY_SPECS = READINESS_EXTERNAL_DEPENDENCY_SPECS


class ExitCode(IntEnum):
    OK = 0
    INTERNAL_ERROR = 1
    VALIDATION_ERROR = 2
    PARTIAL_SUCCESS = 3
    DEPENDENCY_ERROR = 4
    CANCELLED = 130


app = typer.Typer(
    help="AttackCastle: adaptive external pentest visibility CLI for authorized assessments.",
    no_args_is_help=True,
)
run_app = typer.Typer(help="Run lifecycle operations.", no_args_is_help=True)
templates_app = typer.Typer(help="Template operations.", no_args_is_help=True)
adapters_app = typer.Typer(help="Adapter operations (legacy alias).", no_args_is_help=True)
plugins_app = typer.Typer(help="Plugin and adapter operations.", no_args_is_help=True)
report_app = typer.Typer(help="Reporting operations.", no_args_is_help=True)
config_app = typer.Typer(help="Configuration operations.", no_args_is_help=True)
validate_app = typer.Typer(help="Validation operations.", no_args_is_help=True)
completion_app = typer.Typer(help="Shell completion operations.", no_args_is_help=True)
artifacts_app = typer.Typer(help="Artifact browsing operations.", no_args_is_help=True)
findings_app = typer.Typer(help="Finding inspection operations.", no_args_is_help=True)
scope_app = typer.Typer(help="Scope intake and validation operations.", no_args_is_help=True)
profile_app = typer.Typer(help="Profile inspection and editing operations.", no_args_is_help=True)
evidence_app = typer.Typer(help="Evidence inspection operations.", no_args_is_help=True)

app.add_typer(run_app, name="run")
app.add_typer(templates_app, name="templates")
app.add_typer(adapters_app, name="adapters")
app.add_typer(plugins_app, name="plugins")
app.add_typer(report_app, name="report")
app.add_typer(config_app, name="config")
app.add_typer(validate_app, name="validate")
app.add_typer(completion_app, name="completion")
app.add_typer(artifacts_app, name="artifacts")
app.add_typer(findings_app, name="findings")
app.add_typer(scope_app, name="scope")
app.add_typer(profile_app, name="profile")
app.add_typer(evidence_app, name="evidence")


def _normalize_output_format(output_format: str) -> str:
    normalized = output_format.strip().lower()
    if normalized not in OUTPUT_FORMATS:
        raise typer.BadParameter(
            f"Invalid --output-format '{output_format}'. Choose one of: {', '.join(sorted(OUTPUT_FORMATS))}."
        )
    return normalized


def _normalize_choice(value: str, allowed: set[str], field_name: str) -> str:
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise typer.BadParameter(
            f"Invalid {field_name} '{value}'. Choose one of: {', '.join(sorted(allowed))}."
        )
    return normalized


def _profile_names() -> list[str]:
    if not PROFILE_DIR.exists():
        return []
    return sorted(path.stem for path in PROFILE_DIR.glob("*.yaml") if path.is_file())


def _profile_path(profile: str) -> Path:
    return PROFILE_DIR / f"{profile}.yaml"


def _looks_like_file_path(value: str) -> bool:
    candidate = Path(value).expanduser()
    return candidate.exists() and candidate.is_file()


def _read_target_source(source: str) -> str:
    if _looks_like_file_path(source):
        return load_targets_from_scope_file(source)
    return source


def _combine_target_sources(
    target: str | None,
    scope_file: str | None,
    targets: list[str] | None,
) -> list[str]:
    combined: list[str] = []
    if target:
        combined.append(target)
    if scope_file:
        combined.append(load_targets_from_scope_file(scope_file))
    for source in targets or []:
        combined.append(_read_target_source(source))
    return combined


def _ctx_ux(ctx: typer.Context | None) -> UXConfig:
    if ctx and isinstance(ctx.obj, UXConfig):
        return ctx.obj
    return UXConfig()


def _console(ctx: typer.Context | None, output_format: str) -> Console:
    config = _ctx_ux(ctx)
    return build_console(config, output_format=output_format)


def _emit_payload(console: Console, payload: dict[str, Any], output_format: str, event: str = "result") -> None:
    if output_format == "json":
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
        return
    if output_format == "ndjson":
        sys.stdout.write(json.dumps({"event": event, **payload}, sort_keys=True, separators=(",", ":")) + "\n")
        return


def _exit_with_error(
    console: Console,
    output_format: str,
    code: ExitCode,
    message: str,
    suggestion: str | None = None,
    detail: str | None = None,
) -> None:
    payload = {
        "status": "error",
        "code": int(code),
        "message": message,
        "suggestion": suggestion,
        "detail": detail,
        "docs": DOCS_URL,
    }
    if output_format == "text":
        console.print(f"[red]Error:[/red] {message}")
        if detail:
            console.print(f"Detail: {detail}")
        if suggestion:
            console.print(f"How to fix: {suggestion}")
        console.print(f"Docs: {DOCS_URL}")
    else:
        _emit_payload(console, payload, output_format, event="error")
    raise typer.Exit(code=int(code))


def _resolve_target_input(
    target: str | None,
    scope_file: str | None,
    targets: list[str] | None,
    interactive: bool,
    console: Console | None = None,
) -> str:
    chunks = _combine_target_sources(target=target, scope_file=scope_file, targets=targets)
    if chunks:
        return "\n".join(chunks)
    if not interactive:
        raise typer.BadParameter("Missing required target input. Use --target, --scope-file, or repeatable --targets.")
    return Prompt.ask("Target", console=console)


def _resolve_output_dir(output_dir: str | None, interactive: bool, console: Console | None = None) -> str:
    if output_dir:
        return output_dir
    if not interactive:
        raise typer.BadParameter("Missing required --output-dir in non-interactive mode.")
    return Prompt.ask("Output directory", default="./output", console=console)


def _guard_profile_risk(
    profile: str,
    max_ports: int | None,
    yes: bool,
    interactive: bool,
    console: Console,
) -> None:
    aggressive_profile = profile.lower() == "aggressive"
    high_port_budget = max_ports is not None and max_ports > 3000
    if not (aggressive_profile or high_port_budget):
        return
    if yes:
        return
    warning = "Selected settings can produce noisier scan behavior."
    if aggressive_profile and high_port_budget:
        warning = "Aggressive profile and high port budget selected; this can be noisy."
    elif aggressive_profile:
        warning = "Aggressive profile selected; this can be noisy."
    elif high_port_budget:
        warning = f"High port budget selected ({max_ports}); this can be noisy."

    if not interactive:
        raise typer.BadParameter(
            f"{warning} Re-run with --yes to explicitly confirm in non-interactive mode."
        )
    console.print(f"[yellow]{warning}[/yellow]")
    if not Confirm.ask("Proceed?", default=False):
        raise typer.Exit(code=int(ExitCode.VALIDATION_ERROR))


def _exit_code_for_outcome(outcome: ScanOutcome) -> ExitCode:
    state = str(outcome.state).lower()
    if state == "cancelled":
        return ExitCode.CANCELLED
    if state == "failed":
        if outcome.json_path or outcome.report_path:
            return ExitCode.PARTIAL_SUCCESS
        return ExitCode.INTERNAL_ERROR
    if outcome.error_count > 0:
        return ExitCode.PARTIAL_SUCCESS
    return ExitCode.OK


def _load_candidate_count(json_path: Path | None) -> int:
    if not json_path or not json_path.exists():
        return 0
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    return len([item for item in findings if item.get("status") == "candidate"])


def _render_scan_summary(
    console: Console,
    outcome: ScanOutcome,
    candidate_count: int,
    role: str = "operator",
) -> None:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_row("Run ID", str(outcome.run_id))
    table.add_row("State", str(outcome.state))
    table.add_row("Duration", f"{outcome.duration_seconds:.1f}s")
    table.add_row("Run Directory", str(outcome.run_dir))
    if outcome.plan_path and role in {"operator", "qa"}:
        table.add_row("Plan", str(outcome.plan_path))
    if outcome.json_path and role in {"operator", "qa"}:
        table.add_row("JSON", str(outcome.json_path))
    if outcome.report_path:
        table.add_row("HTML Report", str(outcome.report_path))
    if outcome.integration_paths and role in {"operator", "qa"}:
        table.add_row("Integrations", f"{len(outcome.integration_paths)} export file(s)")
    if outcome.summary_path and role in {"operator", "qa"}:
        table.add_row("Summary JSON", str(outcome.summary_path))
    if outcome.pdf_path:
        table.add_row("PDF", str(outcome.pdf_path))
    if outcome.metrics_path and role in {"operator", "qa"}:
        table.add_row("Run Metrics", str(outcome.metrics_path))
    if outcome.timeline_path and role in {"operator", "qa"}:
        table.add_row("Run Timeline", str(outcome.timeline_path))
    if outcome.drift_path and role in {"operator", "qa"}:
        table.add_row("Drift Alerts", str(outcome.drift_path))
    if outcome.identity_graph_path and role in {"operator", "qa"}:
        table.add_row("Identity Graph", str(outcome.identity_graph_path))
    if outcome.task_instance_graph_path and role in {"operator", "qa"}:
        table.add_row("Task Graph", str(outcome.task_instance_graph_path))
    table.add_row("Findings (confirmed)", str(outcome.finding_count))
    table.add_row("Findings (candidate)", str(candidate_count))
    table.add_row("Warnings", str(outcome.warning_count))
    table.add_row("Errors", str(outcome.error_count))
    console.print(Panel.fit(table, title="Scan Summary", border_style="cyan"))
    if str(outcome.state).lower() == "cancelled":
        console.print("Resume with: " f"[cyan]attackcastle run resume --run-dir {outcome.run_dir}[/cyan]")


def _resolve_run_dir(
    run_dir: str | None,
    run_id: str | None,
    output_dir: str,
    required: bool = True,
    validator: Callable[[Path], bool] | None = None,
    search_label: str = "run directories",
) -> Path | None:
    def _nearest_run_dir(path: Path) -> Path | None:
        current = path if path.is_dir() else path.parent
        for candidate in (current, *current.parents):
            if candidate.name.startswith("run_"):
                return candidate.resolve()
        return None

    def _run_id_for_sort(path: Path) -> str:
        return path.name.removeprefix("run_")

    def _candidate_key(path: Path) -> tuple[float, str]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        return (mtime, _run_id_for_sort(path))

    def _has_summary(path: Path) -> bool:
        return (path / "data" / "run_summary.json").exists()

    def _iter_run_candidates(root: Path) -> list[Path]:
        if not root.exists() or not root.is_dir():
            return []
        candidates: list[Path] = []
        for child in root.iterdir():
            if child.is_symlink() or not child.is_dir() or not child.name.startswith("run_"):
                continue
            resolved = child.resolve()
            if validator is not None and not validator(resolved):
                continue
            candidates.append(resolved)
        return candidates

    def _select_latest(root: Path) -> Path | None:
        candidates = _iter_run_candidates(root)
        if not candidates:
            return None
        if validator is None:
            with_summary = [path for path in candidates if _has_summary(path)]
            if with_summary:
                candidates = with_summary
        return max(candidates, key=_candidate_key)

    def _search_detail(root: Path) -> str:
        visible_candidates: list[str] = []
        if root.exists() and root.is_dir():
            for child in root.iterdir():
                if child.is_symlink() or not child.is_dir() or not child.name.startswith("run_"):
                    continue
                visible_candidates.append(child.name)
        considered = ", ".join(sorted(visible_candidates)) or "none"
        if search_label == "run directories":
            return f"No valid run_* directories found under {root}. Considered: {considered}."
        return f"No valid run_* directories containing {search_label} found under {root}. Considered: {considered}."

    if run_dir:
        provided = Path(run_dir).expanduser().resolve()
        if not provided.exists():
            if required:
                raise typer.BadParameter(f"Run directory does not exist: {provided}")
            return None
        nested_run_dir = _nearest_run_dir(provided)
        if nested_run_dir is not None:
            if validator is not None and not validator(nested_run_dir):
                if required:
                    raise typer.BadParameter(f"Run directory does not contain {search_label}: {nested_run_dir}")
                return None
            return nested_run_dir
        # Professional default: if a parent output folder is provided, auto-select latest run.
        if provided.is_dir() and not provided.name.startswith("run_"):
            selected = _select_latest(provided)
            if selected is not None:
                return selected
            if required:
                raise typer.BadParameter(_search_detail(provided))
            return None
        if validator is not None and not validator(provided):
            if required:
                raise typer.BadParameter(f"Run directory does not contain {search_label}: {provided}")
            return None
        return provided
    if run_id:
        candidate = (Path(output_dir).expanduser().resolve() / f"run_{run_id}").resolve()
        if not candidate.exists():
            if required:
                raise typer.BadParameter(f"Run directory does not exist: {candidate}")
            return None
        if validator is not None and not validator(candidate):
            if required:
                raise typer.BadParameter(f"Run directory does not contain {search_label}: {candidate}")
            return None
        return candidate
    root = Path(output_dir).expanduser().resolve()
    if not root.exists():
        if required:
            raise typer.BadParameter(f"Output directory does not exist: {root}")
        return None
    selected = _select_latest(root)
    if selected is None:
        if required:
            raise typer.BadParameter(_search_detail(root))
        return None
    return selected


def _resolve_report_rebuild_run_dir(run_dir: str) -> Path:
    return _resolve_run_dir(
        run_dir=run_dir,
        run_id=None,
        output_dir=run_dir,
        required=True,
        validator=lambda path: (path / "data" / "scan_data.json").exists(),
        search_label="data/scan_data.json",
    ) or Path(run_dir).expanduser().resolve()


def _resolve_scan_data_run_dir(
    *,
    run_dir: str | None,
    run_id: str | None,
    output_dir: str,
    required: bool = True,
) -> Path | None:
    return _resolve_run_dir(
        run_dir=run_dir,
        run_id=run_id,
        output_dir=output_dir,
        required=required,
        validator=lambda path: (path / "data" / "scan_data.json").exists(),
        search_label="data/scan_data.json",
    )


def _launch_report_in_browser(report_path: Path) -> None:
    launched = webbrowser.open(report_path.resolve().as_uri())
    if not launched:
        raise RuntimeError(
            "Default browser could not be opened automatically. Re-run with --no-launch to print the report path."
        )


def _capability_tool(capability: str) -> tuple[str, str]:
    return readiness_capability_tool(capability)


def _adapter_command(adapter_name: str) -> str:
    mapping = {
        "nmap": "nmap",
        "whatweb": "whatweb",
        "nikto": "nikto",
        "nuclei": "nuclei",
        "wpscan": "wpscan",
        "sqlmap": "sqlmap",
        "framework_checks": "nuclei",
    }
    return mapping.get(adapter_name, "python")


def _external_dependency_rows() -> list[dict[str, Any]]:
    return readiness_external_dependency_rows()


def _missing_dependency_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return readiness_missing_dependency_rows(rows)


def _install_dependencies_with_apt(
    console: Console,
    output_format: str,
    rows: list[dict[str, Any]],
    assume_yes: bool,
    update_index: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    missing_rows = _missing_dependency_rows(rows)
    packages = sorted({str(row["apt_package"]) for row in missing_rows if row.get("apt_package")})
    install_support = dependency_install_support()
    summary = {
        "attempted": bool(packages),
        "packages": packages,
        "installed_packages": [],
        "failed_packages": [],
        "error": None,
        "dry_run": dry_run,
        "supported": install_support.supported,
        "support_reason": install_support.reason,
    }
    if not packages:
        return summary
    if dry_run:
        return summary
    if not install_support.supported:
        summary["error"] = "apt_install_not_supported"
        return summary
    apt_get = install_support.command

    is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    prefix: list[str] = [] if is_root else ["sudo"]
    stream_output = output_format == "text"

    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if stream_output:
            return subprocess.run(cmd, check=False)
        return subprocess.run(cmd, check=False, capture_output=True, text=True)

    if output_format == "text":
        console.print(
            f"[cyan]Dependency bootstrap:[/cyan] attempting apt install for {', '.join(packages)}"
        )
    if update_index:
        update_cmd = [*prefix, apt_get, "update"]
        update_proc = _run(update_cmd)
        if update_proc.returncode != 0:
            summary["error"] = "apt_update_failed"
            return summary

    for package in packages:
        install_cmd = [*prefix, apt_get, "install"]
        if assume_yes:
            install_cmd.append("-y")
        install_cmd.append(package)
        proc = _run(install_cmd)
        if proc.returncode == 0:
            summary["installed_packages"].append(package)
        else:
            summary["failed_packages"].append(package)

    if summary["failed_packages"]:
        summary["error"] = "apt_install_failed"
    return summary


def _missing_dependency_message(rows: list[dict[str, Any]]) -> str:
    return readiness_missing_dependency_message(rows)


def _readiness_status_style(status: str) -> str:
    return {
        "ready": "green",
        "partial": "yellow",
        "blocked": "red",
    }.get(str(status).lower(), "cyan")


def _format_tool_impact(report: ReadinessReport, limit: int = 4) -> str:
    parts: list[str] = []
    for entry in report.tool_impact[:limit]:
        tool = str(entry.get("tool") or "unknown")
        labels = [str(item) for item in entry.get("task_labels", []) if str(item).strip()]
        if labels:
            parts.append(f"{tool}: {', '.join(labels[:2])}")
        else:
            capabilities = [str(item) for item in entry.get("capabilities", []) if str(item).strip()]
            parts.append(f"{tool}: {', '.join(capabilities[:2])}")
    if len(report.tool_impact) > limit:
        parts.append("...")
    return "; ".join(parts) if parts else "-"


def _render_readiness_panel(console: Console, report: ReadinessReport, title: str = "Launch Readiness") -> None:
    table = Table(show_header=False, box=None, pad_edge=False)
    style = _readiness_status_style(report.status)
    table.add_row("Status", f"[{style}]{report.status}[/{style}]")
    table.add_row("Can Launch", "yes" if report.can_launch else "no")
    table.add_row("Risk Mode", report.risk_mode or "unknown")
    if report.assessment_mode == "targeted":
        table.add_row("Planned Tasks", str(report.selected_task_count))
        table.add_row("Runnable Tasks", str(report.runnable_task_count))
        table.add_row("Blocked Tasks", str(report.blocked_task_count))
    table.add_row("Missing Tools", ", ".join(report.missing_tools) or "-")
    table.add_row("Impact", _format_tool_impact(report))
    if report.error:
        table.add_row("Error", report.error)
    if report.recommended_actions:
        table.add_row("Next", report.recommended_actions[0])
    console.print(Panel.fit(table, title=title, border_style=style))


def _build_scan_payload(outcome: ScanOutcome, candidate_count: int) -> dict[str, Any]:
    return {
        "status": "ok",
        "run_id": outcome.run_id,
        "run_dir": str(outcome.run_dir),
        "state": outcome.state,
        "duration_seconds": outcome.duration_seconds,
        "plan_path": str(outcome.plan_path) if outcome.plan_path else None,
        "json_path": str(outcome.json_path) if outcome.json_path else None,
        "report_path": str(outcome.report_path) if outcome.report_path else None,
        "integration_paths": [str(path) for path in outcome.integration_paths],
        "summary_path": str(outcome.summary_path) if outcome.summary_path else None,
        "pdf_path": str(outcome.pdf_path) if outcome.pdf_path else None,
        "metrics_path": str(outcome.metrics_path) if outcome.metrics_path else None,
        "timeline_path": str(outcome.timeline_path) if outcome.timeline_path else None,
        "drift_path": str(outcome.drift_path) if outcome.drift_path else None,
        "identity_graph_path": str(outcome.identity_graph_path) if outcome.identity_graph_path else None,
        "task_instance_graph_path": str(outcome.task_instance_graph_path)
        if outcome.task_instance_graph_path
        else None,
        "finding_count_confirmed": outcome.finding_count,
        "finding_count_candidate": candidate_count,
        "warning_count": outcome.warning_count,
        "error_count": outcome.error_count,
        "dry_run": outcome.dry_run,
    }


def _render_inline_triage(console: Console, run_dir: Path, top: int = 8) -> None:
    payload = _load_run_scan_data(run_dir)
    if not payload:
        return
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        return
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = []
    for item in findings:
        if item.get("suppressed"):
            continue
        rows.append(
            {
                "title": item.get("title"),
                "severity": item.get("severity", "info"),
                "status": item.get("status", "unknown"),
                "evidence_quality": float(item.get("evidence_quality_score", 0.0)),
            }
        )
    rows.sort(key=lambda row: (rank.get(row["severity"], 99), -row["evidence_quality"]))
    rows = rows[: max(1, top)]
    if not rows:
        return
    table = Table(title="Inline Findings Triage")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("EvidenceQ")
    table.add_column("Title")
    for row in rows:
        table.add_row(
            str(row["severity"]),
            str(row["status"]),
            f"{row['evidence_quality']:.2f}",
            str(row["title"]),
        )
    console.print(table)


def _load_resume_context(run_dir: Path) -> tuple[str, str]:
    run_store = RunStore.from_existing(run_dir)
    checkpoint = run_store.load_latest_checkpoint()
    payload: dict[str, Any] | None = None
    if checkpoint and isinstance(checkpoint.get("run_data"), dict):
        payload = checkpoint["run_data"]
    else:
        scan_data_path = run_dir / "data" / "scan_data.json"
        if scan_data_path.exists():
            payload = json.loads(scan_data_path.read_text(encoding="utf-8"))
    if not payload:
        raise ValueError("Could not load run context from checkpoint or scan_data.json.")
    run_data = run_data_from_dict(migrate_payload(payload))
    return run_data.metadata.target_input, run_data.metadata.profile


def _render_file_tree(base: Path) -> Tree:
    tree = Tree(f"[bold]{base}[/bold]")

    def add_dir(node: Tree, directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if path.is_dir():
                child = node.add(f"[cyan]{path.name}[/cyan]")
                add_dir(child, path)
            else:
                node.add(path.name)

    add_dir(tree, base)
    return tree


def _parse_cli_override(raw: str | None) -> Any:
    if raw is None:
        return None
    try:
        return yaml.safe_load(raw)
    except Exception:
        return raw


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            loaded = json.loads(stripped)
            if isinstance(loaded, dict):
                rows.append(loaded)
        except Exception:
            continue
    return rows


class ScanDataLoadError(ValueError):
    def __init__(self, message: str, *, suggestion: str | None = None) -> None:
        super().__init__(message)
        self.suggestion = suggestion


def _load_run_scan_data(run_dir: Path) -> dict[str, Any] | None:
    scan_data_path = run_dir / "data" / "scan_data.json"
    if not scan_data_path.exists():
        return None
    try:
        loaded = json.loads(scan_data_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        return None
    return None


def _read_required_scan_data(run_dir: Path) -> dict[str, Any]:
    scan_data_path = run_dir / "data" / "scan_data.json"
    if not scan_data_path.exists():
        raise ScanDataLoadError(
            f"data/scan_data.json not available for this run: {scan_data_path}",
            suggestion="Verify the run completed and the run directory contains data/scan_data.json.",
        )
    try:
        loaded = json.loads(scan_data_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScanDataLoadError(
            f"data/scan_data.json is invalid JSON: {scan_data_path} ({exc})",
            suggestion="Repair or regenerate data/scan_data.json, then rerun the command.",
        ) from exc
    except OSError as exc:
        raise ScanDataLoadError(
            f"data/scan_data.json could not be read: {scan_data_path} ({exc})",
            suggestion="Check file permissions and try again.",
        ) from exc
    if not isinstance(loaded, dict):
        raise ScanDataLoadError(
            f"data/scan_data.json did not contain a JSON object: {scan_data_path}",
            suggestion="Repair or regenerate data/scan_data.json, then rerun the command.",
        )
    return loaded


def _load_json_mapping(path: Path, *, label: str) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, f"{label} ignored: {path.name} is unreadable ({exc})."
    if not isinstance(loaded, dict):
        return {}, f"{label} ignored: {path.name} did not contain a JSON object."
    return loaded, None


def _coerce_dashboard_float(mapping: dict[str, Any], key: str, *, label: str, default: float = 0.0) -> tuple[float, str | None]:
    value = mapping.get(key)
    if value is None:
        return default, None
    if isinstance(value, bool):
        return default, f"{label} ignored: {key} must be numeric."
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return default, f"{label} ignored: {key} must be numeric."
    else:
        return default, f"{label} ignored: {key} must be numeric."
    if not math.isfinite(number):
        return default, f"{label} ignored: {key} must be finite."
    return number, None


def _coerce_dashboard_int(mapping: dict[str, Any], key: str, *, label: str, default: int = 0) -> tuple[int, str | None]:
    value = mapping.get(key)
    if value is None:
        return default, None
    if isinstance(value, bool):
        return default, f"{label} ignored: {key} must be an integer."
    if isinstance(value, int):
        return value, None
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value), None
        return default, f"{label} ignored: {key} must be an integer."
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default, f"{label} ignored: {key} must be an integer."
        try:
            number = float(text)
        except ValueError:
            return default, f"{label} ignored: {key} must be an integer."
        if math.isfinite(number) and number.is_integer():
            return int(number), None
        return default, f"{label} ignored: {key} must be an integer."
    return default, f"{label} ignored: {key} must be an integer."


def _coerce_dashboard_mapping(
    value: Any,
    *,
    label: str,
    field_name: str,
) -> tuple[dict[str, Any], str | None]:
    if value is None:
        return {}, None
    if isinstance(value, dict):
        return value, None
    return {}, f"{label} ignored: {field_name} did not contain a JSON object."


def _coerce_dashboard_items(
    value: Any,
    *,
    label: str,
    field_name: str,
) -> tuple[list[dict[str, Any]], str | None]:
    if value is None:
        return [], None
    if not isinstance(value, list):
        return [], f"{label} ignored: {field_name} did not contain a JSON array."
    valid_items = [item for item in value if isinstance(item, dict)]
    invalid_count = len(value) - len(valid_items)
    if invalid_count <= 0:
        return valid_items, None
    noun = "entry" if invalid_count == 1 else "entries"
    return valid_items, f"{label} ignored: dropped {invalid_count} malformed item {noun} from {field_name}."


def _dashboard_int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value)
        return default
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            number = float(text)
        except ValueError:
            return default
        if math.isfinite(number) and number.is_integer():
            return int(number)
    return default


def _dashboard_output_mode(mode: dict[str, Any]) -> str:
    labels: list[str] = []
    if mode.get("json_only"):
        labels.append("json-only")
    elif mode.get("html_only"):
        labels.append("html-only")
    elif mode.get("no_report"):
        labels.append("no-report")
    else:
        labels.append("standard")
    if mode.get("redact"):
        labels.append("redacted")
    return ", ".join(labels)


def _build_dashboard_plan_summary(
    plan: dict[str, Any],
    scan_data: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    items, items_error = _coerce_dashboard_items(
        plan.get("items"),
        label="Dashboard plan",
        field_name="items",
    )
    scope_summary, scope_error = _coerce_dashboard_mapping(
        plan.get("scope_compiler"),
        label="Dashboard plan",
        field_name="scope_compiler",
    )
    mode, mode_error = _coerce_dashboard_mapping(
        plan.get("mode"),
        label="Dashboard plan",
        field_name="mode",
    )
    noise_limit, noise_limit_error = _coerce_dashboard_int(
        plan,
        "max_noise_limit",
        label="Dashboard plan",
        default=0,
    )
    host_estimate, host_estimate_error = _coerce_dashboard_int(
        scope_summary,
        "compiled_target_count",
        label="Dashboard plan",
        default=0,
    )
    if host_estimate <= 0 and isinstance(scan_data, dict):
        fallback_scope = scan_data.get("scope")
        if isinstance(fallback_scope, list):
            host_estimate = len([item for item in fallback_scope if isinstance(item, dict)])
    selected_items = [item for item in items if item.get("selected")]
    blocked_items = [item for item in items if not item.get("selected")]
    scheduled_tools = {
        str(item.get("capability", "")).strip()
        for item in selected_items
        if str(item.get("capability", "")).strip()
    }
    expected_noise_total = sum(max(0, _dashboard_int_value(item.get("noise_score"), default=0)) for item in selected_items)
    warnings = [
        item
        for item in (
            items_error,
            scope_error,
            mode_error,
            noise_limit_error,
            host_estimate_error,
        )
        if item
    ]
    return {
        "risk_mode": str(plan.get("risk_mode") or "unknown"),
        "output_mode": _dashboard_output_mode(mode),
        "selected_task_count": len(selected_items),
        "blocked_task_count": len(blocked_items),
        "scheduled_tool_count": len(scheduled_tools),
        "host_estimate": host_estimate,
        "expected_noise_total": expected_noise_total,
        "noise_limit": noise_limit,
    }, warnings


def _load_dashboard_control(run_store: RunStore) -> tuple[dict[str, Any], str | None]:
    control = run_store.read_control()
    if control is not None:
        return control, None
    if run_store.control_path.exists():
        return {}, "Dashboard control ignored: control.json was unreadable."
    return {}, None


def _profile_module_map(config: dict[str, Any]) -> dict[str, bool]:
    modules = {
        "subdomain_enum": bool(config.get("subdomain_enum", {}).get("enabled", True)),
        "dns_resolution": True,
        "nmap": bool(config.get("nmap", {}).get("enabled", True)),
        "web_probe": True,
        "web_discovery": True,
        "tls": True,
        "whatweb": bool(config.get("whatweb", {}).get("enabled", True)),
        "nikto": bool(config.get("nikto", {}).get("enabled", True)),
        "nuclei": bool(config.get("nuclei", {}).get("enabled", True)),
        "sqlmap": bool(config.get("sqlmap", {}).get("enabled", True)),
        "wpscan": bool(config.get("wpscan", {}).get("enabled", True)),
        "framework_checks": bool(config.get("framework_checks", {}).get("enabled", True)),
        "cve_enricher": True,
    }
    blocked = {
        str(item)
        for item in config.get("risk_mode_controls", {}).get("blocked_capabilities", [])
        if str(item).strip()
    }
    capability_to_module = {
        "subdomain_enumeration": "subdomain_enum",
        "network_port_scan": "nmap",
        "web_vuln_scan": "nikto",
        "web_template_scan": "nuclei",
        "web_injection_scan": "sqlmap",
        "cms_wordpress_scan": "wpscan",
        "cms_framework_scan": "framework_checks",
    }
    for capability, module_name in capability_to_module.items():
        if capability in blocked:
            modules[module_name] = False
    return modules


def _estimate_plan_runtime_seconds(plan_payload: dict[str, Any], config: dict[str, Any]) -> int:
    budgets = config.get("orchestration", {}).get("capability_budgets", {})
    total = 0
    selected_items = [item for item in plan_payload.get("items", []) if item.get("selected")]
    for item in selected_items:
        capability = str(item.get("capability", ""))
        capability_budget = budgets.get(capability, {})
        runtime = capability_budget.get("max_runtime_seconds")
        if isinstance(runtime, (int, float)):
            total += int(runtime)
            continue
        total += max(30, int(item.get("cost_score", 1)) * 60)
    concurrency = max(1, int(config.get("profile", {}).get("concurrency", 1) or 1))
    return max(1, total // concurrency) if total else 0


def _format_duration_brief(total_seconds: int) -> str:
    seconds = max(0, int(total_seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minute}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _plan_preview_metrics(plan_payload: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    selected_items = [item for item in plan_payload.get("items", []) if item.get("selected")]
    blocked_items = [item for item in plan_payload.get("items", []) if not item.get("selected")]
    scope_summary = plan_payload.get("scope_compiler", {})
    concurrency = max(1, int(config.get("profile", {}).get("concurrency", 1) or 1))
    runtime_seconds = _estimate_plan_runtime_seconds(plan_payload, config)
    return {
        "expected_noise_total": sum(int(item.get("noise_score", 0)) for item in selected_items),
        "noise_limit": plan_payload.get("max_noise_limit"),
        "blocked_task_count": len(blocked_items),
        "selected_task_count": len(selected_items),
        "host_estimate": int(scope_summary.get("compiled_target_count", 0) or 0),
        "tools_scheduled": len({str(item.get("capability", "")) for item in selected_items}),
        "concurrency": concurrency,
        "estimated_runtime_seconds": runtime_seconds,
        "estimated_runtime": _format_duration_brief(runtime_seconds),
        "stages": len({str(item.get("capability", "")) for item in selected_items}),
    }


def _load_run_data(run_dir: Path):
    return run_data_from_dict(migrate_payload(_read_required_scan_data(run_dir)))


def _artifact_text_preview(path: Path, max_lines: int = 40, max_chars: int = 4000) -> str:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
    else:
        text = path.read_text(encoding="utf-8", errors="ignore")
    text = text[:max_chars]
    lines = text.splitlines()
    return "\n".join(lines[:max_lines])


def _contextual_help_for_mode(ui_mode: str) -> list[str]:
    if ui_mode == "automation":
        return [
            "Use --output-format json or ndjson for parsable output.",
            "Use --non-interactive for CI pipelines.",
        ]
    return [
        "Check data/plan.json in the run directory to inspect the automatic task plan.",
        "Use attackcastle run timeline --run-id <id> to replay execution.",
    ]


def _flatten_dict(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten_dict(next_prefix, child, out)
        return
    out[prefix] = value


@app.callback()
def main(
    ctx: typer.Context,
    ui_mode: str = typer.Option(
        "operator",
        "--ui-mode",
        help="Terminal UX mode: operator (rich) or automation (minimal).",
    ),
    theme: str = typer.Option(
        "professional",
        "--theme",
        help="Terminal theme: professional|contrast|plain.",
    ),
    role: str = typer.Option(
        "operator",
        "--role",
        help="Terminal role profile: operator|manager|qa.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
    quiet: bool = typer.Option(False, "--quiet", help="Reduce non-essential text output."),
) -> None:
    """AttackCastle command group."""
    config = UXConfig(
        ui_mode=_normalize_choice(ui_mode, UI_MODES, "--ui-mode"),
        theme=_normalize_choice(theme, UI_THEMES, "--theme"),
        role=_normalize_choice(role, UI_ROLES, "--role"),
        no_color=no_color,
        quiet=quiet,
    )
    ctx.obj = config


@app.command("gui", help="Launch the AttackCastle desktop GUI.")
def launch_gui() -> None:
    from attackcastle.gui.launcher import main as gui_main

    raise typer.Exit(code=int(gui_main()))


@app.command(
    help=(
        "Run an authorized external scan workflow.\n\n"
        "Examples:\n"
        "  attackcastle scan -t example.com -o ./output --profile cautious\n"
        "  attackcastle scan --scope-file ./scope.txt -o ./output --dry-run\n"
        "  attackcastle scan -t 10.0.0.0/24 -o ./output --non-interactive --yes"
    )
)
def scan(
    ctx: typer.Context,
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target input (IP, CIDR, domain, URL, host:port)."
    ),
    targets: list[str] = typer.Option(
        [],
        "--targets",
        help="Repeatable target source. Accepts a file path or a literal target value.",
    ),
    scope_file: str | None = typer.Option(
        None,
        "--scope-file",
        help="File containing newline/comma separated targets.",
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", "-o", help="Directory to write run artifacts."
    ),
    profile: str = typer.Option(
        "prototype",
        "--profile",
        "-p",
        help="Scan profile: prototype | cautious | standard | aggressive.",
    ),
    risk_mode: str | None = typer.Option(
        None,
        "--risk-mode",
        help="Risk mode override: passive | safe-active | aggressive.",
    ),
    target_type: str | None = typer.Option(
        None,
        "--target-type",
        help="Optional explicit target type: domain|wildcard_domain|ip|cidr|ip_range|url|host_port|asn.",
    ),
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional path to custom YAML config file.",
    ),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        help="Route HTTP-capable tooling through an HTTP(S) proxy such as Burp.",
    ),
    no_proxy: bool = typer.Option(
        False,
        "--no-proxy",
        help="Disable AttackCastle HTTP proxy routing for this run, even if configured elsewhere.",
    ),
    allow: list[str] = typer.Option([], "--allow", help="Allow token filter (repeatable)."),
    deny: list[str] = typer.Option([], "--deny", help="Deny token filter (repeatable)."),
    max_hosts: int | None = typer.Option(None, "--max-hosts", help="Maximum estimated host count."),
    max_ports: int | None = typer.Option(None, "--max-ports", help="Apply nmap --top-ports value."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Prepare outputs without running scanners."),
    json_only: bool = typer.Option(False, "--json-only", help="Only produce JSON outputs."),
    html_only: bool = typer.Option(False, "--html-only", help="Only produce HTML output."),
    no_report: bool = typer.Option(False, "--no-report", help="Disable report generation."),
    redact: bool = typer.Option(False, "--redact", help="Redact sensitive evidence snippets in outputs."),
    audience: str = typer.Option(
        "consultant",
        "--audience",
        help="Report audience: executive|client|consultant. Compatibility aliases: client-safe->client, technical->consultant.",
    ),
    events_jsonl: str | None = typer.Option(
        None,
        "--events-jsonl",
        help="Optional path for machine-readable orchestration events.",
    ),
    resume_run_dir: str | None = typer.Option(
        None,
        "--resume-run-dir",
        help="Resume from an existing run directory.",
    ),
    keep_raw_artifacts: bool | None = typer.Option(
        None,
        "--keep-raw-artifacts/--drop-raw-artifacts",
        help="Override retention behavior for raw artifacts.",
    ),
    verbosity: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Increase verbosity (-v for stage logs, -vv for command/evidence details).",
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--non-interactive",
        help="Interactive prompts or strict non-interactive mode.",
    ),
    expand_asn: bool | None = typer.Option(
        None,
        "--expand-asn/--no-expand-asn",
        help="Override ASN-to-CIDR expansion for this run.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Auto-confirm aggressive/noisy scan guardrails.",
    ),
    install_missing: bool = typer.Option(
        False,
        "--install-missing",
        help="Install missing external scanner dependencies with apt before scan execution.",
    ),
    triage: bool = typer.Option(
        False,
        "--triage",
        help="Show inline top findings triage after scan completion.",
    ),
    output_format: str = typer.Option(
        "text",
        "--output-format",
        help="CLI output format: text|json|ndjson.",
    ),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and not ux.quiet:
        render_banner(console, ux)
        render_operator_notice(
            console,
            "Use --ui-mode automation for deterministic machine-oriented output.",
            level="muted",
        )

    if json_only and html_only:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="--json-only and --html-only cannot be used together.",
            suggestion="Choose one output mode or remove both flags.",
        )

    try:
        resolved_target = _resolve_target_input(
            target,
            scope_file,
            targets,
            interactive=interactive,
            console=console,
        )
        resolved_output = _resolve_output_dir(output_dir, interactive=interactive, console=console)
        _guard_profile_risk(
            profile=profile,
            max_ports=max_ports,
            yes=yes,
            interactive=interactive,
            console=console,
        )
    except typer.BadParameter as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message=str(exc),
            suggestion="Review command flags and re-run.",
        )

    dependency_rows = _external_dependency_rows()
    install_support = dependency_install_support()
    missing_dependency_commands = _missing_dependency_message(dependency_rows)
    if missing_dependency_commands:
        should_install = install_missing
        if (
            not should_install
            and interactive
            and output_format == "text"
            and bool(getattr(console, "is_terminal", False))
            and install_support.supported
        ):
            should_install = Confirm.ask(
                (
                    "Missing external tools detected: "
                    f"{missing_dependency_commands}. Install now with apt-get?"
                ),
                default=True,
                console=console,
            )
        elif (
            missing_dependency_commands
            and interactive
            and output_format == "text"
            and not install_support.supported
        ):
            render_operator_notice(console, install_support.reason, level="warn")
        if should_install:
            if not install_support.supported:
                _exit_with_error(
                    console,
                    output_format=output_format,
                    code=ExitCode.DEPENDENCY_ERROR,
                    message="Automatic dependency installation is not available in this environment.",
                    detail=install_support.reason,
                    suggestion="Install the required scanner tools manually, then re-run the scan.",
                )
            install_summary = _install_dependencies_with_apt(
                console=console,
                output_format=output_format,
                rows=dependency_rows,
                assume_yes=yes,
            )
            dependency_rows = _external_dependency_rows()
            unresolved_after_install = _missing_dependency_message(dependency_rows)
            if install_summary.get("error") or unresolved_after_install:
                detail_parts = []
                if install_summary.get("error"):
                    detail_parts.append(f"installer={install_summary.get('error')}")
                if install_summary.get("failed_packages"):
                    detail_parts.append(
                        "failed_packages=" + ",".join(sorted(install_summary.get("failed_packages", [])))
                    )
                if unresolved_after_install:
                    detail_parts.append(f"still_missing={unresolved_after_install}")
                _exit_with_error(
                    console,
                    output_format=output_format,
                    code=ExitCode.DEPENDENCY_ERROR,
                    message="Dependency bootstrap failed before scan execution.",
                    detail="; ".join(detail_parts) or "Unknown dependency bootstrap failure.",
                    suggestion="Run `attackcastle doctor --install-missing --yes` with appropriate sudo access.",
                )
        elif output_format == "text":
            console.print(
                "[yellow]Continuing without some optional tools:[/yellow] "
                f"{missing_dependency_commands}"
            )

    readiness = assess_readiness(
        target_input=resolved_target,
        profile=profile,
        user_config_path=config,
        risk_mode=risk_mode,
        forced_target_type=target_type,
        allow=allow,
        deny=deny,
        max_hosts=max_hosts,
        max_ports=max_ports,
        proxy_url=proxy,
        disable_proxy=no_proxy,
        dependency_rows=dependency_rows,
    )
    if interactive and output_format == "text":
        _render_readiness_panel(console, readiness)
    if not readiness.can_launch:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.DEPENDENCY_ERROR,
            message="Launch readiness check blocked the scan.",
            detail=readiness.error or "; ".join(readiness.recommended_actions),
            suggestion=readiness.recommended_actions[0] if readiness.recommended_actions else "Review the readiness summary and retry.",
        )
    if readiness.partial_run and output_format == "text":
        render_operator_notice(
            console,
            readiness.recommended_actions[0],
            level="warn",
        )

    try:
        outcome = run_scan(
            target_input=resolved_target,
            output_directory=resolved_output,
            profile=profile,
            forced_target_type=target_type,
            risk_mode=risk_mode,
            user_config_path=config,
            verbose=verbosity > 0,
            verbosity=verbosity,
            console=console,
            dry_run=dry_run,
            allow=allow,
            deny=deny,
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
            rich_ui=(
                output_format == "text"
                and ux.ui_mode == "operator"
                and bool(getattr(console, "is_terminal", False))
            ),
            emit_plain_logs=(output_format == "text" and ux.ui_mode == "operator" and not ux.quiet),
            asn_expansion_override=expand_asn,
            proxy_url=proxy,
            disable_proxy=no_proxy,
        )
    except ValidationError as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Validation failed while preparing scan.",
            detail=str(exc),
            suggestion="Review scope/profile limits and try again.",
        )
    except FileNotFoundError as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.DEPENDENCY_ERROR,
            message="A required external dependency was not found.",
            detail=str(exc),
            suggestion="Run `attackcastle doctor` and install missing tools.",
        )
    except KeyboardInterrupt:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.CANCELLED,
            message="Run cancelled by user.",
            suggestion="Resume with `attackcastle run resume --run-dir <path>`.",
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Scan execution failed unexpectedly.",
            detail=str(exc),
            suggestion="Inspect logs/<run>/run.log and retry.",
        )

    candidate_count = _load_candidate_count(outcome.json_path)
    payload = _build_scan_payload(outcome, candidate_count=candidate_count)
    if output_format == "text":
        _render_scan_summary(console, outcome, candidate_count=candidate_count, role=ux.role)
        if triage and outcome.json_path:
            _render_inline_triage(console, outcome.run_dir, top=8)
        if not ux.quiet:
            render_next_steps(
                console,
                [
                    f"attackcastle run status --run-dir {outcome.run_dir}",
                    f"attackcastle artifacts tree --run-dir {outcome.run_dir}",
                    f"attackcastle report open --run-dir {outcome.run_dir}",
                    *_contextual_help_for_mode(ux.ui_mode),
                ],
            )
    else:
        _emit_payload(console, payload, output_format, event="scan.completed")

    exit_code = _exit_code_for_outcome(outcome)
    if exit_code != ExitCode.OK:
        raise typer.Exit(code=int(exit_code))


@app.command(
    "guided-scan",
    help=(
        "Interactive guided scan wizard for operator workflows.\n\n"
        "Collects scan inputs interactively, shows key settings, and launches the scan."
    ),
)
def guided_scan(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
    config: str | None = typer.Option(None, "--config", "-c"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text":
        render_banner(console, ux)
    if output_format != "text":
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "guided-scan requires text output for interactive prompts.",
            suggestion="Use `scan` for json/ndjson modes.",
        )

    target = Prompt.ask("Target", console=console)
    output_dir = Prompt.ask("Output directory", default="./output", console=console)
    profile = Prompt.ask(
        "Profile (prototype|cautious|standard|aggressive)", default="prototype", console=console
    )
    profile = _normalize_choice(profile, {"prototype", "cautious", "standard", "aggressive"}, "profile")
    risk_mode = Prompt.ask(
        "Risk mode (passive|safe-active|aggressive)",
        default="safe-active",
        console=console,
    ).strip().lower()
    proxy = Prompt.ask(
        "Proxy URL (blank to disable; HTTP-capable tooling only)",
        default="",
        show_default=False,
        console=console,
    ).strip()

    summary = Table(show_header=False, box=None, pad_edge=False)
    summary.add_row("Target", target)
    summary.add_row("Output Directory", output_dir)
    summary.add_row("Profile", profile)
    summary.add_row("Risk Mode", risk_mode)
    summary.add_row("Proxy", proxy or "disabled")
    console.print(Panel.fit(summary, title="Scan Settings", border_style="cyan"))
    readiness = assess_readiness(
        target_input=target,
        profile=profile,
        user_config_path=config,
        risk_mode=risk_mode,
        proxy_url=proxy or None,
        dependency_rows=_external_dependency_rows(),
    )
    _render_readiness_panel(console, readiness)
    if not readiness.can_launch:
        render_operator_notice(
            console,
            readiness.recommended_actions[0] if readiness.recommended_actions else "Readiness checks blocked this launch.",
            level="error",
        )
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))

    if not Confirm.ask("Start scan now?", default=True, console=console):
        render_operator_notice(console, "Guided scan cancelled before execution.", level="warn")
        raise typer.Exit(code=int(ExitCode.CANCELLED))

    outcome = run_scan(
        target_input=target,
        output_directory=output_dir,
        profile=profile,
        risk_mode=risk_mode,
        user_config_path=config,
        console=console,
        rich_ui=(ux.ui_mode == "operator"),
        emit_plain_logs=(ux.ui_mode == "operator" and not ux.quiet),
        proxy_url=proxy or None,
    )
    candidate_count = _load_candidate_count(outcome.json_path)
    _render_scan_summary(console, outcome, candidate_count, role=ux.role)
    render_next_steps(
        console,
        [
            f"attackcastle run status --run-dir {outcome.run_dir}",
            f"attackcastle findings triage --run-dir {outcome.run_dir}",
        ],
    )
    code = _exit_code_for_outcome(outcome)
    if code != ExitCode.OK:
        raise typer.Exit(code=int(code))


@app.command(
    help=(
        "Advanced preview/debug of the automatically generated workflow plan.\n\n"
        "Examples:\n"
        "  attackcastle plan -t example.com -o ./output\n"
        "  attackcastle plan --scope-file ./scope.txt --profile cautious --output-format json"
    )
)
def plan(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", "-t", help="Target input."),
    targets: list[str] = typer.Option(
        [],
        "--targets",
        help="Repeatable target source. Accepts a file path or a literal target value.",
    ),
    scope_file: str | None = typer.Option(None, "--scope-file", help="Path to scope file."),
    output_dir: str | None = typer.Option("./output", "--output-dir", "-o"),
    profile: str = typer.Option("prototype", "--profile", "-p"),
    risk_mode: str | None = typer.Option(None, "--risk-mode"),
    target_type: str | None = typer.Option(
        None,
        "--target-type",
        help="Optional explicit target type: domain|wildcard_domain|ip|cidr|ip_range|url|host_port|asn.",
    ),
    config: str | None = typer.Option(None, "--config", "-c"),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        help="Route HTTP-capable tooling through an HTTP(S) proxy such as Burp.",
    ),
    no_proxy: bool = typer.Option(
        False,
        "--no-proxy",
        help="Disable AttackCastle HTTP proxy routing for this plan, even if configured elsewhere.",
    ),
    allow: list[str] = typer.Option([], "--allow"),
    deny: list[str] = typer.Option([], "--deny"),
    max_hosts: int | None = typer.Option(None, "--max-hosts"),
    max_ports: int | None = typer.Option(None, "--max-ports"),
    interactive: bool = typer.Option(
        True,
        "--interactive/--non-interactive",
        help="Interactive prompts or strict non-interactive mode.",
    ),
    show_commands: bool = typer.Option(
        True,
        "--show-commands/--hide-commands",
        help="Include command previews when available.",
    ),
    graph: bool = typer.Option(
        True,
        "--graph/--no-graph",
        help="Render workflow graph with dependencies and decision reasons.",
    ),
    output_format: str = typer.Option(
        "text",
        "--output-format",
        help="CLI output format: text|json|ndjson.",
    ),
    expand_asn: bool | None = typer.Option(
        None,
        "--expand-asn/--no-expand-asn",
        help="Override ASN-to-CIDR expansion for this plan.",
    ),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_target = _resolve_target_input(
            target,
            scope_file,
            targets,
            interactive=interactive,
            console=console,
        )
        resolved_output = _resolve_output_dir(output_dir, interactive=interactive, console=console)
        options = ScanOptions(
            target_input=resolved_target,
            output_directory=resolved_output,
            profile=profile,
            forced_target_type=target_type,
            risk_mode=risk_mode,
            user_config_path=config,
            dry_run=True,
            allow=allow,
            deny=deny,
            max_hosts=max_hosts,
            max_ports=max_ports,
            rich_ui=False,
            asn_expansion_override=expand_asn,
            proxy_url=proxy,
            disable_proxy=no_proxy,
        )
        bundle, run_store = build_scan_plan(options, console=console)
    except (ValidationError, typer.BadParameter) as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Plan build failed.",
            detail=str(exc),
            suggestion="Check target scope and policy limits.",
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Unexpected error while generating plan.",
            detail=str(exc),
        )

    plan_payload = bundle["plan_payload"]
    config_payload = bundle["config"]
    plan_path = run_store.write_json("data/plan.json", plan_payload)

    selected_items = [item for item in plan_payload["items"] if item.get("selected")]
    required_tools: list[dict[str, Any]] = []
    seen_tools: set[str] = set()
    for item in selected_items:
        tool_name, command_name = _capability_tool(item.get("capability", ""))
        if tool_name in seen_tools:
            continue
        seen_tools.add(tool_name)
        available = bool(shutil.which(command_name)) if command_name != "python" else True
        required_tools.append(
            {
                "tool": tool_name,
                "command": command_name,
                "required_by": item.get("key"),
                "available": available,
            }
        )

    preview_metrics = _plan_preview_metrics(plan_payload, config_payload)
    plan_result = {
        "run_id": plan_payload["run_id"],
        "profile": plan_payload["profile"],
        "risk_mode": plan_payload.get("risk_mode"),
        "plan_path": str(plan_path),
        "expected_noise_total": preview_metrics["expected_noise_total"],
        "max_noise_limit": plan_payload.get("max_noise_limit"),
        "items": plan_payload["items"],
        "conflicts": plan_payload.get("conflicts", []),
        "safety": plan_payload.get("safety", {}),
        "required_tools": required_tools,
        "preview": preview_metrics,
        "capability_budgets": config_payload.get("orchestration", {}).get("capability_budgets", {}),
        "retry_ceiling_by_capability": config_payload.get("orchestration", {}).get(
            "retry_ceiling_by_capability", {}
        ),
        "max_total_retries": config_payload.get("orchestration", {}).get("max_total_retries"),
    }
    if show_commands:
        plan_result["preview_commands"] = {
            item.get("key"): item.get("preview_commands", []) for item in plan_payload["items"]
        }

    if output_format == "text":
        if ux.ui_mode == "operator" and graph:
            render_task_graph(console, plan_payload["items"])
        table = Table(title="Execution Plan")
        table.add_column("Task")
        table.add_column("Capability")
        table.add_column("Selected")
        table.add_column("Noise")
        table.add_column("Cost")
        table.add_column("Reason")
        for item in plan_payload["items"]:
            table.add_row(
                item["label"],
                item["capability"],
                "yes" if item["selected"] else "no",
                str(item["noise_score"]),
                str(item.get("cost_score", "-")),
                item["reason"],
            )
        console.print(table)
        tools_table = Table(title="Required Tools")
        tools_table.add_column("Tool")
        tools_table.add_column("Command")
        tools_table.add_column("Available")
        for tool in required_tools:
            tools_table.add_row(tool["tool"], tool["command"], "yes" if tool["available"] else "no")
        console.print(tools_table)
        summary = Table(title="Plan Preview")
        summary.add_column("Metric")
        summary.add_column("Value")
        summary.add_row("Expected noise", str(preview_metrics["expected_noise_total"]))
        summary.add_row("Noise limit", str(preview_metrics["noise_limit"]))
        summary.add_row("Tasks blocked", str(preview_metrics["blocked_task_count"]))
        summary.add_row("Targets compiled", str(preview_metrics["host_estimate"]))
        summary.add_row("Tools scheduled", str(preview_metrics["tools_scheduled"]))
        summary.add_row("Concurrency", str(preview_metrics["concurrency"]))
        summary.add_row("Estimated runtime", str(preview_metrics["estimated_runtime"]))
        console.print(summary)
        console.print(f"Plan saved to: [cyan]{plan_path}[/cyan]")
        if ux.ui_mode == "operator":
            render_safety_contract(
                console,
                {
                    "safety": plan_payload.get("safety", {}),
                    "orchestration": {
                        "max_total_retries": config_payload.get("orchestration", {}).get("max_total_retries"),
                        "retry_ceiling_by_capability": config_payload.get("orchestration", {}).get(
                            "retry_ceiling_by_capability", {}
                        ),
                    },
                },
            )
        if show_commands:
            for item in plan_payload["items"]:
                previews = item.get("preview_commands", [])
                if previews:
                    console.print(f"[bold]{item['label']}[/bold]")
                    for command in previews[:5]:
                        console.print(f"  - {command}")
    else:
        _emit_payload(console, plan_result, output_format, event="plan.generated")


@scope_app.command("validate")
def scope_validate(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", "-t", help="Target input."),
    targets: list[str] = typer.Option(
        [],
        "--targets",
        help="Repeatable target source. Accepts a file path or a literal target value.",
    ),
    scope_file: str | None = typer.Option(None, "--scope-file", help="Path to scope file."),
    target_type: str | None = typer.Option(
        None,
        "--target-type",
        help="Optional explicit target type: domain|wildcard_domain|ip|cidr|ip_range|url|host_port|asn.",
    ),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_target = _resolve_target_input(
            target,
            scope_file,
            targets,
            interactive=False,
            console=console,
        )
        summary = summarize_target_input(resolved_target, forced_type=target_type)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Scope validation failed.",
            detail=str(exc),
        )
        return

    payload = {
        "total_entries": summary.total_entries,
        "valid_entries": summary.valid_entries,
        "invalid_entries": summary.invalid_entries,
        "duplicates_removed": summary.duplicates_removed,
        "by_type": summary.by_type,
        "invalid_values": summary.invalid_values,
    }
    if output_format == "text":
        table = Table(title="Scope Validation")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Total entries", str(summary.total_entries))
        table.add_row("Valid entries", str(summary.valid_entries))
        table.add_row("Valid domains", str(summary.by_type.get("domain", 0) + summary.by_type.get("wildcard_domain", 0)))
        table.add_row(
            "Valid IPs",
            str(
                summary.by_type.get("single_ip", 0)
                + summary.by_type.get("cidr", 0)
                + summary.by_type.get("ip_range", 0)
            ),
        )
        table.add_row("Valid URLs", str(summary.by_type.get("url", 0)))
        table.add_row("Valid ASNs", str(summary.by_type.get("asn", 0)))
        table.add_row("Invalid entries", str(summary.invalid_entries))
        table.add_row("Duplicates removed", str(summary.duplicates_removed))
        console.print(table)
        if summary.invalid_values:
            invalid_table = Table(title="Invalid Scope Entries")
            invalid_table.add_column("Value")
            for value in summary.invalid_values:
                invalid_table.add_row(value)
            console.print(invalid_table)
    else:
        _emit_payload(console, payload, output_format, event="scope.validate")


@profile_app.command("show")
def profile_show(
    ctx: typer.Context,
    profile: str = typer.Argument(..., help="Profile name."),
    config: str | None = typer.Option(None, "--config", "-c"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    path = _profile_path(profile)
    if not path.exists():
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            f"Unknown profile '{profile}'.",
            suggestion=f"Available profiles: {', '.join(_profile_names())}",
        )
    effective = load_config(profile=profile, user_config_path=config)
    risk_mode, risk_controls = resolve_risk_mode(profile_name=profile, config=effective, requested_mode=None)
    effective["risk_mode_controls"] = risk_controls
    modules = _profile_module_map(effective)
    enabled = sorted(name for name, state in modules.items() if state)
    disabled = sorted(name for name, state in modules.items() if not state)
    payload = {
        "profile": profile,
        "path": str(path),
        "description": effective.get("profile", {}).get("description", ""),
        "concurrency": effective.get("profile", {}).get("concurrency"),
        "max_noise_score": effective.get("profile", {}).get(
            "max_noise_score",
            effective.get("policy", {}).get("max_noise_score"),
        ),
        "risk_mode": risk_mode,
        "enabled_modules": enabled,
        "disabled_modules": disabled,
    }
    if output_format == "text":
        console.print(f"[bold]Profile:[/bold] {profile}")
        if payload["description"]:
            console.print(payload["description"])
        console.print(f"Path: {path}")
        console.print(f"Concurrency: {payload['concurrency']}")
        console.print(f"Max Noise: {payload['max_noise_score']}")
        console.print(f"Risk Mode: {payload['risk_mode']}")
        enabled_table = Table(title="Enabled Modules")
        enabled_table.add_column("Module")
        for name in enabled:
            enabled_table.add_row(name)
        console.print(enabled_table)
        disabled_table = Table(title="Disabled Modules")
        disabled_table.add_column("Module")
        for name in disabled:
            disabled_table.add_row(name)
        console.print(disabled_table)
    else:
        _emit_payload(console, payload, output_format, event="profile.show")


@profile_app.command("edit")
def profile_edit(
    ctx: typer.Context,
    profile: str = typer.Argument(..., help="Profile name."),
    editor: str | None = typer.Option(None, "--editor", help="Editor executable to launch."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    path = _profile_path(profile)
    if not path.exists():
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            f"Unknown profile '{profile}'.",
            suggestion=f"Available profiles: {', '.join(_profile_names())}",
        )
    editor_cmd = editor or os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor_cmd:
        editor_cmd = "notepad" if os.name == "nt" else "nano"
    try:
        completed = subprocess.run([editor_cmd, str(path)], check=False)
    except FileNotFoundError as exc:
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            f"Editor '{editor_cmd}' was not found.",
            detail=str(exc),
        )
        return
    payload = {"profile": profile, "path": str(path), "editor": editor_cmd, "exit_code": completed.returncode}
    if output_format == "text":
        console.print(f"Opened profile [cyan]{profile}[/cyan] in [cyan]{editor_cmd}[/cyan]: {path}")
    else:
        _emit_payload(console, payload, output_format, event="profile.edit")


@app.command("plan-diff")
def plan_diff(
    ctx: typer.Context,
    profile_a: str = typer.Argument(..., help="Left-hand profile."),
    profile_b: str = typer.Argument(..., help="Right-hand profile."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target input for plan comparison."),
    targets: list[str] = typer.Option(
        [],
        "--targets",
        help="Repeatable target source. Accepts a file path or a literal target value.",
    ),
    scope_file: str | None = typer.Option(None, "--scope-file", help="Path to scope file."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_target = _resolve_target_input(
            target,
            scope_file,
            targets,
            interactive=False,
            console=console,
        )
        temp_output_dir = tempfile.mkdtemp(prefix="attackcastle_plan_diff_")
        left_bundle, _ = build_scan_plan(
            ScanOptions(target_input=resolved_target, output_directory=temp_output_dir, profile=profile_a, dry_run=True),
            console=console,
        )
        right_bundle, _ = build_scan_plan(
            ScanOptions(target_input=resolved_target, output_directory=temp_output_dir, profile=profile_b, dry_run=True),
            console=console,
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Plan diff failed.", detail=str(exc))
        return

    left_items = {item["key"]: item for item in left_bundle["plan_payload"]["items"]}
    right_items = {item["key"]: item for item in right_bundle["plan_payload"]["items"]}
    rows: list[dict[str, Any]] = []
    for key in sorted(set(left_items) | set(right_items)):
        left = left_items.get(key)
        right = right_items.get(key)
        if left == right:
            continue
        rows.append(
            {
                "task": key,
                "profile_a_selected": bool(left.get("selected")) if left else False,
                "profile_b_selected": bool(right.get("selected")) if right else False,
                "profile_a_reason": left.get("reason", "-") if left else "-",
                "profile_b_reason": right.get("reason", "-") if right else "-",
            }
        )
    payload = {
        "profile_a": profile_a,
        "profile_b": profile_b,
        "target_input": resolved_target,
        "differences": rows,
        "difference_count": len(rows),
    }
    if output_format == "text":
        table = Table(title=f"Plan Diff: {profile_a} vs {profile_b}")
        table.add_column("Task")
        table.add_column(profile_a)
        table.add_column(profile_b)
        table.add_column(f"{profile_a} reason")
        table.add_column(f"{profile_b} reason")
        for row in rows:
            table.add_row(
                row["task"],
                "yes" if row["profile_a_selected"] else "no",
                "yes" if row["profile_b_selected"] else "no",
                row["profile_a_reason"],
                row["profile_b_reason"],
            )
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="plan.diff")


@app.command("summary")
def summary(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_data = _load_run_data(resolved_run_dir)
        confirmed = [item for item in run_data.findings if item.status == "confirmed" and not item.suppressed]
        payload = {
            "run_dir": str(resolved_run_dir),
            "targets": len(run_data.scope),
            "open_ports": len([item for item in run_data.services if item.state == "open"]),
            "web_apps": len(run_data.web_apps),
            "findings": len(confirmed),
        }
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Summary failed.", detail=str(exc))
        return

    if output_format == "text":
        table = Table(title="Quick Summary")
        table.add_column("Metric")
        table.add_column("Value")
        for key, value in payload.items():
            if key == "run_dir":
                continue
            table.add_row(key.replace("_", " ").title(), str(value))
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="summary")


@app.command(
    help=(
        "Run preflight checks for dependencies, configuration, templates, and output path.\n\n"
        "Example:\n"
        "  attackcastle doctor --profile cautious --output-dir ./output"
    )
)
def doctor(
    ctx: typer.Context,
    profile: str = typer.Option("prototype", "--profile", "-p"),
    config: str | None = typer.Option(None, "--config", "-c"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as failures."),
    install_missing: bool = typer.Option(
        False,
        "--install-missing",
        help="Install missing external dependencies with apt-get before finishing checks.",
    ),
    yes: bool = typer.Option(False, "--yes", help="Auto-confirm apt installs (passes -y to apt-get install)."),
    output_format: str = typer.Option(
        "text",
        "--output-format",
        help="CLI output format: text|json|ndjson.",
    ),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    checks: list[dict[str, Any]] = []
    py_ok = sys.version_info >= (3, 12)
    checks.append(
        {
            "check": "python_version",
            "status": "pass" if py_ok else "fail",
            "detail": f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "suggestion": "Use Python 3.12+." if not py_ok else None,
            "severity": "fail" if not py_ok else "pass",
        }
    )
    dependency_rows = _external_dependency_rows()
    install_summary: dict[str, Any] | None = None
    if install_missing and _missing_dependency_rows(dependency_rows):
        install_support = dependency_install_support()
        if not install_support.supported:
            _exit_with_error(
                console,
                output_format=output_format,
                code=ExitCode.DEPENDENCY_ERROR,
                message="Automatic dependency installation is not available in this environment.",
                detail=install_support.reason,
                suggestion="Install the required tools manually, then re-run doctor.",
            )
        install_summary = _install_dependencies_with_apt(
            console=console,
            output_format=output_format,
            rows=dependency_rows,
            assume_yes=yes,
        )
        dependency_rows = _external_dependency_rows()

    for row in dependency_rows:
        checks.append(
            {
                "check": row["check"],
                "status": "pass" if row["available"] else "warn",
                "detail": row["resolved_path"] or f"{row['command']} not found in PATH",
                "suggestion": None if row["available"] else row["suggestion"],
                "severity": "pass" if row["available"] else "warn",
            }
        )

    if install_summary is not None:
        checks.append(
            {
                "check": "dependency_auto_install",
                "status": "pass" if not install_summary.get("error") else "fail",
                "detail": (
                    "installed: "
                    + (
                        ", ".join(install_summary.get("installed_packages", []))
                        if install_summary.get("installed_packages")
                        else "none"
                    )
                ),
                "suggestion": (
                    f"Failed packages: {', '.join(install_summary.get('failed_packages', []))}"
                    if install_summary.get("failed_packages")
                    else install_summary.get("error")
                ),
                "severity": "pass" if not install_summary.get("error") else "fail",
            }
        )

    readiness = assess_readiness(
        profile=profile,
        user_config_path=config,
        dependency_rows=dependency_rows,
    )
    checks.append(
        {
            "check": "launch_readiness",
            "status": "pass" if readiness.status == "ready" else "warn",
            "detail": f"status={readiness.status}; missing_tools={', '.join(readiness.missing_tools) or 'none'}",
            "suggestion": readiness.recommended_actions[0] if readiness.recommended_actions else None,
            "severity": "pass" if readiness.status == "ready" else "warn",
        }
    )

    dependency_paths: dict[str, str | None] = {
        str(row["command"]): row.get("resolved_path") for row in dependency_rows
    }
    nmap_path = dependency_paths.get("nmap")
    if nmap_path:
        try:
            proc = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, check=False, timeout=3)
            version_line = (proc.stdout or "").splitlines()[0] if proc.stdout else "nmap available"
            checks.append(
                {
                    "check": "nmap_version",
                    "status": "pass" if proc.returncode == 0 else "warn",
                    "detail": version_line,
                    "suggestion": "Verify nmap installation integrity." if proc.returncode != 0 else None,
                    "severity": "pass" if proc.returncode == 0 else "warn",
                }
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                {
                    "check": "nmap_version",
                    "status": "warn",
                    "detail": str(exc),
                    "suggestion": "Verify nmap is callable from PATH.",
                    "severity": "warn",
                }
            )
    try:
        loaded = load_config(profile=profile, user_config_path=config)
        checks.append(
            {
                "check": "config_load",
                "status": "pass",
                "detail": f"active_profile={loaded.get('active_profile')}",
                "suggestion": None,
                "severity": "pass",
            }
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(
            {
                "check": "config_load",
                "status": "fail",
                "detail": str(exc),
                "suggestion": "Validate profile name and YAML syntax.",
                "severity": "fail",
            }
        )
    template_dir = Path(__file__).resolve().parent / "findings" / "templates"
    issues = lint_templates(template_dir)
    checks.append(
        {
            "check": "template_schema",
            "status": "pass" if not issues else "fail",
            "detail": "OK" if not issues else "; ".join(issues[:5]),
            "suggestion": "Fix template schema violations." if issues else None,
            "severity": "fail" if issues else "pass",
        }
    )
    try:
        import socket

        socket.getaddrinfo("example.com", 443)
        checks.append(
            {
                "check": "dns_resolution",
                "status": "pass",
                "detail": "example.com resolved",
                "suggestion": None,
                "severity": "pass",
            }
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(
            {
                "check": "dns_resolution",
                "status": "warn",
                "detail": str(exc),
                "suggestion": "Check DNS/network connectivity before scanning.",
                "severity": "warn",
            }
        )
    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    writable = True
    detail = "writable"
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=True, dir=out_path, encoding="utf-8") as handle:
            handle.write("attackcastle-doctor")
            handle.flush()
    except Exception as exc:  # noqa: BLE001
        writable = False
        detail = str(exc)
    checks.append(
        {
            "check": "output_directory",
            "status": "pass" if writable else "fail",
            "detail": str(out_path) if writable else detail,
            "suggestion": "Use a writable output directory." if not writable else None,
            "severity": "fail" if not writable else "pass",
        }
    )

    failed = [item for item in checks if item["severity"] == "fail"]
    warned = [item for item in checks if item["severity"] == "warn"]
    payload = {
        "status": "ok" if not failed else "error",
        "checks": checks,
        "readiness": readiness.to_dict(),
        "failed_count": len(failed),
        "warn_count": len(warned),
        "ready": len(failed) == 0 and (len(warned) == 0 if strict else True),
    }
    if output_format == "text":
        table = Table(title="Doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        table.add_column("Suggestion")
        for item in checks:
            table.add_row(item["check"], item["status"], str(item["detail"]), item["suggestion"] or "-")
        console.print(table)
        _render_readiness_panel(console, readiness, title="Environment Readiness")
    else:
        _emit_payload(console, payload, output_format, event="doctor.completed")
    if failed:
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))
    if warned and strict:
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))
    if warned:
        raise typer.Exit(code=int(ExitCode.PARTIAL_SUCCESS))


@run_app.command("status")
def run_status(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None or not resolved_run_dir.exists():
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        summary_path = resolved_run_dir / "data" / "run_summary.json"
        metrics_path = resolved_run_dir / "data" / "run_metrics.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
        metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
        lock = run_store.lock_details()
        control = run_store.read_control()
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not load run status.",
            detail=str(exc),
            suggestion="Check --run-id/--run-dir and output path.",
        )
        return

    payload = {
        "run_dir": str(resolved_run_dir),
        "summary": summary,
        "metrics": metrics,
        "lock": lock,
        "control": control,
    }
    if output_format == "text":
        table = Table(title="Run Status")
        table.add_column("Field")
        table.add_column("Value")
        for key in ("run_id", "state", "started_at", "ended_at", "finding_count", "warning_count", "error_count"):
            if key in summary:
                table.add_row(key, str(summary.get(key)))
        table.add_row("run_dir", str(resolved_run_dir))
        table.add_row("locked", "yes" if lock.get("exists") else "no")
        table.add_row("control_action", str((control or {}).get("action", "none")))
        if lock.get("exists"):
            table.add_row("lock_age_seconds", f"{float(lock.get('age_seconds', 0.0)):.1f}")
            table.add_row("lock_pid", str(lock.get("pid")))
            table.add_row("lock_process_alive", str(lock.get("process_alive")))
        if metrics:
            table.add_row("duration_seconds", f"{float(metrics.get('duration_seconds', 0.0)):.1f}")
            table.add_row("retries_total", str(metrics.get("retries_total", 0)))
        console.print(table)
        if lock.get("exists"):
            render_next_steps(
                console,
                [
                    f"attackcastle run unlock --stale --run-dir {resolved_run_dir}",
                    f"attackcastle run resume --run-dir {resolved_run_dir}",
                ],
            )
    else:
        _emit_payload(console, payload, output_format, event="run.status")


@run_app.command("resume")
def run_resume(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    config: str | None = typer.Option(None, "--config", "-c"),
    audience: str = typer.Option("consultant", "--audience"),
    interactive: bool = typer.Option(True, "--interactive/--non-interactive"),
    yes: bool = typer.Option(False, "--yes"),
    verbosity: int = typer.Option(0, "--verbose", "-v", count=True),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None or not resolved_run_dir.exists():
            raise typer.BadParameter("Run directory was not found.")
        target_input, resume_profile = _load_resume_context(resolved_run_dir)
        _guard_profile_risk(
            profile=resume_profile,
            max_ports=None,
            yes=yes,
            interactive=interactive,
            console=console,
        )
        outcome = run_scan(
            target_input=target_input,
            output_directory=str(resolved_run_dir.parent),
            profile=resume_profile,
            user_config_path=config,
            verbose=verbosity > 0,
            verbosity=verbosity,
            console=console,
            audience=audience,
            resume_run_dir=str(resolved_run_dir),
            rich_ui=(output_format == "text" and bool(getattr(console, "is_terminal", False))),
            emit_plain_logs=(output_format == "text" and ux.ui_mode == "operator" and not ux.quiet),
        )
    except ValidationError as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Resume validation failed.",
            detail=str(exc),
        )
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Resume failed.",
            detail=str(exc),
        )
        return

    candidate_count = _load_candidate_count(outcome.json_path)
    if output_format == "text":
        _render_scan_summary(console, outcome, candidate_count=candidate_count, role=ux.role)
        if not ux.quiet:
            render_next_steps(
                console,
                [
                    f"attackcastle run timeline --run-dir {outcome.run_dir}",
                    f"attackcastle findings triage --run-dir {outcome.run_dir}",
                ],
            )
    else:
        _emit_payload(console, _build_scan_payload(outcome, candidate_count), output_format, event="run.resumed")
    exit_code = _exit_code_for_outcome(outcome)
    if exit_code != ExitCode.OK:
        raise typer.Exit(code=int(exit_code))


@run_app.command("unlock")
def run_unlock(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    stale: bool = typer.Option(False, "--stale", help="Only unlock if stale checks pass."),
    max_age_minutes: int = typer.Option(30, "--max-age-minutes", help="Staleness threshold."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    if not stale:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Refusing unlock without --stale safeguard.",
            suggestion="Use `attackcastle run unlock --stale --run-id <id>`.",
        )
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None or not resolved_run_dir.exists():
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        unlocked, reason, details = run_store.unlock_if_stale(max_age_minutes=max_age_minutes)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Unable to evaluate lock.",
            detail=str(exc),
        )
        return

    payload = {
        "run_dir": str(resolved_run_dir),
        "unlocked": unlocked,
        "reason": reason,
        "details": details,
    }
    if output_format == "text":
        if unlocked:
            console.print(f"[green]Lock removed:[/green] {details.get('path')}")
        elif reason == "no_lock":
            console.print("[yellow]No lock file found.[/yellow]")
        elif reason == "lock_not_stale":
            console.print("[yellow]Lock exists but is not stale under the requested threshold.[/yellow]")
        else:
            console.print(f"[yellow]No action taken ({reason}).[/yellow]")
    else:
        _emit_payload(console, payload, output_format, event="run.unlock")
    if not unlocked and reason == "lock_not_stale":
        raise typer.Exit(code=int(ExitCode.VALIDATION_ERROR))


@run_app.command("pause")
def run_pause(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    reason: str = typer.Option("operator_requested_pause", "--reason"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        control_path = run_store.write_control(
            "pause",
            {"reason": reason, "timestamp": now_utc().isoformat()},
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Pause request failed.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "action": "pause", "control_path": str(control_path)}
    if output_format == "text":
        console.print(f"Pause requested for run: [cyan]{resolved_run_dir}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="run.pause")


@run_app.command("continue")
def run_continue_command(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        run_store.write_control("resume", {"timestamp": now_utc().isoformat()})
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Continue request failed.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "action": "resume"}
    if output_format == "text":
        console.print(f"Resume requested for run: [cyan]{resolved_run_dir}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="run.continue")


@run_app.command("stop")
def run_stop(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    reason: str = typer.Option("operator_requested_stop", "--reason"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        control_path = run_store.write_control(
            "stop",
            {"reason": reason, "timestamp": now_utc().isoformat()},
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Stop request failed.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "action": "stop", "control_path": str(control_path)}
    if output_format == "text":
        console.print(f"Stop requested for run: [cyan]{resolved_run_dir}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="run.stop")


@run_app.command("skip-task")
def run_skip_task(
    ctx: typer.Context,
    task_key: str = typer.Option(..., "--task-key"),
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        control_path = run_store.write_control(
            "skip_task",
            {"task_key": task_key, "timestamp": now_utc().isoformat()},
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Skip-task request failed.", detail=str(exc))
        return

    payload = {
        "run_dir": str(resolved_run_dir),
        "action": "skip_task",
        "task_key": task_key,
        "control_path": str(control_path),
    }
    if output_format == "text":
        console.print(f"Skip requested: [cyan]{task_key}[/cyan] on run [cyan]{resolved_run_dir}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="run.skip_task")


@run_app.command("timeline")
def run_timeline(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    limit: int = typer.Option(200, "--limit", help="Maximum events to show."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        timeline_file = resolved_run_dir / "data" / "run_timeline.json"
        if timeline_file.exists():
            loaded = json.loads(timeline_file.read_text(encoding="utf-8"))
            events = loaded if isinstance(loaded, list) else []
        else:
            events = _read_jsonl(resolved_run_dir / "logs" / "audit.jsonl")
        sliced = events[-max(1, limit) :]
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Could not load run timeline.",
            detail=str(exc),
        )
        return

    payload = {"run_dir": str(resolved_run_dir), "event_count": len(sliced), "events": sliced}
    if output_format == "text":
        table = Table(title="Run Timeline")
        table.add_column("Timestamp")
        table.add_column("Event")
        table.add_column("Summary")
        for event in sliced:
            payload_text = str(event.get("payload", {}))
            table.add_row(
                str(event.get("timestamp")),
                str(event.get("event_type")),
                payload_text[:100],
            )
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="run.timeline")


@run_app.command("dashboard")
def run_dashboard(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    follow: bool = typer.Option(False, "--follow", help="Continuously refresh while run is active."),
    interval_seconds: float = typer.Option(1.5, "--interval-seconds"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory not found.")
        summary_path = resolved_run_dir / "data" / "run_summary.json"
        metrics_path = resolved_run_dir / "data" / "run_metrics.json"
        plan_path = resolved_run_dir / "data" / "plan.json"
        scan_data_path = resolved_run_dir / "data" / "scan_data.json"
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Could not build run dashboard.",
            detail=str(exc),
        )
        return

    run_store = RunStore.from_existing(resolved_run_dir)

    def load_payload() -> dict[str, Any]:
        summary_raw, summary_error = _load_json_mapping(summary_path, label="Dashboard summary")
        metrics_raw, metrics_error = _load_json_mapping(metrics_path, label="Dashboard metrics")
        plan, plan_error = _load_json_mapping(plan_path, label="Dashboard plan")
        scan_data, scan_data_error = _load_json_mapping(scan_data_path, label="Dashboard scan data")
        plan_summary, plan_summary_errors = _build_dashboard_plan_summary(plan, scan_data=scan_data)
        safety, safety_error = _coerce_dashboard_mapping(
            plan.get("safety"),
            label="Dashboard plan",
            field_name="safety",
        )
        mode, mode_error = _coerce_dashboard_mapping(
            plan.get("mode"),
            label="Dashboard plan",
            field_name="mode",
        )
        duration_seconds, duration_error = _coerce_dashboard_float(
            metrics_raw,
            "duration_seconds",
            label="Dashboard metrics",
        )
        task_count, task_count_error = _coerce_dashboard_int(
            metrics_raw,
            "task_count",
            label="Dashboard metrics",
        )
        retries_total, retries_total_error = _coerce_dashboard_int(
            metrics_raw,
            "retries_total",
            label="Dashboard metrics",
        )
        finding_count, finding_error = _coerce_dashboard_int(
            summary_raw,
            "finding_count",
            label="Dashboard summary",
        )
        warning_count, warning_error = _coerce_dashboard_int(
            summary_raw,
            "warning_count",
            label="Dashboard summary",
        )
        error_count, error_count_error = _coerce_dashboard_int(
            summary_raw,
            "error_count",
            label="Dashboard summary",
        )
        summary = {
            "state": summary_raw.get("state"),
            "finding_count": finding_count,
            "warning_count": warning_count,
            "error_count": error_count,
        }
        metrics = {
            "duration_seconds": duration_seconds,
            "task_count": task_count,
            "retries_total": retries_total,
        }
        control, control_error = _load_dashboard_control(run_store)
        read_errors = [
            item
            for item in (
                summary_error,
                metrics_error,
                plan_error,
                scan_data_error,
                *plan_summary_errors,
                safety_error,
                mode_error,
                duration_error,
                task_count_error,
                retries_total_error,
                finding_error,
                warning_error,
                error_count_error,
                control_error,
            )
            if item
        ]
        return {
            "run_dir": str(resolved_run_dir),
            "summary": summary,
            "metrics": metrics,
            "plan_summary": plan_summary,
            "safety": safety,
            "mode": mode,
            "locked": run_store.lock_exists(),
            "control": control,
            "read_errors": read_errors,
        }

    payload = load_payload()
    if output_format == "text":
        while True:
            table = Table(title="Run Dashboard")
            table.add_column("Metric")
            table.add_column("Value")
            table.add_row("state", str(payload["summary"].get("state")))
            table.add_row("locked", "yes" if payload.get("locked") else "no")
            table.add_row("control_action", str(payload.get("control", {}).get("action", "none")))
            table.add_row("risk_mode", str(payload.get("plan_summary", {}).get("risk_mode", "unknown")))
            table.add_row("output_mode", str(payload.get("plan_summary", {}).get("output_mode", "standard")))
            table.add_row("duration_seconds", str(round(float(payload["metrics"].get("duration_seconds", 0.0)), 2)))
            table.add_row("task_count", str(payload["metrics"].get("task_count", 0)))
            table.add_row("retries_total", str(payload["metrics"].get("retries_total", 0)))
            table.add_row("finding_count", str(payload["summary"].get("finding_count")))
            table.add_row("warning_count", str(payload["summary"].get("warning_count")))
            table.add_row("error_count", str(payload["summary"].get("error_count")))
            table.add_row("selected_tasks", str(payload.get("plan_summary", {}).get("selected_task_count", 0)))
            table.add_row("blocked_tasks", str(payload.get("plan_summary", {}).get("blocked_task_count", 0)))
            table.add_row("targets_compiled", str(payload.get("plan_summary", {}).get("host_estimate", 0)))
            table.add_row("tools_scheduled", str(payload.get("plan_summary", {}).get("scheduled_tool_count", 0)))
            table.add_row(
                "noise_budget",
                f"{payload.get('plan_summary', {}).get('expected_noise_total', 0)}/"
                f"{payload.get('plan_summary', {}).get('noise_limit', 0)}",
            )
            if payload.get("read_errors"):
                table.add_row("read_warnings", " | ".join(str(item) for item in payload["read_errors"]))
            console.print(table)
            for read_error in payload.get("read_errors", []):
                console.print(str(read_error))
            if not follow or not payload.get("locked"):
                break
            import time

            time.sleep(max(0.2, float(interval_seconds)))
            payload = load_payload()
    else:
        _emit_payload(console, payload, output_format, event="run.dashboard")


@run_app.command("doctor")
def run_doctor(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    if output_format == "text" and ux.ui_mode == "operator" and not ux.quiet:
        render_banner(console, ux)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory not found.")
        run_store = RunStore.from_existing(resolved_run_dir)
        checks = [
            {
                "check": "run_summary",
                "status": "pass" if (resolved_run_dir / "data" / "run_summary.json").exists() else "fail",
                "detail": str((resolved_run_dir / "data" / "run_summary.json")),
            },
            {
                "check": "scan_data",
                "status": "pass" if (resolved_run_dir / "data" / "scan_data.json").exists() else "warn",
                "detail": str((resolved_run_dir / "data" / "scan_data.json")),
            },
            {
                "check": "checkpoint_manifest",
                "status": "pass" if (resolved_run_dir / "checkpoints" / "manifest.json").exists() else "warn",
                "detail": str((resolved_run_dir / "checkpoints" / "manifest.json")),
            },
            {
                "check": "lock_status",
                "status": "warn" if run_store.lock_exists() else "pass",
                "detail": str(run_store.lock_details()),
            },
        ]
        audit_result = verify_audit_chain(resolved_run_dir / "logs" / "audit.jsonl")
        audit_status = "pass" if audit_result.get("valid") else "warn"
        checks.append(
            {
                "check": "audit_chain",
                "status": audit_status,
                "detail": json.dumps(audit_result),
            }
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Run doctor failed.", detail=str(exc))
        return

    failed = [item for item in checks if item["status"] == "fail"]
    warned = [item for item in checks if item["status"] == "warn"]
    payload = {"run_dir": str(resolved_run_dir), "checks": checks, "failed": len(failed), "warned": len(warned)}
    if output_format == "text":
        table = Table(title="Run Doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for item in checks:
            table.add_row(item["check"], item["status"], item["detail"])
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="run.doctor")

    if failed:
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))
    if warned:
        raise typer.Exit(code=int(ExitCode.PARTIAL_SUCCESS))


@run_app.command("perf")
def run_perf(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory not found.")
        metrics_path = resolved_run_dir / "data" / "run_metrics.json"
        metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Perf metrics unavailable.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "metrics": metrics}
    if output_format == "text":
        stage_table = Table(title="Stage Durations (s)")
        stage_table.add_column("Stage")
        stage_table.add_column("Seconds")
        for stage, value in sorted(metrics.get("stage_durations_seconds", {}).items()):
            stage_table.add_row(stage, f"{float(value):.2f}")
        console.print(stage_table)
        cap_table = Table(title="Capability Durations (s)")
        cap_table.add_column("Capability")
        cap_table.add_column("Seconds")
        for cap, value in sorted(metrics.get("capability_durations_seconds", {}).items()):
            cap_table.add_row(cap, f"{float(value):.2f}")
        console.print(cap_table)
    else:
        _emit_payload(console, payload, output_format, event="run.perf")


@run_app.command("shard-plan")
def run_shard_plan(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", "-t"),
    scope_file: str | None = typer.Option(None, "--scope-file"),
    shards: int = typer.Option(4, "--shards", help="Number of worker shards."),
    output: str | None = typer.Option(None, "--output", help="Optional output JSON file."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_target = _resolve_target_input(target, scope_file, interactive=False, console=console)
        plan = build_shard_plan(resolved_target, max(1, int(shards)))
        output_path = None
        if output:
            output_path = Path(output).expanduser().resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Failed to build shard plan.", detail=str(exc))
        return

    payload = {**plan, "output_path": str(output_path) if output else None}
    if output_format == "text":
        table = Table(title="Distributed Shard Plan")
        table.add_column("Shard")
        table.add_column("Target Count")
        table.add_column("Target Preview")
        for assignment in plan.get("assignments", []):
            targets = assignment.get("targets", [])
            preview = ", ".join(targets[:2])
            if len(targets) > 2:
                preview += ", ..."
            table.add_row(str(assignment.get("shard_id")), str(len(targets)), preview)
        console.print(table)
        if output_path:
            console.print(f"Shard plan written to: [cyan]{output_path}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="run.shard_plan")


@run_app.command("worker")
def run_worker(
    ctx: typer.Context,
    shard_plan: str = typer.Option(..., "--shard-plan", help="Path to shard-plan JSON."),
    shard_id: int = typer.Option(..., "--shard-id"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    profile: str = typer.Option("standard", "--profile", "-p"),
    risk_mode: str | None = typer.Option(None, "--risk-mode"),
    config: str | None = typer.Option(None, "--config", "-c"),
    interactive: bool = typer.Option(False, "--interactive/--non-interactive"),
    yes: bool = typer.Option(True, "--yes/--no-yes"),
    verbosity: int = typer.Option(0, "--verbose", "-v", count=True),
    audience: str = typer.Option("consultant", "--audience"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    ux = _ctx_ux(ctx)
    console = _console(ctx, output_format)
    try:
        plan_path = Path(shard_plan).expanduser().resolve()
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
        assignments = payload.get("assignments", []) if isinstance(payload, dict) else []
        assignment = next(
            (item for item in assignments if int(item.get("shard_id", -1)) == int(shard_id)),
            None,
        )
        if not assignment:
            raise ValueError(f"Shard id {shard_id} not found in plan.")
        target_input = str(assignment.get("target_input") or "").strip()
        if not target_input:
            raise ValueError(f"Shard id {shard_id} has empty target set.")

        _guard_profile_risk(
            profile=profile,
            max_ports=None,
            yes=yes,
            interactive=interactive,
            console=console,
        )
        outcome = run_scan(
            target_input=target_input,
            output_directory=output_dir,
            profile=profile,
            risk_mode=risk_mode,
            user_config_path=config,
            verbose=verbosity > 0,
            verbosity=verbosity,
            console=console,
            audience=audience,
            rich_ui=(output_format == "text" and bool(getattr(console, "is_terminal", False))),
            emit_plain_logs=(output_format == "text" and ux.ui_mode == "operator" and not ux.quiet),
        )
        RunStore.from_existing(outcome.run_dir).write_json(
            "data/distributed_worker.json",
            {
                "shard_plan": str(plan_path),
                "shard_id": int(shard_id),
                "target_count": len(assignment.get("targets", [])),
            },
        )
    except ValidationError as exc:
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Worker run validation failed.", detail=str(exc))
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.INTERNAL_ERROR, "Worker run failed.", detail=str(exc))
        return

    candidate_count = _load_candidate_count(outcome.json_path)
    if output_format == "text":
        _render_scan_summary(console, outcome, candidate_count=candidate_count, role=ux.role)
    else:
        _emit_payload(console, _build_scan_payload(outcome, candidate_count), output_format, event="run.worker")
    exit_code = _exit_code_for_outcome(outcome)
    if exit_code != ExitCode.OK:
        raise typer.Exit(code=int(exit_code))


@run_app.command("queue-init")
def run_queue_init(
    ctx: typer.Context,
    shard_plan: str = typer.Option(..., "--shard-plan", help="Path to shard-plan JSON."),
    queue_dir: str = typer.Option("./output/distributed_queue", "--queue-dir"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        plan_path = Path(shard_plan).expanduser().resolve()
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        queue_path = initialize_worker_queue(plan=plan, queue_dir=Path(queue_dir).expanduser().resolve())
        status = queue_status(Path(queue_dir).expanduser().resolve())
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Failed to initialize queue.", detail=str(exc))
        return

    payload = {"queue_path": str(queue_path), "status": status}
    if output_format == "text":
        console.print(f"Queue initialized at: [cyan]{queue_path}[/cyan]")
        console.print_json(data=status)
    else:
        _emit_payload(console, payload, output_format, event="run.queue_init")


@run_app.command("queue-status")
def run_queue_status(
    ctx: typer.Context,
    queue_dir: str = typer.Option("./output/distributed_queue", "--queue-dir"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        status = queue_status(Path(queue_dir).expanduser().resolve())
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Failed to read queue status.", detail=str(exc))
        return

    if output_format == "text":
        table = Table(title="Distributed Queue Status")
        table.add_column("State")
        table.add_column("Count")
        for state, count in sorted(status.get("counts", {}).items()):
            table.add_row(state, str(count))
        console.print(table)
    else:
        _emit_payload(console, status, output_format, event="run.queue_status")


@run_app.command("queue-claim")
def run_queue_claim(
    ctx: typer.Context,
    worker_id: str = typer.Option(..., "--worker-id"),
    queue_dir: str = typer.Option("./output/distributed_queue", "--queue-dir"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        assignment = claim_next_shard(Path(queue_dir).expanduser().resolve(), worker_id=worker_id)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Failed to claim shard.", detail=str(exc))
        return

    payload = {"worker_id": worker_id, "assignment": assignment}
    if output_format == "text":
        if not assignment:
            console.print("No pending shard assignment available.")
        else:
            console.print_json(data=assignment)
    else:
        _emit_payload(console, payload, output_format, event="run.queue_claim")


@run_app.command("queue-complete")
def run_queue_complete(
    ctx: typer.Context,
    shard_id: int = typer.Option(..., "--shard-id"),
    worker_id: str = typer.Option(..., "--worker-id"),
    status: str = typer.Option("completed", "--status"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    queue_dir: str = typer.Option("./output/distributed_queue", "--queue-dir"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    result_payload: dict[str, Any] = {}
    if run_dir:
        result_payload["run_dir"] = str(Path(run_dir).expanduser().resolve())
    try:
        updated = complete_shard(
            queue_dir=Path(queue_dir).expanduser().resolve(),
            shard_id=shard_id,
            worker_id=worker_id,
            status=status,
            result=result_payload,
        )
        status_payload = queue_status(Path(queue_dir).expanduser().resolve())
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Failed to complete shard.", detail=str(exc))
        return

    payload = {"updated": updated, "status": status_payload}
    if output_format == "text":
        console.print("Shard completion updated." if updated else "No matching running shard was updated.")
        console.print_json(data=status_payload)
    else:
        _emit_payload(console, payload, output_format, event="run.queue_complete")


@validate_app.command("targets")
def validate_targets_cmd(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target", "-t"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        parsed = parse_target_input(target)
        validate_targets(parsed)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Target validation failed.",
            detail=str(exc),
        )
        return
    payload = {"status": "valid", "parsed_target_count": len(parsed)}
    if output_format == "text":
        console.print(f"[green]Valid[/green] ({len(parsed)} parsed target(s))")
    else:
        _emit_payload(console, payload, output_format, event="validate.targets")


@templates_app.command("validate")
def templates_validate(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    template_dir = Path(__file__).resolve().parent / "findings" / "templates"
    issues = lint_templates(template_dir)
    payload = {"template_dir": str(template_dir), "issues": issues}
    if issues:
        if output_format == "text":
            console.print("[red]Template issues found:[/red]")
            for issue in issues:
                console.print(f"- {issue}")
        else:
            _emit_payload(console, payload, output_format, event="templates.validate")
        raise typer.Exit(code=int(ExitCode.VALIDATION_ERROR))
    if output_format == "text":
        console.print("[green]All templates are valid.[/green]")
    else:
        _emit_payload(console, {"status": "ok", **payload}, output_format, event="templates.validate")


@templates_app.command("list")
def templates_list(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    template_dir = Path(__file__).resolve().parent / "findings" / "templates"
    rows = sorted(path.name for path in template_dir.glob("*.json"))
    payload = {"templates": rows, "template_count": len(rows)}
    if output_format == "text":
        for row in rows:
            console.print(f"- {row}")
    else:
        _emit_payload(console, payload, output_format, event="templates.list")


@plugins_app.command("list")
def plugins_list(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    adapters = [
        CVEEnricherAdapter(),
        SubdomainEnumAdapter(),
        DNSAdapter(),
        NmapAdapter(),
        WebProbeAdapter(),
        WebDiscoveryAdapter(),
        TLSAdapter(),
        ServiceExposureAdapter(),
        WhatWebAdapter(),
        NiktoAdapter(),
        NucleiAdapter(),
        FrameworkChecksAdapter(),
        WPScanAdapter(),
        SQLMapAdapter(),
    ]
    rows = []
    for adapter in adapters:
        command = _adapter_command(adapter.name)
        available = bool(shutil.which(command)) if command != "python" else True
        rows.append(
            {
                "name": adapter.name,
                "capability": getattr(adapter, "capability", "-"),
                "noise_score": getattr(adapter, "noise_score", "-"),
                "cost_score": getattr(adapter, "cost_score", "-"),
                "available": available,
                "command": command,
            }
        )
    if output_format == "text":
        table = Table(title="Registered Plugins")
        table.add_column("Name")
        table.add_column("Capability")
        table.add_column("Noise")
        table.add_column("Cost")
        table.add_column("Command")
        table.add_column("Available")
        for row in rows:
            table.add_row(
                str(row["name"]),
                str(row["capability"]),
                str(row["noise_score"]),
                str(row["cost_score"]),
                str(row["command"]),
                "yes" if row["available"] else "no",
            )
        console.print(table)
    else:
        _emit_payload(console, {"plugins": rows}, output_format, event="plugins.list")


@plugins_app.command("doctor")
def plugins_doctor(
    ctx: typer.Context,
    install_missing: bool = typer.Option(
        False,
        "--install-missing",
        help="Install missing plugin dependencies with apt-get before reporting health.",
    ),
    yes: bool = typer.Option(False, "--yes", help="Auto-confirm apt installs (passes -y to apt-get install)."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    adapters = [
        CVEEnricherAdapter(),
        SubdomainEnumAdapter(),
        DNSAdapter(),
        NmapAdapter(),
        WebProbeAdapter(),
        WebDiscoveryAdapter(),
        TLSAdapter(),
        ServiceExposureAdapter(),
        WhatWebAdapter(),
        NiktoAdapter(),
        NucleiAdapter(),
        FrameworkChecksAdapter(),
        WPScanAdapter(),
        SQLMapAdapter(),
    ]
    template_dir = Path(__file__).resolve().parent / "findings" / "templates"
    template_names = [path.name.lower() for path in template_dir.glob("*.json")]
    dependent_hints = {
        "subdomain_enumeration": [name for name in template_names if "dns" in name or "exposure" in name],
        "dns_resolution": [name for name in template_names if "dns" in name],
        "network_port_scan": [name for name in template_names if "tls" in name or "http" in name],
        "web_probe": [name for name in template_names if "wordpress" in name or "http" in name],
        "web_discovery": [name for name in template_names if "http" in name or "sql" in name],
        "tls_probe": [name for name in template_names if "tls" in name],
        "service_exposure_checks": [name for name in template_names if "exposure" in name or "mail" in name],
        "web_fingerprint": [name for name in template_names if "wordpress" in name],
        "web_vuln_scan": [name for name in template_names if "http" in name or "wordpress" in name],
        "web_template_scan": [name for name in template_names if "nuclei" in name or "exposure" in name],
        "web_injection_scan": [name for name in template_names if "sql" in name],
        "cms_wordpress_scan": [name for name in template_names if "wordpress" in name],
        "cms_framework_scan": [name for name in template_names if "wordpress" in name or "nuclei" in name],
        "vuln_enrichment": [name for name in template_names if "vuln" in name or "exposed" in name],
    }
    install_summary: dict[str, Any] | None = None

    def _build_rows() -> list[dict[str, Any]]:
        dependency_lookup = {row["command"]: row for row in _external_dependency_rows()}
        plugin_rows: list[dict[str, Any]] = []
        for adapter in adapters:
            command = _adapter_command(adapter.name)
            dependency_row = dependency_lookup.get(command)
            available = True if command == "python" else bool(dependency_row and dependency_row["available"])
            health = "healthy" if available else "missing_dependency"
            plugin_rows.append(
                {
                    "name": adapter.name,
                    "capability": adapter.capability,
                    "command": command,
                    "apt_package": dependency_row["apt_package"] if dependency_row else None,
                    "available": available,
                    "health": health,
                    "known_limitations": [] if available else [f"{command} not found in PATH"],
                    "dependent_templates": dependent_hints.get(adapter.capability, []),
                }
            )
        return plugin_rows

    rows = _build_rows()
    if install_missing:
        install_support = dependency_install_support()
        if not install_support.supported and any(not row["available"] for row in rows):
            _exit_with_error(
                console,
                output_format=output_format,
                code=ExitCode.DEPENDENCY_ERROR,
                message="Automatic dependency installation is not available in this environment.",
                detail=install_support.reason,
                suggestion="Install the required tools manually, then re-run plugin doctor.",
            )
        dependency_lookup = {row["command"]: row for row in _external_dependency_rows()}
        requested_rows: list[dict[str, Any]] = []
        seen_commands: set[str] = set()
        for row in rows:
            if row["command"] == "python" or row["available"]:
                continue
            dependency_row = dependency_lookup.get(row["command"])
            if not dependency_row:
                continue
            command_name = str(dependency_row["command"])
            if command_name in seen_commands:
                continue
            seen_commands.add(command_name)
            requested_rows.append(dependency_row)
        if requested_rows:
            install_summary = _install_dependencies_with_apt(
                console=console,
                output_format=output_format,
                rows=requested_rows,
                assume_yes=yes,
            )
            rows = _build_rows()

    readiness = assess_readiness(dependency_rows=_external_dependency_rows())
    payload = {"plugins": rows, "readiness": readiness.to_dict()}
    if install_summary is not None:
        payload["dependency_install"] = install_summary
    if output_format == "text":
        table = Table(title="Plugin Doctor")
        table.add_column("Plugin")
        table.add_column("Capability")
        table.add_column("Health")
        table.add_column("Dependency")
        table.add_column("Template Impact")
        for row in rows:
            table.add_row(
                row["name"],
                row["capability"],
                row["health"],
                row["command"],
                ", ".join(row["dependent_templates"][:3]) or "-",
            )
        console.print(table)
        _render_readiness_panel(console, readiness, title="Plugin Readiness")
    else:
        _emit_payload(console, payload, output_format, event="plugins.doctor")

    missing = [row for row in rows if not row["available"]]
    if install_summary and install_summary.get("error"):
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))
    if missing:
        raise typer.Exit(code=int(ExitCode.PARTIAL_SUCCESS))


@plugins_app.command("install-missing")
def plugins_install_missing(
    ctx: typer.Context,
    yes: bool = typer.Option(False, "--yes", help="Auto-confirm apt installs (passes -y to apt-get install)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show install intent without running apt-get."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    install_support = dependency_install_support()
    dependency_rows = _external_dependency_rows()
    missing_rows = _missing_dependency_rows(dependency_rows)
    if not missing_rows:
        payload = {"status": "ok", "missing_count": 0, "message": "All known external dependencies are present."}
        if output_format == "text":
            console.print("[green]All known external dependencies are already installed.[/green]")
        else:
            _emit_payload(console, payload, output_format, event="plugins.install_missing")
        return
    if not install_support.supported and not dry_run:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.DEPENDENCY_ERROR,
            message="Automatic dependency installation is not available in this environment.",
            detail=install_support.reason,
            suggestion="Install the required tools manually, then re-run this command.",
        )

    summary = _install_dependencies_with_apt(
        console=console,
        output_format=output_format,
        rows=dependency_rows,
        assume_yes=yes,
        dry_run=dry_run,
    )
    refreshed_rows = _external_dependency_rows()
    remaining = [row["command"] for row in _missing_dependency_rows(refreshed_rows)]
    payload = {
        "status": "ok" if dry_run or (not summary.get("error") and not remaining) else "error",
        "attempted_packages": summary.get("packages", []),
        "installed_packages": summary.get("installed_packages", []),
        "failed_packages": summary.get("failed_packages", []),
        "remaining_missing_commands": remaining,
        "error": summary.get("error"),
        "dry_run": dry_run,
    }
    if output_format == "text":
        table = Table(title="Install Missing Dependencies")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("attempted_packages", ", ".join(payload["attempted_packages"]) or "-")
        table.add_row("installed_packages", ", ".join(payload["installed_packages"]) or "-")
        table.add_row("failed_packages", ", ".join(payload["failed_packages"]) or "-")
        table.add_row("remaining_missing_commands", ", ".join(payload["remaining_missing_commands"]) or "-")
        table.add_row("error", str(payload["error"] or "-"))
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="plugins.install_missing")

    if payload["status"] != "ok" and not dry_run:
        raise typer.Exit(code=int(ExitCode.DEPENDENCY_ERROR))


@adapters_app.command("list")
def adapters_list(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    plugins_list(ctx=ctx, output_format=output_format)


@config_app.command("show-effective")
def config_show_effective(
    ctx: typer.Context,
    profile: str = typer.Option("prototype", "--profile", "-p"),
    config: str | None = typer.Option(None, "--config", "-c"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    effective = load_config(profile=profile, user_config_path=config)
    payload = {
        "precedence": "default < profile < user-config < env < CLI flags",
        "sources": effective.get("config_sources", {}),
        "effective_config": redact_sensitive_config(effective),
    }
    if output_format == "text":
        console.print_json(data=payload)
    else:
        _emit_payload(console, payload, output_format, event="config.show_effective")


@config_app.command("explain")
def config_explain(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Dot-path key, e.g. scan.max_ports"),
    profile: str = typer.Option("prototype", "--profile", "-p"),
    config: str | None = typer.Option(None, "--config", "-c"),
    cli_value: str | None = typer.Option(
        None,
        "--cli-value",
        help="Optional CLI override value (YAML parsed) to include in source resolution.",
    ),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        explain_args = {
            "profile": profile,
            "key_path": key,
            "user_config_path": config,
        }
        if cli_value is not None:
            explain_args["cli_override"] = _parse_cli_override(cli_value)
        explanation = explain_config_key(**explain_args)
        explanation = redact_sensitive_config(explanation)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not explain config key.",
            detail=str(exc),
            suggestion="Verify key path format (example: scan.max_ports).",
        )
        return

    if output_format == "text":
        table = Table(title=f"Config Explain: {key}")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("resolved_source", str(explanation.get("source")))
        table.add_row("resolved_value", json.dumps(explanation.get("value"), default=str))
        layer_values = explanation.get("layer_values", {})
        for layer_name in ("default", "profile", "user", "env", "cli"):
            table.add_row(layer_name, json.dumps(layer_values.get(layer_name), default=str))
        console.print(table)
    else:
        _emit_payload(console, explanation, output_format, event="config.explain")


@config_app.command("diff")
def config_diff(
    ctx: typer.Context,
    profile_a: str = typer.Option("prototype", "--profile-a"),
    profile_b: str = typer.Option("standard", "--profile-b"),
    config_a: str | None = typer.Option(None, "--config-a"),
    config_b: str | None = typer.Option(None, "--config-b"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        left = load_config(profile=profile_a, user_config_path=config_a)
        right = load_config(profile=profile_b, user_config_path=config_b)
        left_flat: dict[str, Any] = {}
        right_flat: dict[str, Any] = {}
        _flatten_dict("", left, left_flat)
        _flatten_dict("", right, right_flat)
        keys = sorted(set(left_flat.keys()) | set(right_flat.keys()))
        changes = []
        for key in keys:
            if left_flat.get(key) != right_flat.get(key):
                changes.append({"key": key, "a": left_flat.get(key), "b": right_flat.get(key)})
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Config diff failed.", detail=str(exc))
        return

    payload = {"profile_a": profile_a, "profile_b": profile_b, "change_count": len(changes), "changes": changes}
    if output_format == "text":
        table = Table(title=f"Config Diff: {profile_a} -> {profile_b}")
        table.add_column("Key")
        table.add_column(profile_a)
        table.add_column(profile_b)
        for row in changes:
            table.add_row(row["key"], json.dumps(row["a"], default=str), json.dumps(row["b"], default=str))
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="config.diff")


@config_app.command("simulate")
def config_simulate(
    ctx: typer.Context,
    target: str = typer.Option(..., "--target"),
    profile: str = typer.Option("prototype", "--profile"),
    config: str | None = typer.Option(None, "--config"),
    output_dir: str = typer.Option("./output", "--output-dir"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        options = ScanOptions(
            target_input=target,
            output_directory=output_dir,
            profile=profile,
            user_config_path=config,
            dry_run=True,
            rich_ui=False,
            emit_plain_logs=False,
        )
        bundle, run_store = build_scan_plan(options, console=console)
        plan_payload = bundle["plan_payload"]
        plan_path = run_store.write_json("data/plan.json", plan_payload)
        simulation = {
            "target": target,
            "profile": profile,
            "plan_path": str(plan_path),
            "max_noise_limit": plan_payload.get("max_noise_limit"),
            "items": plan_payload.get("items", []),
            "safety": plan_payload.get("safety", {}),
            "orchestration": {
                "max_total_retries": bundle["config"].get("orchestration", {}).get("max_total_retries"),
                "capability_budgets": bundle["config"].get("orchestration", {}).get("capability_budgets", {}),
            },
        }
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Config simulation failed.",
            detail=str(exc),
        )
        return

    if output_format == "text":
        render_task_graph(console, simulation["items"])
        render_safety_contract(console, {"safety": simulation["safety"], "orchestration": simulation["orchestration"]})
        console.print(f"Plan path: [accent]{simulation['plan_path']}[/accent]")
    else:
        _emit_payload(console, simulation, output_format, event="config.simulate")


@report_app.command("rebuild")
def report_rebuild(
    ctx: typer.Context,
    run_dir: str = typer.Option(..., "--run-dir"),
    audience: str = typer.Option("consultant", "--audience"),
    export_pdf: bool = typer.Option(False, "--pdf"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_report_rebuild_run_dir(run_dir)
        scan_data = _read_required_scan_data(resolved_run_dir)
        run_store = RunStore.from_existing(resolved_run_dir)
        run_data = run_data_from_dict(migrate_payload(scan_data))
        builder = ReportBuilder()
        result = builder.build(
            run_data,
            run_store,
            audience=audience,
            export_csv=True,
            export_json_summary=True,
            export_pdf=export_pdf,
        )
    except typer.BadParameter as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Failed to rebuild report.",
            detail=str(exc),
            suggestion="Point --run-dir at a run_* directory or an output root containing completed runs.",
        )
        return
    except ScanDataLoadError as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Failed to rebuild report.",
            detail=str(exc),
            suggestion=exc.suggestion,
        )
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Failed to rebuild report.",
            detail=str(exc),
            suggestion="Verify data/scan_data.json is readable and matches the expected run schema.",
        )
        return

    payload = {
        "run_dir": str(resolved_run_dir),
        "report_path": str(result["report_path"]),
        "summary_path": str(result["summary_path"]) if result.get("summary_path") else None,
        "csv_paths": [str(path) for path in result.get("csv_paths", [])],
        "pdf_path": str(result["pdf_path"]) if result.get("pdf_path") else None,
    }
    if output_format == "text":
        console.print(f"Run directory: [cyan]{payload['run_dir']}[/cyan]")
        console.print(f"Report rebuilt: [cyan]{payload['report_path']}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="report.rebuild")


@report_app.command("trend")
def report_trend(
    ctx: typer.Context,
    run_dirs: list[str] = typer.Option(..., "--run-dir", help="Repeat for each run directory."),
    output_path: str = typer.Option("./output/trend_report.html", "--output"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        trend = build_trend_report(
            [Path(item).expanduser().resolve() for item in run_dirs],
            Path(output_path).expanduser().resolve(),
        )
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.INTERNAL_ERROR,
            message="Failed to build trend report.",
            detail=str(exc),
        )
        return
    payload = {**trend, "output_path": str(Path(output_path).expanduser().resolve())}
    if output_format == "text":
        console.print_json(data=trend)
        console.print(f"Trend report: [cyan]{payload['output_path']}[/cyan]")
    else:
        _emit_payload(console, payload, output_format, event="report.trend")


@report_app.command("open")
def report_open(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    launch: bool = typer.Option(True, "--launch/--no-launch", help="Open report in default browser."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(
            run_dir=run_dir,
            run_id=run_id,
            output_dir=output_dir,
            required=True,
            validator=lambda path: (path / "reports" / "report.html").exists(),
            search_label="reports/report.html",
        )
        if resolved_run_dir is None:
            raise typer.BadParameter("No run directory available.")
        html_path = resolved_run_dir / "reports" / "report.html"
        if not html_path.exists():
            raise FileNotFoundError(f"No HTML report found at {html_path}.")
        report_path = html_path
        if launch:
            _launch_report_in_browser(report_path)
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not locate/open report artifact.",
            detail=str(exc),
            suggestion="Run `attackcastle report rebuild --run-dir <path>` first.",
        )
        return

    payload = {"run_dir": str(resolved_run_dir), "report_path": str(report_path), "launched": launch}
    if output_format == "text":
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_row("Run ID", resolved_run_dir.name.removeprefix("run_"))
        table.add_row("Path", str(report_path))
        console.print(Panel.fit(table, title="Opening report" if launch else "Report ready", border_style="accent"))
    else:
        _emit_payload(console, payload, output_format, event="report.open")


@artifacts_app.command("tree")
def artifacts_tree(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None or not resolved_run_dir.exists():
            raise typer.BadParameter("Run directory was not found.")
        file_paths = [
            path.relative_to(resolved_run_dir).as_posix()
            for path in resolved_run_dir.rglob("*")
            if path.is_file()
        ]
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not render artifacts tree.",
            detail=str(exc),
        )
        return

    payload = {"run_dir": str(resolved_run_dir), "files": sorted(file_paths)}
    if output_format == "text":
        console.print(_render_file_tree(resolved_run_dir))
    else:
        _emit_payload(console, payload, output_format, event="artifacts.tree")


@artifacts_app.command("find")
def artifacts_find(
    ctx: typer.Context,
    query: str = typer.Option(..., "--query", "-q", help="Substring match against artifact paths."),
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        hits = []
        for path in resolved_run_dir.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(resolved_run_dir).as_posix()
            if query.lower() in rel.lower():
                hits.append({"path": rel, "size": path.stat().st_size})
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Artifact search failed.",
            detail=str(exc),
        )
        return

    payload = {"run_dir": str(resolved_run_dir), "query": query, "matches": hits, "match_count": len(hits)}
    if output_format == "text":
        table = Table(title=f"Artifacts matching '{query}'")
        table.add_column("Path")
        table.add_column("Size")
        for row in hits:
            table.add_row(row["path"], str(row["size"]))
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="artifacts.find")


@artifacts_app.command("view")
def artifacts_view(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Artifact path or substring to preview."),
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_run_dir(run_dir=run_dir, run_id=run_id, output_dir=output_dir, required=True)
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        exact_path = resolved_run_dir / query
        matches: list[Path] = []
        if exact_path.exists() and exact_path.is_file():
            matches = [exact_path]
        else:
            for path in resolved_run_dir.rglob("*"):
                if path.is_file() and query.lower() in path.relative_to(resolved_run_dir).as_posix().lower():
                    matches.append(path)
        if not matches:
            raise FileNotFoundError(f"No artifacts matched '{query}'.")
        if len(matches) > 1:
            payload = {
                "run_dir": str(resolved_run_dir),
                "query": query,
                "matches": [path.relative_to(resolved_run_dir).as_posix() for path in matches[:25]],
            }
            if output_format == "text":
                table = Table(title=f"Multiple Artifact Matches for '{query}'")
                table.add_column("Path")
                for match in matches[:25]:
                    table.add_row(match.relative_to(resolved_run_dir).as_posix())
                console.print(table)
            else:
                _emit_payload(console, payload, output_format, event="artifacts.view.matches")
            return
        artifact_path = matches[0]
        preview = _artifact_text_preview(artifact_path)
        payload = {
            "run_dir": str(resolved_run_dir),
            "path": artifact_path.relative_to(resolved_run_dir).as_posix(),
            "size": artifact_path.stat().st_size,
            "preview": preview,
        }
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Artifact preview failed.", detail=str(exc))
        return

    if output_format == "text":
        console.print(Panel.fit(payload["path"], title="Artifact"))
        console.print(payload["preview"] or "[empty]")
    else:
        _emit_payload(console, payload, output_format, event="artifacts.view")


@evidence_app.command("list")
def evidence_list(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    source_tool: str | None = typer.Option(None, "--source-tool"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_scan_data_run_dir(
            run_dir=run_dir,
            run_id=run_id,
            output_dir=output_dir,
            required=True,
        )
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_data = _load_run_data(resolved_run_dir)
        rows = []
        for item in run_data.evidence:
            if source_tool and item.source_tool != source_tool:
                continue
            rows.append(
                {
                    "evidence_id": item.evidence_id,
                    "source_tool": item.source_tool,
                    "kind": item.kind,
                    "artifact_path": item.artifact_path or "",
                    "snippet": item.snippet[:120],
                }
            )
    except ScanDataLoadError as exc:
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Evidence listing failed.",
            detail=str(exc),
            suggestion=exc.suggestion,
        )
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Evidence listing failed.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "evidence": rows, "count": len(rows)}
    if output_format == "text":
        table = Table(title="Evidence")
        table.add_column("ID")
        table.add_column("Tool")
        table.add_column("Kind")
        table.add_column("Artifact")
        table.add_column("Snippet")
        for row in rows:
            table.add_row(
                row["evidence_id"],
                row["source_tool"],
                row["kind"],
                row["artifact_path"] or "-",
                row["snippet"],
            )
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="evidence.list")


@findings_app.command("list")
def findings_list(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    status: str | None = typer.Option(None, "--status", help="Filter by finding status."),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_scan_data_run_dir(
            run_dir=run_dir,
            run_id=run_id,
            output_dir=output_dir,
            required=True,
        )
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_data = run_data_from_dict(migrate_payload(_read_required_scan_data(resolved_run_dir)))
        findings = run_data.findings
    except ScanDataLoadError as exc:
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not load findings from run.",
            detail=str(exc),
            suggestion=exc.suggestion,
        )
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Could not load findings from run.",
            detail=str(exc),
        )
        return

    rows = []
    for finding in findings:
        if status and finding.status != status:
            continue
        if severity and finding.severity.value != severity:
            continue
        rows.append(
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status,
                "template_id": finding.template_id,
            }
        )

    payload = {"run_dir": str(resolved_run_dir), "finding_count": len(rows), "findings": rows}
    if output_format == "text":
        table = Table(title="Findings")
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("Title")
        for row in rows:
            table.add_row(row["finding_id"], row["severity"], row["status"], row["title"])
        console.print(table)
    else:
        _emit_payload(console, payload, output_format, event="findings.list")


@findings_app.command("templates")
def findings_templates(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    templates_list(ctx=ctx, output_format=output_format)


@findings_app.command("triage")
def findings_triage(
    ctx: typer.Context,
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    top: int = typer.Option(15, "--top"),
    candidate_only: bool = typer.Option(False, "--candidate-only"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_scan_data_run_dir(
            run_dir=run_dir,
            run_id=run_id,
            output_dir=output_dir,
            required=True,
        )
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_data = run_data_from_dict(migrate_payload(_read_required_scan_data(resolved_run_dir)))
        evidence_lookup = {item.evidence_id: item for item in run_data.evidence}
        rows = []
        for finding in run_data.findings:
            if finding.suppressed:
                continue
            if candidate_only and finding.status != "candidate":
                continue
            first_evidence = evidence_lookup.get(finding.evidence_ids[0]) if finding.evidence_ids else None
            rows.append(
                {
                    "finding_id": finding.finding_id,
                    "template_id": finding.template_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "status": finding.status,
                    "evidence_quality_score": finding.evidence_quality_score,
                    "confidence": first_evidence.confidence if first_evidence else 0.0,
                    "proof_snippet": (first_evidence.snippet[:120] if first_evidence else ""),
                    "suggest_suppress": finding.status == "candidate" and finding.evidence_quality_score < 0.7,
                }
            )
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda item: (rank.get(item["severity"], 99), -item["evidence_quality_score"]))
        rows = rows[: max(1, top)]
    except ScanDataLoadError as exc:
        _exit_with_error(
            console,
            output_format,
            ExitCode.VALIDATION_ERROR,
            "Findings triage failed.",
            detail=str(exc),
            suggestion=exc.suggestion,
        )
        return
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Findings triage failed.", detail=str(exc))
        return

    payload = {"run_dir": str(resolved_run_dir), "triage": rows, "count": len(rows)}
    if output_format == "text":
        table = Table(title="Findings Triage Queue")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("EvidenceQ")
        table.add_column("Title")
        table.add_column("Proof Snippet")
        table.add_column("Suppress?")
        for row in rows:
            table.add_row(
                row["severity"],
                row["status"],
                f"{row['evidence_quality_score']:.2f}",
                row["title"],
                row["proof_snippet"] or "-",
                "yes" if row["suggest_suppress"] else "no",
            )
        console.print(table)
        render_next_steps(
            console,
            [
                "Review candidate findings before final client delivery.",
                "Use findings suppression policy file for approved suppressions.",
            ],
        )
    else:
        _emit_payload(console, payload, output_format, event="findings.triage")


@findings_app.command("explain")
def findings_explain(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding ID to explain."),
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    try:
        resolved_run_dir = _resolve_scan_data_run_dir(
            run_dir=run_dir,
            run_id=run_id,
            output_dir=output_dir,
            required=True,
        )
        if resolved_run_dir is None:
            raise typer.BadParameter("Run directory was not found.")
        run_data = _load_run_data(resolved_run_dir)
        finding = next((item for item in run_data.findings if item.finding_id == finding_id), None)
        if finding is None:
            raise FileNotFoundError(f"Finding '{finding_id}' was not found.")
        evidence_lookup = {item.evidence_id: item for item in run_data.evidence}
        evidence_rows = []
        for evidence_id in finding.evidence_ids:
            evidence = evidence_lookup.get(evidence_id)
            if evidence is None:
                continue
            evidence_rows.append(
                {
                    "evidence_id": evidence.evidence_id,
                    "tool": evidence.source_tool,
                    "kind": evidence.kind,
                    "confidence": evidence.confidence,
                    "artifact_path": evidence.artifact_path,
                    "snippet": evidence.snippet[:240],
                }
            )
        payload = {
            "run_dir": str(resolved_run_dir),
            "finding_id": finding.finding_id,
            "template_id": finding.template_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "status": finding.status,
            "quality_score": finding.evidence_quality_score,
            "quality_notes": finding.quality_notes,
            "corroboration": finding.corroboration,
            "evidence": evidence_rows,
        }
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(console, output_format, ExitCode.VALIDATION_ERROR, "Finding explain failed.", detail=str(exc))
        return

    if output_format == "text":
        console.print(f"[bold]{payload['title']}[/bold]")
        console.print(f"Finding ID: {payload['finding_id']}")
        console.print(f"Template: {payload['template_id']}")
        console.print(f"Severity: {payload['severity']}")
        console.print(f"Status: {payload['status']}")
        console.print(f"Evidence quality: {payload['quality_score']:.2f}")
        evidence_table = Table(title="Evidence")
        evidence_table.add_column("ID")
        evidence_table.add_column("Tool")
        evidence_table.add_column("Kind")
        evidence_table.add_column("Conf")
        evidence_table.add_column("Artifact")
        evidence_table.add_column("Snippet")
        for row in payload["evidence"]:
            evidence_table.add_row(
                row["evidence_id"],
                row["tool"],
                row["kind"],
                f"{row['confidence']:.2f}",
                row["artifact_path"] or "-",
                row["snippet"],
            )
        console.print(evidence_table)
    else:
        _emit_payload(console, payload, output_format, event="findings.explain")


@app.command("explain")
def explain_finding_alias(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding ID to explain."),
    run_id: str | None = typer.Option(None, "--run-id"),
    run_dir: str | None = typer.Option(None, "--run-dir"),
    output_dir: str = typer.Option("./output", "--output-dir", "-o"),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    findings_explain(
        ctx=ctx,
        finding_id=finding_id,
        run_id=run_id,
        run_dir=run_dir,
        output_dir=output_dir,
        output_format=output_format,
    )


def _completion_install_spec(shell_name: str) -> tuple[Path, str, str]:
    shell = shell_name.lower()
    if shell == "bash":
        path = Path("~/.local/share/bash-completion/completions/attackcastle").expanduser()
        content = 'eval "$(_ATTACKCASTLE_COMPLETE=bash_source attackcastle)"\n'
        hint = "Open a new shell session or source your bash rc file."
        return path, content, hint
    if shell == "zsh":
        path = Path("~/.zfunc/_attackcastle").expanduser()
        content = 'eval "$(_ATTACKCASTLE_COMPLETE=zsh_source attackcastle)"\n'
        hint = "Ensure ~/.zfunc is in fpath and run compinit."
        return path, content, hint
    if shell == "fish":
        path = Path("~/.config/fish/completions/attackcastle.fish").expanduser()
        content = "eval (env _ATTACKCASTLE_COMPLETE=fish_source attackcastle)\n"
        hint = "Open a new fish session."
        return path, content, hint
    raise ValueError("Unsupported shell. Use bash, zsh, or fish.")


@completion_app.command("install")
def completion_install(
    ctx: typer.Context,
    shell: str | None = typer.Option(None, "--shell", help="Target shell: bash|zsh|fish."),
    path: str | None = typer.Option(None, "--path", help="Override completion file path."),
    print_only: bool = typer.Option(False, "--print-only", help="Print snippet only."),
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    output_format = _normalize_output_format(output_format)
    console = _console(ctx, output_format)
    detected_shell = shell or Path(os.environ.get("SHELL", "/bin/bash")).name
    try:
        default_path, snippet, hint = _completion_install_spec(detected_shell)
        target_path = Path(path).expanduser().resolve() if path else default_path.resolve()
        if print_only:
            payload = {"shell": detected_shell, "snippet": snippet}
            if output_format == "text":
                console.print(snippet.rstrip())
            else:
                _emit_payload(console, payload, output_format, event="completion.snippet")
            return
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(snippet, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _exit_with_error(
            console,
            output_format=output_format,
            code=ExitCode.VALIDATION_ERROR,
            message="Failed to install completion script.",
            detail=str(exc),
            suggestion="Use --print-only to install manually.",
        )
        return

    payload = {"shell": detected_shell, "path": str(target_path), "hint": hint}
    if output_format == "text":
        console.print(f"Completion installed: [cyan]{target_path}[/cyan]")
        console.print(hint)
    else:
        _emit_payload(console, payload, output_format, event="completion.install")


@validate_app.command("templates")
def validate_templates_alias(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--output-format"),
) -> None:
    templates_validate(ctx=ctx, output_format=output_format)


if __name__ == "__main__":
    app()
