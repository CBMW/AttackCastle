from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from attackcastle.reporting.audience import normalize_report_audience

SectionRenderer = Callable[[dict[str, Any], str], dict[str, Any]]
SectionCondition = Callable[[dict[str, Any], str], bool]


@dataclass
class ReportSectionPlugin:
    section_id: str
    title: str
    template: str
    renderer: SectionRenderer
    group: str = "details"
    default_open: bool = False
    audiences: frozenset[str] = frozenset({"consultant", "client", "executive"})
    condition: SectionCondition | None = None

    def render(self, view_model: dict[str, Any], audience: str) -> dict[str, Any]:
        audience = normalize_report_audience(audience)
        return {
            "id": self.section_id,
            "title": self.title,
            "template": self.template,
            "group": self.group,
            "default_open": self.default_open,
            "summary": _section_summary(self.section_id, view_model),
            "context": self.renderer(view_model, audience),
        }

    def should_render(self, view_model: dict[str, Any], audience: str) -> bool:
        if audience not in self.audiences:
            return False
        if self.condition is None:
            return True
        return bool(self.condition(view_model, audience))


def _section_summary(section_id: str, vm: dict[str, Any]) -> str:
    summary = vm.get("summary", {})
    coverage_count = vm.get("coverage", {}).get("summary", {}).get("coverage_gap_count", 0)
    issue_count = int(vm.get("execution_issues_summary", {}).get("total_count", 0) or 0)
    if section_id == "overview":
        return f"Risk {summary.get('risk_score', 0)}/100 across {summary.get('finding_count', 0)} confirmed findings"
    if section_id == "findings":
        return f"{len(vm.get('findings', []))} confirmed findings"
    if section_id == "investigation-queue":
        return (
            f"{summary.get('high_priority_lead_count', 0)} high-priority leads, "
            f"{summary.get('candidate_finding_count', 0)} candidate findings"
        )
    if section_id == "attack-surface":
        return (
            f"{summary.get('asset_count', 0)} assets, {summary.get('service_count', 0)} services, "
            f"{summary.get('web_app_count', 0)} web apps"
        )
    if section_id == "appendices":
        evidence_count = len(vm.get("evidence", []))
        return f"{evidence_count} evidence items, {coverage_count} coverage gaps, {issue_count} execution issues"
    if section_id == "extensions":
        return f"{len(vm.get('extensions', []))} extension output(s)"
    return ""


def _overview(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return vm["overview"]


def _findings(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return {"findings": vm["findings"], "audience": audience}


def _investigation_queue(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return vm["investigation_queue"]


def _attack_surface(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return vm["attack_surface"]


def _appendices(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return vm["appendices"]


def _extensions(vm: dict[str, Any], audience: str) -> dict[str, Any]:
    return {"extensions": vm.get("extensions", []), "audience": audience}


DEFAULT_SECTION_PLUGINS: list[ReportSectionPlugin] = [
    ReportSectionPlugin(
        "overview",
        "Overview",
        "overview_group.j2",
        _overview,
        group="overview",
        default_open=True,
    ),
    ReportSectionPlugin(
        "findings",
        "Confirmed Findings",
        "findings.j2",
        _findings,
        group="findings",
        default_open=True,
    ),
    ReportSectionPlugin(
        "investigation-queue",
        "Investigation Queue",
        "investigation_queue_group.j2",
        _investigation_queue,
        group="analysis",
        audiences=frozenset({"consultant"}),
    ),
    ReportSectionPlugin(
        "attack-surface",
        "Attack Surface",
        "attack_surface_group.j2",
        _attack_surface,
        group="surface",
        default_open=True,
        audiences=frozenset({"consultant", "client"}),
    ),
    ReportSectionPlugin(
        "extensions",
        "Extensions",
        "extensions_group.j2",
        _extensions,
        group="extensions",
        default_open=True,
        audiences=frozenset({"consultant", "client"}),
        condition=lambda vm, _audience: bool(vm.get("extensions")),
    ),
    ReportSectionPlugin(
        "appendices",
        "Appendices",
        "appendices_group.j2",
        _appendices,
        group="appendix",
        audiences=frozenset({"consultant"}),
    ),
]
