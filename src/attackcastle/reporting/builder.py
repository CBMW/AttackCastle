from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from attackcastle.core.models import RunData
from attackcastle.core.migrations import migrate_payload
from attackcastle.reporting.audience import normalize_report_audience
from attackcastle.reporting.schema import validate_view_model
from attackcastle.reporting.sections import DEFAULT_SECTION_PLUGINS
from attackcastle.reporting.viewmodel import build_view_model
from attackcastle.storage.run_store import RunStore


class ReportBuilder:
    def __init__(self) -> None:
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.asset_dir = Path(__file__).resolve().parent / "assets"
        self.environment = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _copy_assets(self, run_store: RunStore) -> None:
        output_assets_dir = run_store.reports_dir / "assets"
        output_assets_dir.mkdir(parents=True, exist_ok=True)
        for asset_file in self.asset_dir.glob("*"):
            if asset_file.is_file():
                target_path = output_assets_dir / asset_file.name
                target_path.write_bytes(asset_file.read_bytes())

    def _render_sections(self, view_model: dict[str, Any], audience: str) -> list[dict[str, Any]]:
        audience = normalize_report_audience(audience)
        sections: list[dict[str, Any]] = []
        for plugin in DEFAULT_SECTION_PLUGINS:
            if not plugin.should_render(view_model, audience):
                continue
            sections.append(plugin.render(view_model, audience))
        return sections

    def _confirmed_finding_keys(self, run_data: RunData) -> set[str]:
        keys = set()
        for finding in run_data.findings:
            if finding.suppressed or finding.status != "confirmed":
                continue
            affected = ",".join(
                sorted(
                    f"{item.get('entity_type')}:{item.get('entity_id')}"
                    for item in finding.affected_entities
                )
            )
            keys.add(f"{finding.template_id}|{affected}")
        return keys

    def _high_priority_lead_keys(self, run_data: RunData) -> set[str]:
        keys = set()
        for lead in getattr(run_data, "leads", []):
            if lead.priority_label not in {"very-high", "high"}:
                continue
            affected = ",".join(
                sorted(f"{item.get('entity_type')}:{item.get('entity_id')}" for item in lead.affected_entities)
            )
            keys.add(f"{lead.category}|{lead.title}|{affected}")
        return keys

    def _score_from_run_data(self, run_data: RunData) -> int:
        severity_weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 1}
        raw = 0
        for finding in run_data.findings:
            if finding.suppressed or finding.status != "confirmed":
                continue
            raw += severity_weights.get(finding.severity.value, 0)
        if raw <= 0:
            return 0
        return int(round(min(100.0, (raw / (raw + 40.0)) * 100.0)))

    def _screenshot_signatures(self, run_data: RunData) -> dict[str, str]:
        signatures: dict[str, str] = {}
        for evidence in run_data.evidence:
            if evidence.kind != "web_screenshot" or not evidence.artifact_path:
                continue
            path = Path(evidence.artifact_path)
            if not path.exists() or not path.is_file():
                continue
            try:
                signatures[str(evidence.snippet or evidence.artifact_path)] = self._hash_file(path)
            except Exception:
                continue
        return signatures

    def _load_previous_run_data(self, run_store: RunStore) -> RunData | None:
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
            payload = json.loads(scan_path.read_text(encoding="utf-8"))
            from attackcastle.core.models import run_data_from_dict

            return run_data_from_dict(migrate_payload(payload))
        return None

    def _build_trend_context(self, run_data: RunData, run_store: RunStore) -> dict[str, Any]:
        previous = self._load_previous_run_data(run_store)
        current_keys = self._confirmed_finding_keys(run_data)
        if previous is None:
            return {
                "available": False,
                "baseline_run_id": None,
                "latest_run_id": run_data.metadata.run_id,
                "risk_score_delta": None,
                "metric_delta": {},
                "new_findings": [],
                "resolved_findings": [],
                "new_high_priority_leads": [],
                "resolved_high_priority_leads": [],
                "changed_screenshots": [],
                "unchanged_findings": [],
                "history": [{"run_id": run_data.metadata.run_id, "risk_score": self._score_from_run_data(run_data)}],
            }
        previous_keys = self._confirmed_finding_keys(previous)
        current_leads = self._high_priority_lead_keys(run_data)
        previous_leads = self._high_priority_lead_keys(previous)
        current_screenshots = self._screenshot_signatures(run_data)
        previous_screenshots = self._screenshot_signatures(previous)
        current_score = self._score_from_run_data(run_data)
        previous_score = self._score_from_run_data(previous)
        metric_delta = {
            "asset_count": len(run_data.assets) - len(previous.assets),
            "service_count": len(run_data.services) - len(previous.services),
            "web_app_count": len(run_data.web_apps) - len(previous.web_apps),
            "finding_count": len(current_keys) - len(previous_keys),
            "lead_count": len(current_leads) - len(previous_leads),
            "changed_screenshot_count": len(
                [
                    key
                    for key in set(current_screenshots) & set(previous_screenshots)
                    if current_screenshots[key] != previous_screenshots[key]
                ]
            ),
        }
        return {
            "available": True,
            "baseline_run_id": previous.metadata.run_id,
            "latest_run_id": run_data.metadata.run_id,
            "risk_score_delta": current_score - previous_score,
            "metric_delta": metric_delta,
            "new_findings": sorted(current_keys - previous_keys),
            "resolved_findings": sorted(previous_keys - current_keys),
            "new_high_priority_leads": sorted(current_leads - previous_leads),
            "resolved_high_priority_leads": sorted(previous_leads - current_leads),
            "changed_screenshots": sorted(
                [
                    key
                    for key in set(current_screenshots) & set(previous_screenshots)
                    if current_screenshots[key] != previous_screenshots[key]
                ]
            ),
            "unchanged_findings": sorted(current_keys & previous_keys),
            "history": [
                {"run_id": previous.metadata.run_id, "risk_score": previous_score},
                {"run_id": run_data.metadata.run_id, "risk_score": current_score},
            ],
        }

    def _write_csv_exports(self, run_store: RunStore, view_model: dict[str, Any]) -> list[Path]:
        paths: list[Path] = []
        services_path = run_store.reports_dir / "services.csv"
        findings_path = run_store.reports_dir / "findings.csv"
        remediation_path = run_store.reports_dir / "remediation_plan.csv"
        exposure_path = run_store.reports_dir / "asset_exposure_matrix.csv"
        vulnerabilities_path = run_store.reports_dir / "vulnerabilities.csv"
        leads_path = run_store.reports_dir / "priority_leads.csv"
        bundles_path = run_store.reports_dir / "evidence_bundles.csv"
        evidence_index_path = run_store.reports_dir / "evidence_index.csv"
        command_log_path = run_store.reports_dir / "command_log.csv"

        with services_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["service_id", "asset_id", "port", "protocol", "state", "name", "banner"],
            )
            writer.writeheader()
            for row in view_model.get("services", []):
                writer.writerow(row)
        paths.append(services_path)

        with findings_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "finding_id",
                    "template_id",
                    "title",
                    "severity",
                    "status",
                    "category",
                    "confidence_score",
                    "evidence_quality_score",
                ],
            )
            writer.writeheader()
            for row in view_model.get("findings", []):
                writer.writerow(
                    {
                        "finding_id": row.get("finding_id"),
                        "template_id": row.get("template_id"),
                        "title": row.get("title"),
                        "severity": row.get("severity"),
                        "status": row.get("status"),
                        "category": row.get("category"),
                        "confidence_score": row.get("confidence_score"),
                        "evidence_quality_score": row.get("evidence_quality_score"),
                    }
                )
        paths.append(findings_path)

        with remediation_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "finding_id",
                    "title",
                    "severity",
                    "action",
                    "owner",
                    "effort",
                    "risk_reduction_points",
                    "priority_index",
                    "target_window",
                ],
            )
            writer.writeheader()
            for row in view_model.get("remediation_plan", []):
                writer.writerow({field: row.get(field) for field in writer.fieldnames})
        paths.append(remediation_path)

        with exposure_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "asset_id",
                    "asset_name",
                    "kind",
                    "ip",
                    "finding_count",
                    "highest_severity",
                    "weak_tls",
                    "open_services",
                    "web_apps",
                    "technologies",
                ],
            )
            writer.writeheader()
            for row in view_model.get("exposure_matrix", []):
                writer.writerow(
                    {
                        "asset_id": row.get("asset_id"),
                        "asset_name": row.get("asset_name"),
                        "kind": row.get("kind"),
                        "ip": row.get("ip"),
                        "finding_count": row.get("finding_count"),
                        "highest_severity": row.get("highest_severity"),
                        "weak_tls": row.get("weak_tls"),
                        "open_services": "; ".join(row.get("open_services", [])),
                        "web_apps": "; ".join(row.get("web_apps", [])),
                        "technologies": "; ".join(row.get("technologies", [])),
                    }
                )
        paths.append(exposure_path)

        with vulnerabilities_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "record_id",
                    "title",
                    "severity",
                    "status",
                    "source",
                    "confidence_score",
                    "category",
                    "template_id",
                    "evidence_count",
                ],
            )
            writer.writeheader()
            for row in view_model.get("vulnerabilities", []):
                writer.writerow({field: row.get(field) for field in writer.fieldnames})
        paths.append(vulnerabilities_path)

        with leads_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "lead_id",
                    "title",
                    "category",
                    "priority_score",
                    "priority_label",
                    "status",
                    "confidence",
                    "likely_finding",
                    "likely_severity",
                ],
            )
            writer.writeheader()
            for row in view_model.get("priority_leads", []):
                writer.writerow({field: row.get(field) for field in writer.fieldnames})
        paths.append(leads_path)

        with bundles_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "bundle_id",
                    "label",
                    "entity_type",
                    "entity_id",
                    "summary",
                    "confidence",
                    "source_tools",
                    "artifact_paths",
                ],
            )
            writer.writeheader()
            for row in view_model.get("evidence_bundles", []):
                writer.writerow(
                    {
                        "bundle_id": row.get("bundle_id"),
                        "label": row.get("label"),
                        "entity_type": row.get("entity_type"),
                        "entity_id": row.get("entity_id"),
                        "summary": row.get("summary"),
                        "confidence": row.get("confidence"),
                        "source_tools": "; ".join(row.get("source_tools", [])),
                        "artifact_paths": "; ".join(row.get("artifact_paths", [])),
                    }
                )
        paths.append(bundles_path)

        with evidence_index_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "evidence_id",
                    "source_tool",
                    "source_execution_id",
                    "kind",
                    "confidence",
                    "artifact_path",
                    "timestamp",
                ],
            )
            writer.writeheader()
            for row in view_model.get("evidence", []):
                writer.writerow({field: row.get(field) for field in writer.fieldnames})
        paths.append(evidence_index_path)

        with command_log_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "execution_id",
                    "tool_name",
                    "capability",
                    "status",
                    "exit_code",
                    "started_at",
                    "ended_at",
                    "command",
                    "stdout_path",
                    "stderr_path",
                    "error_message",
                ],
            )
            writer.writeheader()
            for row in view_model.get("tool_executions", []):
                writer.writerow({field: row.get(field) for field in writer.fieldnames})
        paths.append(command_log_path)
        return paths

    def _write_json_summary(self, run_store: RunStore, view_model: dict[str, Any]) -> Path:
        summary_path = run_store.reports_dir / "report_summary.json"
        summary = {
            "schema_version": "report_summary_v2",
            "metadata": view_model.get("metadata", {}),
            "summary": view_model.get("summary", {}),
            "completeness_status": view_model.get("completeness_status", "healthy"),
            "severity_counts": view_model.get("severity_counts", {}),
            "service_distribution": view_model.get("service_distribution", []),
            "risk_domains": view_model.get("risk_domains", []),
            "service_exposure_breakdown": view_model.get("service_exposure_breakdown", []),
            "execution_issues_summary": view_model.get("execution_issues_summary", {}),
            "execution_issues": view_model.get("execution_issues", [])[:50],
            "priority_leads": view_model.get("priority_leads", [])[:50],
            "likely_findings": view_model.get("likely_findings", [])[:50],
            "issue_groups": view_model.get("issue_groups", [])[:50],
            "remediation_plan": view_model.get("remediation_plan", [])[:20],
            "vulnerabilities": view_model.get("vulnerabilities", [])[:100],
            "trend": view_model.get("trend", {}),
            "coverage_summary": view_model.get("coverage", {}).get("summary", {}),
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary_path

    def _write_evidence_bundle_exports(self, run_store: RunStore, view_model: dict[str, Any]) -> list[Path]:
        bundle_dir = run_store.reports_dir / "evidence_bundles"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        evidence_lookup = {
            str(item.get("evidence_id")): item for item in view_model.get("evidence", []) if isinstance(item, dict)
        }
        index: list[dict[str, Any]] = []
        paths: list[Path] = []
        for bundle in view_model.get("evidence_bundles", []):
            if not isinstance(bundle, dict):
                continue
            payload = dict(bundle)
            payload["evidence_items"] = [
                evidence_lookup[evidence_id]
                for evidence_id in bundle.get("evidence_ids", [])
                if evidence_id in evidence_lookup
            ]
            bundle_path = bundle_dir / f"{bundle.get('bundle_id', 'bundle')}.json"
            bundle_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            paths.append(bundle_path)
            index.append(
                {
                    "bundle_id": bundle.get("bundle_id"),
                    "label": bundle.get("label"),
                    "path": str(bundle_path),
                    "evidence_count": len(bundle.get("evidence_ids", [])),
                }
            )
        index_path = bundle_dir / "index.json"
        index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        paths.append(index_path)
        return paths

    def _try_pdf_export(self, run_store: RunStore, html_path: Path) -> Path | None:
        try:
            from weasyprint import HTML  # type: ignore
        except Exception:
            return None
        pdf_path = run_store.reports_dir / "report.pdf"
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path

    def _write_integration_exports(self, run_store: RunStore, view_model: dict[str, Any]) -> list[Path]:
        integration_dir = run_store.reports_dir / "integrations"
        integration_dir.mkdir(parents=True, exist_ok=True)
        findings = view_model.get("findings", [])
        metadata = view_model.get("metadata", {})
        run_id = str(metadata.get("run_id", ""))
        paths: list[Path] = []

        jira_payload = {
            "run_id": run_id,
            "issues": [
                {
                    "summary": f"[AttackCastle] {item.get('title')}",
                    "description": "\n".join(
                        [
                            f"Severity: {item.get('severity')}",
                            f"Category: {item.get('category')}",
                            f"Impact: {item.get('impact')}",
                            "Recommendations:",
                            *(item.get("recommendations") or []),
                        ]
                    ),
                    "labels": ["attackcastle", str(item.get("severity", "info"))],
                    "priority": str(item.get("severity", "medium")).upper(),
                }
                for item in findings
            ],
        }
        jira_path = integration_dir / "jira_issues.json"
        jira_path.write_text(json.dumps(jira_payload, indent=2), encoding="utf-8")
        paths.append(jira_path)

        dradis_payload = {
            "run_id": run_id,
            "findings": [
                {
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "description": item.get("description"),
                    "evidence": [evidence.get("snippet") for evidence in item.get("evidence", [])],
                    "remediation": item.get("recommendations"),
                }
                for item in findings
            ],
        }
        dradis_path = integration_dir / "dradis_findings.json"
        dradis_path.write_text(json.dumps(dradis_payload, indent=2), encoding="utf-8")
        paths.append(dradis_path)

        serpico_payload = {
            "run_id": run_id,
            "findings": [
                {
                    "title": item.get("title"),
                    "risk": item.get("severity"),
                    "overview": item.get("description"),
                    "impact": item.get("impact"),
                    "recommendations": item.get("recommendations"),
                }
                for item in findings
            ],
        }
        serpico_path = integration_dir / "serpico_findings.json"
        serpico_path.write_text(json.dumps(serpico_payload, indent=2), encoding="utf-8")
        paths.append(serpico_path)

        defectdojo_payload = {
            "scan_type": "AttackCastle External Scan",
            "test_title": f"AttackCastle Run {run_id}",
            "findings": [
                {
                    "title": item.get("title"),
                    "severity": str(item.get("severity", "Info")).capitalize(),
                    "description": item.get("description"),
                    "mitigation": "\n".join(item.get("recommendations", [])),
                    "impact": item.get("impact"),
                    "references": "\n".join(item.get("references", [])),
                    "active": True,
                    "verified": str(item.get("status")) == "confirmed",
                }
                for item in findings
            ],
        }
        defectdojo_path = integration_dir / "defectdojo_import.json"
        defectdojo_path.write_text(json.dumps(defectdojo_payload, indent=2), encoding="utf-8")
        paths.append(defectdojo_path)

        markdown_lines = [f"# AttackCastle Findings ({run_id})", ""]
        for item in findings:
            markdown_lines.extend(
                [
                    f"## {item.get('title')}",
                    f"- Severity: `{item.get('severity')}`",
                    f"- Category: `{item.get('category')}`",
                    f"- Status: `{item.get('status')}`",
                    f"- Impact: {item.get('impact')}",
                    "",
                    "### Recommendations",
                    *(f"- {rec}" for rec in item.get("recommendations", [])),
                    "",
                ]
            )
        markdown_path = integration_dir / "findings.md"
        markdown_path.write_text("\n".join(markdown_lines), encoding="utf-8")
        paths.append(markdown_path)
        return paths

    def build(
        self,
        run_data: RunData,
        run_store: RunStore,
        audience: str = "consultant",
        export_csv: bool = True,
        export_json_summary: bool = True,
        export_pdf: bool = False,
        export_integrations: bool = True,
    ) -> dict[str, Any]:
        audience = normalize_report_audience(audience)
        trend_context = self._build_trend_context(run_data, run_store)
        previous = self._load_previous_run_data(run_store)
        view_model = build_view_model(
            run_data,
            audience=audience,
            trend=trend_context,
            previous_runs=[previous] if previous else None,
        )
        sections = self._render_sections(view_model, audience=audience)
        view_model["sections"] = sections
        view_model["section_groups"] = list(dict.fromkeys(section["group"] for section in sections))
        validate_view_model(view_model)
        template = self.environment.get_template("report.html.j2")
        html = template.render(**view_model)
        self._copy_assets(run_store)
        report_path = run_store.reports_dir / "report.html"
        report_path.write_text(html, encoding="utf-8")

        csv_paths: list[Path] = []
        if export_csv:
            csv_paths = self._write_csv_exports(run_store, view_model)
        summary_path = self._write_json_summary(run_store, view_model) if export_json_summary else None
        bundle_paths = self._write_evidence_bundle_exports(run_store, view_model)
        pdf_path = self._try_pdf_export(run_store, report_path) if export_pdf else None
        integration_paths = self._write_integration_exports(run_store, view_model) if export_integrations else []

        return {
            "report_path": report_path,
            "csv_paths": csv_paths,
            "summary_path": summary_path,
            "bundle_paths": bundle_paths,
            "pdf_path": pdf_path,
            "integration_paths": integration_paths,
            "view_model": view_model,
        }
