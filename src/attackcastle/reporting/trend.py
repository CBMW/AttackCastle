from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from attackcastle.core.models import run_data_from_dict
from attackcastle.core.migrations import migrate_payload
from attackcastle.reporting.audience import normalize_report_audience
from attackcastle.reporting.viewmodel import build_view_model


def _finding_keys(view_model: dict[str, Any]) -> set[str]:
    keys = set()
    for finding in view_model.get("findings", []):
        affected = ",".join(
            sorted(
                f"{item.get('entity_type')}:{item.get('entity_id')}"
                for item in finding.get("affected_entities", [])
            )
        )
        keys.add(f"{finding.get('template_id')}|{affected}")
    return keys


def _lead_keys(view_model: dict[str, Any]) -> set[str]:
    keys = set()
    for lead in view_model.get("priority_leads", []):
        if lead.get("priority_label") not in {"very-high", "high"}:
            continue
        affected = ",".join(
            sorted(
                f"{item.get('entity_type')}:{item.get('entity_id')}"
                for item in lead.get("affected_entities", [])
            )
        )
        keys.add(f"{lead.get('category')}|{lead.get('title')}|{affected}")
    return keys


def _screenshot_keys(view_model: dict[str, Any]) -> set[str]:
    return {
        str(item.get("caption") or item.get("path") or item.get("evidence_id"))
        for item in view_model.get("screenshots", [])
    }


def build_trend_report(run_dirs: list[Path], output_path: Path) -> dict[str, Any]:
    if len(run_dirs) < 2:
        raise ValueError("Trend analysis needs at least two run directories.")
    view_models: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        scan_data_path = run_dir / "data" / "scan_data.json"
        payload = json.loads(scan_data_path.read_text(encoding="utf-8"))
        run_data = run_data_from_dict(migrate_payload(payload))
        view_models.append(build_view_model(run_data, audience=normalize_report_audience("technical")))

    baseline = view_models[0]
    latest = view_models[-1]
    baseline_keys = _finding_keys(baseline)
    latest_keys = _finding_keys(latest)
    baseline_leads = _lead_keys(baseline)
    latest_leads = _lead_keys(latest)
    baseline_screens = _screenshot_keys(baseline)
    latest_screens = _screenshot_keys(latest)
    baseline_summary = baseline.get("summary", {})
    latest_summary = latest.get("summary", {})
    metric_delta = {
        "asset_count": int(latest_summary.get("asset_count", 0)) - int(baseline_summary.get("asset_count", 0)),
        "service_count": int(latest_summary.get("service_count", 0)) - int(
            baseline_summary.get("service_count", 0)
        ),
        "web_app_count": int(latest_summary.get("web_app_count", 0)) - int(
            baseline_summary.get("web_app_count", 0)
        ),
        "finding_count": int(latest_summary.get("finding_count", 0)) - int(
            baseline_summary.get("finding_count", 0)
        ),
        "lead_count": int(latest_summary.get("high_priority_lead_count", 0)) - int(
            baseline_summary.get("high_priority_lead_count", 0)
        ),
        "risk_score": int(latest_summary.get("risk_score", 0)) - int(baseline_summary.get("risk_score", 0)),
        "screenshot_count": len(latest_screens) - len(baseline_screens),
    }
    report_data = {
        "baseline_run": baseline["metadata"]["run_id"],
        "latest_run": latest["metadata"]["run_id"],
        "new_findings": sorted(latest_keys - baseline_keys),
        "resolved_findings": sorted(baseline_keys - latest_keys),
        "unchanged_findings": sorted(latest_keys & baseline_keys),
        "new_high_priority_leads": sorted(latest_leads - baseline_leads),
        "resolved_high_priority_leads": sorted(baseline_leads - latest_leads),
        "new_screenshots": sorted(latest_screens - baseline_screens),
        "resolved_screenshots": sorted(baseline_screens - latest_screens),
        "baseline_screenshot_count": len(baseline_screens),
        "latest_screenshot_count": len(latest_screens),
        "baseline_summary": baseline_summary,
        "latest_summary": latest_summary,
        "metric_delta": metric_delta,
    }

    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.from_string(
        """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>AttackCastle Trend Report</title></head>
<body>
  <h1>Trend Report</h1>
  <p>Baseline: {{ data.baseline_run }} | Latest: {{ data.latest_run }}</p>
  <h2>Metric Delta</h2>
  <table border="1" cellpadding="6" cellspacing="0">
    <thead><tr><th>Metric</th><th>Baseline</th><th>Latest</th><th>Delta</th></tr></thead>
    <tbody>
      <tr><td>Assets</td><td>{{ data.baseline_summary.asset_count }}</td><td>{{ data.latest_summary.asset_count }}</td><td>{{ data.metric_delta.asset_count }}</td></tr>
      <tr><td>Services</td><td>{{ data.baseline_summary.service_count }}</td><td>{{ data.latest_summary.service_count }}</td><td>{{ data.metric_delta.service_count }}</td></tr>
      <tr><td>Web Apps</td><td>{{ data.baseline_summary.web_app_count }}</td><td>{{ data.latest_summary.web_app_count }}</td><td>{{ data.metric_delta.web_app_count }}</td></tr>
      <tr><td>Confirmed Findings</td><td>{{ data.baseline_summary.finding_count }}</td><td>{{ data.latest_summary.finding_count }}</td><td>{{ data.metric_delta.finding_count }}</td></tr>
      <tr><td>High Priority Leads</td><td>{{ data.baseline_summary.high_priority_lead_count }}</td><td>{{ data.latest_summary.high_priority_lead_count }}</td><td>{{ data.metric_delta.lead_count }}</td></tr>
      <tr><td>Risk Score</td><td>{{ data.baseline_summary.risk_score }}</td><td>{{ data.latest_summary.risk_score }}</td><td>{{ data.metric_delta.risk_score }}</td></tr>
      <tr><td>Screenshots</td><td>{{ data.baseline_screenshot_count }}</td><td>{{ data.latest_screenshot_count }}</td><td>{{ data.metric_delta.screenshot_count }}</td></tr>
    </tbody>
  </table>
  <h2>New Findings ({{ data.new_findings|length }})</h2>
  <ul>{% for item in data.new_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
  <h2>Resolved Findings ({{ data.resolved_findings|length }})</h2>
  <ul>{% for item in data.resolved_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
  <h2>New High Priority Leads ({{ data.new_high_priority_leads|length }})</h2>
  <ul>{% for item in data.new_high_priority_leads %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
  <h2>Unchanged Findings ({{ data.unchanged_findings|length }})</h2>
  <ul>{% for item in data.unchanged_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
</body>
</html>
"""
    )
    output_path.write_text(template.render(data=report_data), encoding="utf-8")
    return report_data
