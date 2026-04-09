from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackcastle.core.enums import Severity
from attackcastle.core.models import Asset, Finding, Lead, RunData, RunMetadata, now_utc, to_serializable
from attackcastle.reporting.trend import _finding_keys, _lead_keys, _screenshot_keys, build_trend_report


def test_trend_key_helpers_extract_stable_comparison_keys():
    view_model = {
        "findings": [
            {
                "template_id": "LOGIN_PORTAL",
                "affected_entities": [
                    {"entity_type": "asset", "entity_id": "asset-1"},
                    {"entity_type": "web_app", "entity_id": "web-1"},
                ],
            }
        ],
        "priority_leads": [
            {
                "category": "Exposure",
                "title": "Admin panel",
                "priority_label": "high",
                "affected_entities": [{"entity_type": "asset", "entity_id": "asset-1"}],
            },
            {
                "category": "Noise",
                "title": "Ignore me",
                "priority_label": "medium",
                "affected_entities": [{"entity_type": "asset", "entity_id": "asset-2"}],
            },
        ],
        "screenshots": [
            {"caption": "Landing page"},
            {"path": "/tmp/raw.png"},
            {"evidence_id": "evidence-3"},
        ],
    }

    assert _finding_keys(view_model) == {"LOGIN_PORTAL|asset:asset-1,web_app:web-1"}
    assert _lead_keys(view_model) == {"Exposure|Admin panel|asset:asset-1"}
    assert _screenshot_keys(view_model) == {"Landing page", "/tmp/raw.png", "evidence-3"}


def test_build_trend_report_requires_at_least_two_runs(tmp_path: Path):
    only_run = tmp_path / "run_one"
    only_run.mkdir()

    with pytest.raises(ValueError, match="at least two"):
        build_trend_report([only_run], tmp_path / "trend.html")


def test_build_trend_report_computes_findings_and_lead_deltas(tmp_path: Path):
    baseline = RunData(
        metadata=RunMetadata(
            run_id="baseline",
            target_input="example.com",
            profile="standard",
            output_dir=str(tmp_path / "baseline"),
            started_at=now_utc(),
        )
    )
    latest = RunData(
        metadata=RunMetadata(
            run_id="latest",
            target_input="example.com",
            profile="standard",
            output_dir=str(tmp_path / "latest"),
            started_at=now_utc(),
        )
    )
    latest.assets.append(Asset(asset_id="asset-1", kind="host", name="example.com", ip="203.0.113.10"))
    latest.findings.append(
        Finding(
            finding_id="finding-1",
            template_id="LOGIN_PORTAL",
            title="Public Login Portal",
            severity=Severity.LOW,
            category="Web Exposure",
            description="A public login portal is exposed.",
            impact="Increases attack surface.",
            likelihood="Medium",
            recommendations=["Review exposure."],
            references=[],
            tags=["web"],
            affected_entities=[{"entity_type": "asset", "entity_id": "asset-1"}],
            evidence_ids=[],
            status="confirmed",
        )
    )
    latest.leads.append(
        Lead(
            lead_id="lead-1",
            title="Admin panel",
            category="Exposure",
            priority_score=90,
            priority_label="high",
            affected_entities=[{"entity_type": "asset", "entity_id": "asset-1"}],
        )
    )

    baseline_dir = tmp_path / "run_baseline"
    latest_dir = tmp_path / "run_latest"
    _write_run_data(baseline_dir, baseline)
    _write_run_data(latest_dir, latest)

    output_path = tmp_path / "trend.html"
    report = build_trend_report([baseline_dir, latest_dir], output_path)
    html = output_path.read_text(encoding="utf-8")

    assert report["baseline_run"] == "baseline"
    assert report["latest_run"] == "latest"
    assert report["new_findings"] == ["LOGIN_PORTAL|asset:asset-1"]
    assert report["resolved_findings"] == []
    assert report["new_high_priority_leads"] == ["Exposure|Admin panel|asset:asset-1"]
    assert report["metric_delta"]["finding_count"] == 1
    assert report["metric_delta"]["lead_count"] == 1
    assert report["metric_delta"]["asset_count"] == 1
    assert "Trend Report" in html
    assert "baseline" in html
    assert "latest" in html


def _write_run_data(run_dir: Path, run_data: RunData) -> None:
    scan_data_path = run_dir / "data" / "scan_data.json"
    scan_data_path.parent.mkdir(parents=True, exist_ok=True)
    scan_data_path.write_text(json.dumps(to_serializable(run_data), indent=2), encoding="utf-8")
