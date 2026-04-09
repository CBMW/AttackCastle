from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackcastle.cli import app


def test_run_dashboard_ignores_invalid_json_summary(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "output" / "run_20260318T000000Z_dashboard"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text("{not-json", encoding="utf-8")
    (run_dir / "data" / "run_metrics.json").write_text('{"duration_seconds": 12.5}', encoding="utf-8")
    (run_dir / "data" / "plan.json").write_text("[]", encoding="utf-8")

    result = runner.invoke(app, ["run", "dashboard", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.stdout
    assert "Run Dashboard" in result.stdout
    assert "12.5" in result.stdout
    assert "Dashboard summary ignored" in result.stdout
    assert "Dashboard plan ignored" in result.stdout


def test_run_dashboard_tolerates_invalid_metric_and_plan_field_types(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "output" / "run_20260318T000001Z_dashboard"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text(
        json.dumps(
            {
                "state": "running",
                "finding_count": "7",
                "warning_count": "bad",
                "error_count": [],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "data" / "run_metrics.json").write_text(
        json.dumps(
            {
                "duration_seconds": "12.5",
                "task_count": "bad",
                "retries_total": [],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "data" / "plan.json").write_text(
        json.dumps({"safety": [], "mode": "aggressive"}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["run", "dashboard", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.stdout
    assert "Run Dashboard" in result.stdout
    assert "12.5" in result.stdout
    assert "running" in result.stdout
    assert "Dashboard metrics ignored: task_count must be an integer." in result.stdout
    assert "Dashboard metrics ignored: retries_total must be an integer." in result.stdout
    assert "Dashboard summary ignored: warning_count must be an integer." in result.stdout
    assert "Dashboard summary ignored: error_count must be an integer." in result.stdout
    assert "Dashboard plan ignored: safety did not contain a JSON object." in result.stdout
    assert "Dashboard plan ignored: mode did not contain a JSON object." in result.stdout


def test_run_dashboard_surfaces_plan_context_rows(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "output" / "run_20260318T000002Z_dashboard"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text(
        json.dumps({"state": "completed", "finding_count": 4, "warning_count": 1, "error_count": 0}),
        encoding="utf-8",
    )
    (run_dir / "data" / "run_metrics.json").write_text(
        json.dumps({"duration_seconds": 18.25, "task_count": 6, "retries_total": 2}),
        encoding="utf-8",
    )
    (run_dir / "data" / "plan.json").write_text(
        json.dumps(
            {
                "risk_mode": "stealth",
                "max_noise_limit": 20,
                "mode": {"json_only": False, "html_only": True, "no_report": False, "redact": True},
                "scope_compiler": {"compiled_target_count": 9},
                "items": [
                    {"selected": True, "capability": "network_fast_scan", "noise_score": 4},
                    {"selected": True, "capability": "network_port_scan", "noise_score": "3"},
                    {"selected": False, "capability": "web_vuln_scan", "noise_score": 10},
                ],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["run", "dashboard", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.stdout
    assert "risk_mode" in result.stdout
    assert "stealth" in result.stdout
    assert "output_mode" in result.stdout
    assert "html-only, redacted" in result.stdout
    assert "selected_tasks" in result.stdout
    assert "2" in result.stdout
    assert "blocked_tasks" in result.stdout
    assert "1" in result.stdout
    assert "targets_compiled" in result.stdout
    assert "9" in result.stdout
    assert "tools_scheduled" in result.stdout
    assert "noise_budget" in result.stdout
    assert "7/20" in result.stdout


def test_run_dashboard_warns_for_invalid_control_and_malformed_plan_items(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "output" / "run_20260318T000003Z_dashboard"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "control").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text(json.dumps({"state": "running"}), encoding="utf-8")
    (run_dir / "data" / "run_metrics.json").write_text(json.dumps({"duration_seconds": 5}), encoding="utf-8")
    (run_dir / "data" / "plan.json").write_text(
        json.dumps(
            {
                "risk_mode": "standard",
                "max_noise_limit": 15,
                "mode": {},
                "scope_compiler": {"compiled_target_count": 2},
                "items": [
                    {"selected": True, "capability": "network_fast_scan", "noise_score": 5},
                    "bad-item",
                    7,
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "control" / "control.json").write_text("{not-json", encoding="utf-8")

    result = runner.invoke(app, ["run", "dashboard", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.stdout
    assert "selected_tasks" in result.stdout
    assert "1" in result.stdout
    assert "noise_budget" in result.stdout
    assert "5/15" in result.stdout
    assert "Dashboard plan ignored: dropped 2 malformed item entries from items." in result.stdout
    assert "Dashboard control ignored: control.json was unreadable." in result.stdout


def test_run_dashboard_falls_back_to_scan_data_scope_count(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "output" / "run_20260318T000004Z_dashboard"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text(
        json.dumps({"state": "completed", "finding_count": 1, "warning_count": 0, "error_count": 0}),
        encoding="utf-8",
    )
    (run_dir / "data" / "run_metrics.json").write_text(
        json.dumps({"duration_seconds": 9.5, "task_count": 4, "retries_total": 0}),
        encoding="utf-8",
    )
    (run_dir / "data" / "plan.json").write_text(
        json.dumps(
            {
                "risk_mode": "safe-active",
                "max_noise_limit": 10,
                "mode": {"json_only": False, "html_only": False, "no_report": False, "redact": False},
                "items": [{"selected": True, "capability": "network_port_scan", "noise_score": 4}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "data" / "scan_data.json").write_text(
        json.dumps(
            {
                "scope": [
                    {"target_id": "one"},
                    {"target_id": "two"},
                    {"target_id": "three"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["run", "dashboard", "--run-dir", str(run_dir)])

    assert result.exit_code == 0, result.stdout
    assert "targets_compiled" in result.stdout
    assert "3" in result.stdout
