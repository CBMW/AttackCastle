from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from attackcastle.app import ScanOutcome
from attackcastle.cli import app


def _outcome(tmp_path: Path) -> ScanOutcome:
    return ScanOutcome(
        run_id="audience-default",
        run_dir=tmp_path,
        json_path=None,
        report_path=None,
        warning_count=0,
        error_count=0,
        finding_count=0,
        state="completed",
        duration_seconds=0.1,
    )


def test_scan_cli_defaults_to_consultant_audience(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}

    monkeypatch.setattr("attackcastle.cli._external_dependency_rows", lambda: [])
    monkeypatch.setattr("attackcastle.cli._missing_dependency_message", lambda rows: "")

    def _fake_run_scan(**kwargs):  # noqa: ANN003
        captured.update(kwargs)
        return _outcome(tmp_path)

    monkeypatch.setattr("attackcastle.cli.run_scan", _fake_run_scan)

    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--output-format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert captured["audience"] == "consultant"
