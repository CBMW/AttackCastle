from __future__ import annotations

import json
import os
import time
from pathlib import Path

from typer.testing import CliRunner

from attackcastle.cli import app


def _make_report_run(
    path: Path,
    *,
    report_html: bool = True,
    summary: bool = True,
) -> Path:
    (path / "data").mkdir(parents=True, exist_ok=True)
    (path / "reports").mkdir(parents=True, exist_ok=True)
    if summary:
        (path / "data" / "run_summary.json").write_text("{}", encoding="utf-8")
    if report_html:
        (path / "reports" / "report.html").write_text("<html>report</html>", encoding="utf-8")
    return path


def _set_mtime(path: Path, ts: float) -> None:
    os.utime(path, (ts, ts))


def _write_scan_data(path: Path, payload: str = "{}") -> None:
    (path / "data").mkdir(parents=True, exist_ok=True)
    (path / "data" / "scan_data.json").write_text(payload, encoding="utf-8")


def test_report_open_run_dir_output_root_resolves_latest_valid_run(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    older = _make_report_run(output_root / "run_20260315T045637Z_older")
    newer = _make_report_run(output_root / "run_20260315T045638Z_newer")

    now = time.time()
    _set_mtime(older, now - 10)
    _set_mtime(newer, now)

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(output_root)])

    assert result.exit_code == 0, result.stdout
    assert opened == [(newer / "reports" / "report.html").resolve().as_uri()]
    assert "Opening report" in result.stdout
    assert "20260315T045638Z_newer" in result.stdout


def test_report_open_defaults_to_output_from_current_workdir(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    latest = _make_report_run(output_root / "run_20260315T045639Z_default")
    monkeypatch.chdir(tmp_path)

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open"])

    assert result.exit_code == 0, result.stdout
    assert opened == [(latest / "reports" / "report.html").resolve().as_uri()]


def test_report_open_ignores_root_level_junk_entries(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    latest = _make_report_run(output_root / "run_20260315T045640Z_valid")
    for name in [
        "artifacts",
        "cache",
        "checkpoints",
        "data",
        "locks",
        "logs",
        "reports",
    ]:
        (output_root / name).mkdir(parents=True, exist_ok=True)
    (output_root / "events.jsonl").write_text("{}", encoding="utf-8")
    (output_root / "trend_report.html").write_text("<html>trend</html>", encoding="utf-8")

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(output_root)])

    assert result.exit_code == 0, result.stdout
    assert opened == [(latest / "reports" / "report.html").resolve().as_uri()]


def test_report_open_does_not_consider_unrelated_trash_paths(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    latest = _make_report_run(output_root / "run_20260315T045641Z_project")
    trash_run = _make_report_run(tmp_path / ".local" / "share" / "Trash" / "run_20990101T000000Z_stale")

    now = time.time()
    _set_mtime(latest, now - 10)
    _set_mtime(trash_run, now)
    monkeypatch.chdir(tmp_path)

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open"])

    assert result.exit_code == 0, result.stdout
    assert opened == [(latest / "reports" / "report.html").resolve().as_uri()]
    assert "Trash" not in result.stdout


def test_report_open_skips_latest_run_missing_html_report(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    older_valid = _make_report_run(output_root / "run_20260315T045642Z_valid")
    newer_invalid = _make_report_run(output_root / "run_20260315T045643Z_missing", report_html=False)

    now = time.time()
    _set_mtime(older_valid, now - 10)
    _set_mtime(newer_invalid, now)

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(output_root)])

    assert result.exit_code == 0, result.stdout
    assert opened == [(older_valid / "reports" / "report.html").resolve().as_uri()]


def test_report_open_specific_run_dir_still_works(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    requested = _make_report_run(output_root / "run_20260315T045644Z_requested")
    _make_report_run(output_root / "run_20260315T045645Z_other")

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(requested)])

    assert result.exit_code == 0, result.stdout
    assert opened == [(requested / "reports" / "report.html").resolve().as_uri()]


def test_report_open_accepts_direct_report_html_path(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    requested = _make_report_run(tmp_path / "output" / "run_20260315T045644Z_requested")
    report_path = requested / "reports" / "report.html"

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(report_path)])

    assert result.exit_code == 0, result.stdout
    assert opened == [report_path.resolve().as_uri()]
    assert "20260315T045644Z_requested" in result.stdout


def test_report_open_explains_search_when_no_valid_report_exists(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    _make_report_run(output_root / "run_20260315T045646Z_missing", report_html=False)

    opened: list[str] = []
    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: opened.append(uri) or True)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(output_root)])

    assert result.exit_code == 2, result.stdout
    assert opened == []
    assert "No valid run_* directories containing reports/report.html found under" in result.stdout


def test_report_open_fails_when_browser_launch_returns_false(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    report_run = _make_report_run(tmp_path / "output" / "run_20260315T045647Z_launch_fail")

    monkeypatch.setattr("attackcastle.cli.webbrowser.open", lambda uri: False)

    result = runner.invoke(app, ["report", "open", "--run-dir", str(report_run)])

    assert result.exit_code == 2, result.stdout
    assert "Default browser could not be opened automatically" in result.stdout
    assert "--no-launch" in result.stdout


def test_report_rebuild_run_dir_output_root_resolves_latest_valid_run(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    older = _make_report_run(output_root / "run_20260315T045648Z_old")
    newer = _make_report_run(output_root / "run_20260315T045649Z_new")
    (older / "data" / "scan_data.json").write_text("{}", encoding="utf-8")
    (newer / "data" / "scan_data.json").write_text("{}", encoding="utf-8")

    now = time.time()
    _set_mtime(older, now - 10)
    _set_mtime(newer, now)

    built_from: list[Path] = []
    captured_audiences: list[str] = []

    class StubRunStore:
        def __init__(self, root: Path) -> None:
            self.root = root

        def read_json(self, relative_path: str) -> dict[str, object]:
            assert relative_path == "data/scan_data.json"
            return {}

    class StubReportBuilder:
        def build(
            self,
            run_data,
            run_store,
            *,
            audience: str,
            export_csv: bool,
            export_json_summary: bool,
            export_pdf: bool,
        ) -> dict[str, object]:
            built_from.append(run_store.root)
            captured_audiences.append(audience)
            return {
                "report_path": run_store.root / "reports" / "report.html",
                "summary_path": run_store.root / "reports" / "report_summary.json",
                "csv_paths": [],
                "pdf_path": None,
            }

    monkeypatch.setattr("attackcastle.cli.RunStore.from_existing", lambda path: StubRunStore(path))
    monkeypatch.setattr("attackcastle.cli.run_data_from_dict", lambda payload: object())
    monkeypatch.setattr("attackcastle.cli.ReportBuilder", StubReportBuilder)

    result = runner.invoke(app, ["report", "rebuild", "--run-dir", str(output_root)])

    assert result.exit_code == 0, result.stdout
    assert built_from == [newer.resolve()]
    assert captured_audiences == ["consultant"]
    assert str(newer.resolve()) in result.stdout


def test_report_rebuild_explains_when_scan_data_is_invalid_json(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = _make_report_run(tmp_path / "output" / "run_20260315T045649Z_invalid_scan")
    (run_dir / "data" / "scan_data.json").write_text("{not-json", encoding="utf-8")

    result = runner.invoke(app, ["report", "rebuild", "--run-dir", str(run_dir)])

    assert result.exit_code == 2, result.stdout
    assert "Failed to rebuild report." in result.stdout
    assert "data/scan_data.json is invalid JSON" in result.stdout
    assert "Repair or regenerate data/scan_data.json" in result.stdout


def test_evidence_list_output_root_skips_newer_run_missing_scan_data(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    older = _make_report_run(output_root / "run_20260315T045650Z_complete")
    newer = _make_report_run(output_root / "run_20260315T045651Z_partial")
    _write_scan_data(older)

    now = time.time()
    _set_mtime(older, now - 10)
    _set_mtime(newer, now)

    stub_run_data = type("StubRunData", (), {"evidence": []})()
    monkeypatch.setattr("attackcastle.cli._load_run_data", lambda path: stub_run_data)

    result = runner.invoke(app, ["evidence", "list", "--run-dir", str(output_root), "--output-format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["run_dir"] == str(older.resolve())


def test_evidence_list_accepts_direct_scan_data_path(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    requested = _make_report_run(tmp_path / "output" / "run_20260315T045650Z_complete")
    scan_data_path = requested / "data" / "scan_data.json"
    _write_scan_data(requested)

    stub_run_data = type("StubRunData", (), {"evidence": []})()
    monkeypatch.setattr("attackcastle.cli._load_run_data", lambda path: stub_run_data)

    result = runner.invoke(
        app,
        ["evidence", "list", "--run-dir", str(scan_data_path), "--output-format", "json"],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["run_dir"] == str(requested.resolve())


def test_evidence_list_explains_when_scan_data_is_invalid_json(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = _make_report_run(tmp_path / "output" / "run_20260315T045651Z_invalid")
    _write_scan_data(run_dir, payload="{not-json")

    result = runner.invoke(app, ["evidence", "list", "--run-dir", str(run_dir), "--output-format", "json"])

    assert result.exit_code == 2, result.stdout
    assert "Evidence listing failed." in result.stdout
    assert "data/scan_data.json is invalid JSON" in result.stdout
    assert "Repair or regenerate data/scan_data.json" in result.stdout


def test_findings_list_output_root_skips_newer_run_missing_scan_data(tmp_path: Path) -> None:
    runner = CliRunner()
    output_root = tmp_path / "output"
    older = _make_report_run(output_root / "run_20260315T045652Z_complete")
    newer = _make_report_run(output_root / "run_20260315T045653Z_partial")
    _write_scan_data(
        older,
        payload=json.dumps(
            {
                "metadata": {
                    "run_id": "run_20260315T045652Z_complete",
                    "target_input": "example.com",
                    "profile": "cautious",
                    "output_dir": str(older),
                    "started_at": "2026-03-15T04:56:52+00:00",
                },
                "findings": [],
            }
        ),
    )

    now = time.time()
    _set_mtime(older, now - 10)
    _set_mtime(newer, now)

    result = runner.invoke(app, ["findings", "list", "--run-dir", str(output_root), "--output-format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["run_dir"] == str(older.resolve())
    assert payload["finding_count"] == 0


def test_findings_list_explains_when_scan_data_is_not_a_json_object(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = _make_report_run(tmp_path / "output" / "run_20260315T045654Z_invalid_shape")
    _write_scan_data(run_dir, payload="[]")

    result = runner.invoke(app, ["findings", "list", "--run-dir", str(run_dir), "--output-format", "json"])

    assert result.exit_code == 2, result.stdout
    assert "Could not load findings from run." in result.stdout
    assert "data/scan_data.json did not contain a JSON object" in result.stdout
    assert "Repair or regenerate data/scan_data.json" in result.stdout
