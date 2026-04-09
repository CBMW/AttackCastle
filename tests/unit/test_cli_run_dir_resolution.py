from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
import typer

from attackcastle.cli import _resolve_run_dir, _resolve_scan_data_run_dir


def _make_run_dir(path: Path) -> Path:
    run_dir = path
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    return run_dir


def test_resolve_run_dir_accepts_explicit_run_directory(tmp_path: Path) -> None:
    run_dir = _make_run_dir(tmp_path / "run_20260101T000000Z_test")
    resolved = _resolve_run_dir(
        run_dir=str(run_dir),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
    )
    assert resolved == run_dir.resolve()


def test_resolve_run_dir_accepts_nested_directory_inside_run(tmp_path: Path) -> None:
    run_dir = _make_run_dir(tmp_path / "run_20260101T000000Z_nested")
    nested_dir = run_dir / "data"

    resolved = _resolve_run_dir(
        run_dir=str(nested_dir),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
    )

    assert resolved == run_dir.resolve()


def test_resolve_run_dir_accepts_artifact_file_inside_run(tmp_path: Path) -> None:
    run_dir = _make_run_dir(tmp_path / "run_20260101T000000Z_artifact")
    report_path = run_dir / "reports" / "report.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("<html>report</html>", encoding="utf-8")

    resolved = _resolve_run_dir(
        run_dir=str(report_path),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
        validator=lambda path: (path / "reports" / "report.html").exists(),
        search_label="reports/report.html",
    )

    assert resolved == run_dir.resolve()


def test_resolve_run_dir_selects_latest_child_when_parent_output_provided(tmp_path: Path) -> None:
    older = _make_run_dir(tmp_path / "run_20260101T000000Z_old")
    newer = _make_run_dir(tmp_path / "run_20260101T000001Z_new")
    (older / "data" / "run_summary.json").write_text("{}", encoding="utf-8")
    (newer / "data" / "run_summary.json").write_text("{}", encoding="utf-8")
    # Parent can have stray top-level run artifacts and should still resolve latest child run_*.
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    # Force deterministic ordering by mtime.
    now = time.time()
    os.utime(older, (now - 10, now - 10))
    os.utime(newer, (now, now))

    resolved = _resolve_run_dir(
        run_dir=str(tmp_path),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
    )
    assert resolved == newer.resolve()


def test_resolve_run_dir_raises_for_missing_path_when_required(tmp_path: Path) -> None:
    missing = tmp_path / "run_missing"
    with pytest.raises(typer.BadParameter):
        _resolve_run_dir(
            run_dir=str(missing),
            run_id=None,
            output_dir=str(tmp_path),
            required=True,
        )


def test_resolve_run_dir_prefers_completed_run_with_summary(tmp_path: Path) -> None:
    completed = _make_run_dir(tmp_path / "run_20260101T000000Z_completed")
    planning_only = _make_run_dir(tmp_path / "run_20260101T000001Z_planning")
    (completed / "data" / "run_summary.json").write_text("{}", encoding="utf-8")

    now = time.time()
    os.utime(completed, (now - 10, now - 10))
    os.utime(planning_only, (now, now))

    resolved = _resolve_run_dir(
        run_dir=str(tmp_path),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
    )
    assert resolved == completed.resolve()


def test_resolve_run_dir_can_filter_to_latest_valid_report_run(tmp_path: Path) -> None:
    older = _make_run_dir(tmp_path / "run_20260101T000000Z_old")
    newer_missing_report = _make_run_dir(tmp_path / "run_20260101T000001Z_new")
    (older / "reports").mkdir(parents=True, exist_ok=True)
    (older / "reports" / "report.html").write_text("<html>old</html>", encoding="utf-8")
    (older / "data" / "run_summary.json").write_text("{}", encoding="utf-8")
    (newer_missing_report / "data" / "run_summary.json").write_text("{}", encoding="utf-8")

    now = time.time()
    os.utime(older, (now - 10, now - 10))
    os.utime(newer_missing_report, (now, now))

    resolved = _resolve_run_dir(
        run_dir=str(tmp_path),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
        validator=lambda path: (path / "reports" / "report.html").exists(),
        search_label="reports/report.html",
    )

    assert resolved == older.resolve()


def test_resolve_scan_data_run_dir_skips_newer_run_missing_scan_data(tmp_path: Path) -> None:
    older = _make_run_dir(tmp_path / "run_20260101T000000Z_complete")
    newer_missing_scan = _make_run_dir(tmp_path / "run_20260101T000001Z_partial")
    (older / "data" / "scan_data.json").write_text("{}", encoding="utf-8")
    (older / "data" / "run_summary.json").write_text("{}", encoding="utf-8")
    (newer_missing_scan / "data" / "run_summary.json").write_text("{}", encoding="utf-8")

    now = time.time()
    os.utime(older, (now - 10, now - 10))
    os.utime(newer_missing_scan, (now, now))

    resolved = _resolve_scan_data_run_dir(
        run_dir=str(tmp_path),
        run_id=None,
        output_dir=str(tmp_path),
        required=True,
    )

    assert resolved == older.resolve()
