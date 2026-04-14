from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication

from attackcastle.gui.models import RunSnapshot
from attackcastle.gui.scanner_panel import ScannerPanel


def _make_snapshot(tmp_path: Path) -> RunSnapshot:
    return RunSnapshot(
        run_id="run-scanner",
        scan_name="Scanner Run",
        run_dir=str(tmp_path / "run-scanner"),
        state="running",
        elapsed_seconds=18.0,
        eta_seconds=42.0,
        current_task="Web Probe",
        total_tasks=3,
        completed_tasks=1,
        tasks=[
            {
                "key": "web-probe",
                "label": "Web Probe",
                "status": "running",
                "started_at": "2026-04-09T12:00:00+00:00",
                "ended_at": "",
                "detail": {"capability": "httpx"},
            }
        ],
        tool_executions=[
            {
                "execution_id": "exec-httpx",
                "tool_name": "httpx",
                "status": "running",
                "exit_code": None,
                "started_at": "2026-04-09T12:00:00+00:00",
                "stdout_path": str(tmp_path / "run-scanner" / "logs" / "httpx.stdout.txt"),
            }
        ],
    )


def test_scanner_panel_task_context_menu_routes_selected_row_to_handler(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()
    calls: list[tuple[str, dict[str, object]]] = []
    panel.set_context_menu_handler(lambda kind, _table, _point, row: calls.append((kind, row)))
    panel.set_snapshot(_make_snapshot(tmp_path))
    panel.resize(1200, 800)
    panel.show()
    app.processEvents()

    try:
        index = panel.tasks_model.index(0, 0)
        point = panel.tasks_view.visualRect(index).center()

        panel._open_context_menu(panel.tasks_view, point)

        assert panel.tasks_view.selectionModel().currentIndex().row() == 0
        assert calls == [("task", panel.tasks_model.index(0, 0).data(Qt.UserRole))]
    finally:
        panel.close()


def test_scanner_panel_tool_context_menu_routes_selected_row_to_handler(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()
    calls: list[tuple[str, dict[str, object]]] = []
    panel.set_context_menu_handler(lambda kind, _table, _point, row: calls.append((kind, row)))
    panel.set_snapshot(_make_snapshot(tmp_path))
    panel.resize(1200, 800)
    panel.show()
    app.processEvents()

    try:
        index = panel.tools_model.index(0, 0)
        point = panel.tools_view.visualRect(index).center()

        panel._open_context_menu(panel.tools_view, point)

        assert panel.tools_view.selectionModel().currentIndex().row() == 0
        assert calls == [("tool", panel.tools_model.index(0, 0).data(Qt.UserRole))]
    finally:
        panel.close()


def test_scanner_panel_stacks_inspector_until_workspace_is_wide() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()

    try:
        panel.resize(1240, 760)
        panel.sync_responsive_mode(panel.width())
        assert panel.main_split.orientation() == Qt.Vertical

        panel.resize(1320, 760)
        panel.sync_responsive_mode(panel.width())
        assert panel.main_split.orientation() == Qt.Horizontal
        sizes = panel.main_split.sizes()
        assert sizes[0] > sizes[1]
    finally:
        panel.close()
