from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication, QTabWidget

from attackcastle.gui.models import RunSnapshot
from attackcastle.gui.scanner_panel import ScannerPanel


def _make_snapshot(tmp_path: Path) -> RunSnapshot:
    log_dir = tmp_path / "run-scanner" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / "httpx.stdout.txt"
    stdout_path.write_text("   __    __\n  / /_  / /_\nhttps://example.com/ [200]\n", encoding="utf-8")
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
                "detail": {
                    "capability": "httpx",
                    "instance_key": "web-probe::iter1::abc",
                    "task_inputs": ["https://example.com/"],
                },
            }
        ],
        tool_executions=[
            {
                "execution_id": "exec-httpx",
                "tool_name": "httpx",
                "command": "httpx -redacted",
                "raw_command": "httpx -silent -u https://example.com/",
                "task_instance_key": "web-probe::iter1::abc",
                "task_inputs": ["https://example.com/"],
                "status": "running",
                "exit_code": None,
                "started_at": "2026-04-09T12:00:00+00:00",
                "stdout_path": str(stdout_path),
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


def test_scanner_panel_tool_runs_show_elapsed_column(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()
    snapshot = _make_snapshot(tmp_path)
    snapshot.tool_executions[0]["status"] = "completed"
    snapshot.tool_executions[0]["ended_at"] = "2026-04-09T12:01:05+00:00"

    try:
        panel.set_snapshot(snapshot)

        headers = [
            panel.tools_model.headerData(column, Qt.Horizontal)
            for column in range(panel.tools_model.columnCount())
        ]
        assert headers == ["Tool", "Status", "Elapsed", "Exit", "Started"]
        assert panel.tools_model.index(0, 2).data(Qt.DisplayRole) == "01:05"
        assert panel._elapsed_timer.isActive() is False
    finally:
        panel.close()


def test_scanner_panel_refreshes_running_tool_elapsed_cells(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()

    try:
        panel.set_snapshot(_make_snapshot(tmp_path))

        assert panel._elapsed_timer.isActive() is True
        assert panel.tools_model.index(0, 2).data(Qt.DisplayRole)
    finally:
        panel.close()


def test_scanner_panel_keeps_selected_task_details_across_refresh(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()

    try:
        panel.set_snapshot(_make_snapshot(tmp_path))
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)
        assert "- status: running" in panel.detail_text.toPlainText()

        updated = _make_snapshot(tmp_path)
        updated.tasks[0]["status"] = "completed"
        updated.tasks[0]["detail"] = {
            "capability": "nmap",
            "ports": "80,443",
            "instance_key": "web-probe::iter1::abc",
            "task_inputs": ["https://example.com/"],
        }
        panel.set_snapshot(updated)

        assert "- status: completed" in panel.detail_text.toPlainText()
        assert '"status": "completed"' in panel.raw_text.toPlainText()
        assert panel.tasks_view.selectionModel().currentIndex().row() == 0
    finally:
        panel.close()


def test_scanner_panel_preserves_inspector_scroll_across_refresh(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    snapshot = _make_snapshot(tmp_path)
    stdout_path = Path(str(snapshot.tool_executions[0]["stdout_path"]))
    stdout_path.write_text("\n".join(f"line {index}" for index in range(240)), encoding="utf-8")

    try:
        panel.resize(700, 360)
        panel.show()
        panel.set_snapshot(snapshot)
        panel._task_selected(panel.tasks_model.index(0, 0))
        panel.inspector_tabs.setCurrentIndex(2)
        app.processEvents()

        scrollbar = panel.output_text.verticalScrollBar()
        assert scrollbar.maximum() > 0
        scrollbar.setValue(scrollbar.maximum())
        scrolled_position = scrollbar.value()

        panel.set_snapshot(snapshot)
        app.processEvents()

        assert panel.output_text.verticalScrollBar().value() == scrolled_position
    finally:
        panel.close()


def test_scanner_panel_task_details_copy_exact_raw_command(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    panel = ScannerPanel()

    try:
        panel.set_snapshot(_make_snapshot(tmp_path))
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)
        assert panel.command_text.toPlainText() == "httpx -silent -u https://example.com/"
        assert "1. httpx" not in panel.command_text.toPlainText()
        assert panel.command_copy_button.isEnabled() is True

        panel.command_copy_button.click()

        assert app.clipboard().text() == "httpx -silent -u https://example.com/"
    finally:
        panel.close()


def test_scanner_panel_task_details_copy_each_inspector_section(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    panel = ScannerPanel()

    try:
        panel.set_snapshot(_make_snapshot(tmp_path))
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)

        assert panel.detail_copy_button.isEnabled() is True
        panel.detail_copy_button.click()
        assert app.clipboard().text() == panel.detail_text.toPlainText()

        assert panel.command_copy_button.isEnabled() is True
        panel.command_copy_button.click()
        assert app.clipboard().text() == panel.command_text.toPlainText()

        assert panel.output_copy_button.isEnabled() is True
        panel.output_copy_button.click()
        assert app.clipboard().text() == panel.output_text.toPlainText()

        assert panel.raw_copy_button.isEnabled() is True
        panel.raw_copy_button.click()
        assert app.clipboard().text() == panel.raw_text.toPlainText()
    finally:
        panel.close()


def test_scanner_panel_task_details_show_literal_command_output(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()

    try:
        panel.set_snapshot(_make_snapshot(tmp_path))
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)

        assert panel.output_text.toPlainText() == "   __    __\n  / /_  / /_\nhttps://example.com/ [200]"
    finally:
        panel.close()


def test_scanner_panel_internal_vhost_task_does_not_render_description_as_command(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()
    snapshot = _make_snapshot(tmp_path)
    snapshot.tasks[0]["key"] = "vhost_discovery"
    snapshot.tasks[0]["label"] = "Discovering virtual hosts"
    snapshot.tasks[0]["detail"] = {
        "capability": "vhost_discovery",
        "instance_key": "vhost::iter1::abc",
        "task_inputs": ["https://example.com/"],
    }
    snapshot.tool_executions[0].update(
        {
            "execution_id": "exec-vhost",
            "tool_name": "vhost_discovery",
            "command": "internal host-header virtual host discovery",
            "raw_command": "internal host-header virtual host discovery",
            "capability": "vhost_discovery",
            "task_instance_key": "vhost::iter1::abc",
        }
    )

    try:
        panel.set_snapshot(snapshot)
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)

        assert panel.command_text.toPlainText() == "No Data"
        assert "internal host-header virtual host discovery" not in panel.command_text.toPlainText()
    finally:
        panel.close()


def test_scanner_panel_task_details_render_matched_debug_bundle(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    snapshot = _make_snapshot(tmp_path)

    try:
        panel.set_snapshot(snapshot)
        index = panel.tasks_model.index(0, 0)

        panel._task_selected(index)

        assert "Task" in panel.detail_text.toPlainText()
        assert "- key: web-probe" in panel.detail_text.toPlainText()
        assert '"matched_tool_executions"' in panel.raw_text.toPlainText()
        assert '"execution_id": "exec-httpx"' in panel.raw_text.toPlainText()
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


def test_scanner_panel_uses_group_and_inspector_tab_roles() -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    panel = ScannerPanel()

    try:
        tab_widgets = {tabs.objectName(): tabs for tabs in panel.findChildren(QTabWidget)}

        assert panel.tabs.objectName() == "groupTabs"
        assert panel.tabs.property("tabRole") == "group"
        assert panel.tabs.tabBar().objectName() == "groupTabBar"
        assert panel.inspector_tabs.objectName() == "inspectorTabs"
        assert panel.inspector_tabs.property("tabRole") == "inspector"
        assert panel.inspector_tabs.tabBar().objectName() == "inspectorTabBar"
        assert "subTabs" not in tab_widgets
        assert panel.tabs.widget(panel.tasks_tab_index).property("surface") == "flat"
        assert panel.inspector_tabs.widget(0).property("surface") == "flat"
        assert panel.inspector_tabs.widget(1).property("surface") == "flat"
    finally:
        panel.close()
