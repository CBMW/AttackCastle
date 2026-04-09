from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QProcess, QPoint, QRect, Qt
from PySide6.QtGui import QShortcut
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFrame, QGroupBox, QLabel, QMessageBox, QPushButton, QMenu

from attackcastle.gui.main_window import MainWindow
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.models import Engagement, RunRegistryEntry, RunSnapshot, Workspace
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.worker_protocol import WorkerEvent
from attackcastle.gui.workspace_store import WorkspaceStore, ad_hoc_output_home
from attackcastle.core.enums import RunState
from attackcastle.core.models import RunData, RunMetadata, TaskArtifactRef, TaskResult, ToolExecution, now_utc
from attackcastle.storage.run_store import RunStore


def _make_window(tmp_path: Path) -> MainWindow:
    app = QApplication.instance() or QApplication([])
    _ = app
    return MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )


def _make_workspace_window(tmp_path: Path, active_workspace_id: str, *workspace_names: tuple[str, str]) -> tuple[MainWindow, WorkspaceStore]:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    for workspace_id, name in workspace_names:
        workspace_store.save_engagement(Engagement(engagement_id=workspace_id, name=name))
    workspace_store.set_active_workspace(active_workspace_id)
    return MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store), workspace_store


def test_navigation_defaults_to_workspace_and_uses_workflow_sections(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        sections = [window.nav_list.item(idx).text() for idx in range(window.nav_list.count())]

        assert sections == ["Workspaces", "Scanner", "Assets", "Findings", "Profiles", "Extensions", "Settings"]
        assert window.nav_list.currentItem() is not None
        assert window.nav_list.currentItem().text() == "Workspaces"
        assert window.section_stack.currentWidget() is window.workspace_page
    finally:
        window._refresh_timer.stop()
        window.close()


def test_no_workspace_mode_keeps_session_controls_available(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert window._active_workspace() is None
        assert window.start_scan_button.isEnabled()
        assert not window.findChildren(QFrame, "headerPanel")
        assert not window.no_workspace_button.isVisible()
        assert window.no_workspace_button.isEnabled() is False
    finally:
        window._refresh_timer.stop()
        window.close()


def test_keyboard_shortcuts_cover_primary_navigation_and_operator_actions(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        shortcuts = {shortcut.key().toString() for shortcut in window.findChildren(QShortcut)}

        assert {"Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6", "Ctrl+7"}.issubset(shortcuts)
        assert {"Ctrl+N", "Ctrl+F", "Ctrl+R", "Ctrl+P", "Ctrl+O"}.issubset(shortcuts)
        assert "Ctrl+K" not in shortcuts
    finally:
        window._refresh_timer.stop()
        window.close()


def test_initial_geometry_clamps_to_available_screen_space(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        geometry = QRect(0, 0, 1024, 700)
        window._apply_initial_geometry(geometry)

        assert window.width() <= 1024
        assert window.height() <= 700
        assert window.width() == MainWindow._fit_dimension(1560, 1024, 0.96)
        assert window.height() == MainWindow._fit_dimension(980, 700, 0.92)
    finally:
        window._refresh_timer.stop()
        window.close()


def test_restore_geometry_uses_smaller_manageable_window_size(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        geometry = QRect(0, 0, 1024, 700)
        window._apply_restore_geometry(geometry)

        assert window.width() < geometry.width()
        assert window.height() < geometry.height()
        assert window.width() == MainWindow._fit_restore_dimension(1440, 1024, 0.82, 820)
        assert window.height() == MainWindow._fit_restore_dimension(900, 700, 0.82, 620)
    finally:
        window._refresh_timer.stop()
        window.close()


def test_main_window_minimum_height_stays_shrinkable(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert window.minimumSizeHint().height() < 700
    finally:
        window._refresh_timer.stop()
        window.close()


def test_run_actions_show_empty_selection_guidance(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        window._selected_run_id = None
        window._update_run_action_state()

        assert "No run selected" in window.selected_run_status_label.text()
        assert "disabled until a run is selected" in window.run_actions_hint_label.text()
        assert not window.pause_button.isEnabled()
        assert not window.open_output_button.isEnabled()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_runs_page_actions_update_for_selected_run(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-1",
            scan_name="Client Alpha External",
            run_dir=str(tmp_path / "run-1"),
            state="running",
            elapsed_seconds=90.0,
            eta_seconds=120.0,
            current_task="Nmap",
            total_tasks=10,
            completed_tasks=4,
            engagement_id="eng-1",
            engagement_name="Client Alpha",
            target_input="example.com",
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id

        window._update_run_action_state()

        assert window.selected_run_status_label.text() == "Client Alpha External is Running and 40% complete."
        assert "Pause, Stop, or Skip Task" in window.run_actions_hint_label.text()
        assert "Client Alpha" in window.general_status_detail.text()
        assert window.pause_button.isEnabled()
        assert window.open_output_button.isEnabled()
    finally:
        window._refresh_timer.stop()
        window.close()


@pytest.mark.parametrize(
    ("state", "pause_requested", "resume_required", "pause_enabled", "resume_enabled"),
    [
        ("running", False, False, True, False),
        ("paused", False, False, False, True),
        ("running", True, True, False, True),
    ],
)
def test_run_context_menu_actions_reflect_pause_resume_state(
    tmp_path: Path,
    state: str,
    pause_requested: bool,
    resume_required: bool,
    pause_enabled: bool,
    resume_enabled: bool,
) -> None:
    window = _make_window(tmp_path)
    run_dir = tmp_path / f"run-{state}"
    run_dir.mkdir()

    try:
        snapshot = RunSnapshot(
            run_id=f"run-{state}",
            scan_name="Context Menu Run",
            run_dir=str(run_dir),
            state=state,
            elapsed_seconds=30.0,
            eta_seconds=60.0,
            current_task="Probe",
            total_tasks=5,
            completed_tasks=2,
            pause_requested=pause_requested,
            resume_required=resume_required,
            tasks=[{"key": "probe", "label": "Probe", "status": state}],
        )

        menu, pause_action, resume_action, debug_action, current_task_action = window._build_run_context_menu(
            window.run_table,
            snapshot,
        )

        assert [action.text() for action in menu.actions() if action.text()] == [
            "Pause Scan",
            "Resume",
            "View Debug Log",
            "View Current Task Debug Log",
        ]
        assert pause_action.isEnabled() is pause_enabled
        assert resume_action.isEnabled() is resume_enabled
        assert debug_action.isEnabled() is True
        assert current_task_action.isEnabled() is True
    finally:
        window._refresh_timer.stop()
        window.close()


@pytest.mark.parametrize(("table_name", "search_name"), [("run_table", "run_search_edit"), ("workspace_run_table", "workspace_run_search_edit")])
def test_run_context_menu_selects_row_before_showing_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    table_name: str,
    search_name: str,
) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    window = _make_window(tmp_path)
    run_dir = tmp_path / "run-select"
    run_dir.mkdir()

    try:
        window._run_snapshots["run-select"] = RunSnapshot(
            run_id="run-select",
            scan_name="Selectable Run",
            run_dir=str(run_dir),
            state="running",
            elapsed_seconds=12.0,
            eta_seconds=44.0,
            current_task="Resolve Hosts",
            total_tasks=3,
            completed_tasks=1,
            tasks=[{"key": "resolve-hosts", "label": "Resolve Hosts", "status": "running"}],
        )
        getattr(window, search_name).clear()
        window._sync_run_table()
        window.show()
        app.processEvents()
        table = getattr(window, table_name)
        index = table.model().index(0, 0)
        point = table.visualRect(index).center()
        monkeypatch.setattr(QMenu, "exec", lambda self, *_args, **_kwargs: None)

        window._open_run_context_menu(table, point)

        assert table.selectionModel().currentIndex().row() == 0
        assert window._selected_run_id == "run-select"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_refresh_runs_reloads_active_run_snapshot_from_disk(tmp_path: Path) -> None:
    window = _make_window(tmp_path)
    run_store = RunStore(output_root=tmp_path, run_id="live-refresh")
    started_at = now_utc()
    stdout_path = run_store.logs_dir / "probe.stdout.txt"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text("hydrated stdout", encoding="utf-8")
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "Live Refresh",
            "run_id": "live-refresh",
            "started_at": started_at.isoformat(),
            "target_input": "example.com",
        },
    )
    run_store.write_json("data/plan.json", {"items": [{"key": "web-probe", "selected": True}]})
    run_store.save_checkpoint(
        "web-probe",
        "running",
        RunData(
            metadata=RunMetadata(
                run_id="live-refresh",
                target_input="example.com",
                profile="prototype",
                output_dir=str(run_store.run_dir),
                started_at=started_at,
                state=RunState.RUNNING,
            ),
            task_states=[
                {
                    "key": "web-probe",
                    "label": "Web Probe",
                    "status": "running",
                    "started_at": started_at.isoformat(),
                    "ended_at": "",
                    "detail": {"capability": "httpx"},
                }
            ],
            task_results=[
                TaskResult(
                    task_id="task-web-probe",
                    task_type="web-probe",
                    status="running",
                    command="httpx -json example.com",
                    exit_code=None,
                    started_at=started_at,
                    finished_at=started_at,
                    raw_artifacts=[TaskArtifactRef(artifact_type="stdout", path=str(stdout_path))],
                )
            ],
            tool_executions=[
                ToolExecution(
                    execution_id="exec-httpx",
                    tool_name="httpx",
                    command="httpx -json example.com",
                    started_at=started_at,
                    ended_at=started_at,
                    exit_code=0,
                    status="completed",
                    capability="httpx",
                    stdout_path=str(stdout_path),
                )
            ],
        ),
    )

    try:
        window._run_snapshots["live-refresh"] = RunSnapshot(
            run_id="live-refresh",
            scan_name="Live Refresh",
            run_dir=str(run_store.run_dir),
            state="running",
            elapsed_seconds=1.0,
            eta_seconds=None,
            current_task="Idle",
            total_tasks=0,
            completed_tasks=0,
        )

        window._refresh_runs()

        refreshed = window._run_snapshots["live-refresh"]
        assert refreshed.current_task == "Web Probe"
        assert refreshed.tool_executions[0]["tool_name"] == "httpx"
        assert refreshed.task_results[0]["task_type"] == "web-probe"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_workspace_dashboard_prioritizes_critical_and_validation_metrics(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-1",
            scan_name="Prod External",
            run_dir=str(tmp_path / "run-1"),
            state="running",
            elapsed_seconds=45.0,
            eta_seconds=90.0,
            current_task="Nuclei",
            total_tasks=8,
            completed_tasks=3,
            findings=[
                {"finding_id": "f-1", "severity": "high", "title": "High"},
                {"finding_id": "f-2", "severity": "low", "title": "Low"},
            ],
            engagement_id="eng-1",
            engagement_name="Prod",
            target_input="example.com",
        )
        window._run_snapshots[snapshot.run_id] = snapshot

        window._refresh_dashboard()

        assert window.card_active_runs.value_label.text() == "1"
        assert window.card_critical_findings.value_label.text() == "1"
        assert window.card_needs_validation.value_label.text() == "2"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_workspace_view_omits_removed_status_and_summary_sections(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        panel_titles = {group.title() for group in window.findChildren(QGroupBox)}

        assert not window.findChildren(QFrame, "statusPanel")
        assert "Workspace Brief" not in panel_titles
        assert "Selected Run" not in panel_titles
        assert "Operator Alerts" not in panel_titles
    finally:
        window._refresh_timer.stop()
        window.close()


def test_launch_controls_live_in_scanner_page_not_workspace_page(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        workspace_titles = {group.title() for group in window.workspace_page.findChildren(QGroupBox)}
        scanner_titles = {group.title() for group in window.runs_page.findChildren(QGroupBox)}

        assert "Start New Scan" not in workspace_titles
        assert "Start New Scan" in scanner_titles
        assert window.start_scan_button.parentWidget() is not None
        assert window.runs_page.isAncestorOf(window.start_scan_button)
    finally:
        window._refresh_timer.stop()
        window.close()


def test_main_window_exposes_resizable_splitters_for_primary_sections(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert window.body_split.count() == 2
        assert window.workspace_primary_split.count() == 2
        assert window.runs_page_split.count() == 2
        assert window.runs_top_split.count() == 2
        assert window.runs_body_split.count() == 2
        assert window.output_tab.main_split.count() == 2
        assert window.assets_tab.main_split.count() == 2
        assert window.settings_split.count() == 2
    finally:
        window._refresh_timer.stop()
        window.close()


def test_header_strip_is_removed_to_free_vertical_space(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert not window.findChildren(QLabel, "logoBadge")
        assert not window.findChildren(QLabel, "appTitle")
        assert not window.findChildren(QLabel, "appSubtitle")
        assert not window.findChildren(QFrame, "headerPanel")
        assert "Quick Actions" not in {button.text() for button in window.findChildren(QPushButton)}
    finally:
        window._refresh_timer.stop()
        window.close()


def test_findings_workspace_groups_output_by_operator_task(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        tabs = [window.output_tab.primary_tabs.tabText(idx) for idx in range(window.output_tab.primary_tabs.count())]

        assert tabs == ["Findings", "Validation", "Evidence"]
    finally:
        window._refresh_timer.stop()
        window.close()


def test_scanner_detail_tabs_surface_execution_and_audit_views(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        tabs = [window.scanner_panel.tabs.tabText(idx) for idx in range(window.scanner_panel.tabs.count())]

        assert tabs == ["Tasks", "Tool Runs", "Issues", "Health", "Audit"]
    finally:
        window._refresh_timer.stop()
        window.close()


def test_assets_workspace_is_available_in_navigation_and_tracks_selected_run(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-assets",
            scan_name="Asset Heavy Run",
            run_dir=str(tmp_path / "run-assets"),
            state="completed",
            elapsed_seconds=30.0,
            eta_seconds=0.0,
            current_task="Idle",
            total_tasks=2,
            completed_tasks=2,
            workspace_name="Client Alpha",
            target_input="example.com",
            assets=[{"asset_id": "asset-1", "kind": "host", "name": "example.com", "ip": "203.0.113.10"}],
            services=[{"service_id": "svc-1", "asset_id": "asset-1", "port": 443, "protocol": "tcp", "state": "open", "name": "https"}],
            web_apps=[{"webapp_id": "web-1", "asset_id": "asset-1", "service_id": "svc-1", "url": "https://example.com", "status_code": 200}],
        )
        window._run_snapshots[snapshot.run_id] = snapshot

        window._update_output_snapshot(snapshot.run_id)
        window._navigate_to("assets")

        assert window.section_stack.currentWidget() is window.assets_tab
        assert window.assets_tab.title_label.text() == "Asset Heavy Run"
        assert window.assets_tab.assets_model.rowCount() == 1
        assert window.assets_tab.services_model.rowCount() == 1
    finally:
        window._refresh_timer.stop()
        window.close()


def test_extensions_page_bootstraps_default_theme_extension(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        tabs = [window.nav_list.item(idx).text() for idx in range(window.nav_list.count())]
        assert "Extensions" in tabs
        assert window.extensions_tab.extension_list.count() >= 1
        first_item = window.extensions_tab.extension_list.item(0)
        assert first_item is not None
        assert "Theme" in window.extensions_tab.meta_label.text() or "Default Theme" in first_item.text()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_responsive_layout_switches_to_stacked_mode_on_narrow_width(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        window.resize(1100, 800)
        window._sync_responsive_layouts()

        assert window.workspace_content_split.orientation() == Qt.Vertical
        assert window.runs_top_split.orientation() == Qt.Vertical
        assert window.output_tab.main_split.orientation() == Qt.Vertical
    finally:
        window._refresh_timer.stop()
        window.close()


def test_responsive_layout_uses_horizontal_splits_on_wide_width(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        window.resize(1560, 980)
        window._sync_responsive_layouts()

        assert window.workspace_content_split.orientation() == Qt.Horizontal
        assert window.runs_page_split.orientation() == Qt.Horizontal
        assert window.runs_top_split.orientation() == Qt.Vertical
        assert window.runs_body_split.orientation() == Qt.Horizontal
        assert window.output_tab.main_split.orientation() == Qt.Horizontal
    finally:
        window._refresh_timer.stop()
        window.close()


def test_saved_splitter_layout_restores_on_reopen(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")

    first = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)
    try:
        first.resize(1560, 980)
        first._sync_responsive_layouts()
        first.body_split.setSizes([330, 1110])
        saved_sizes = list(first.body_split.sizes())
        controller = first._splitter_controllers["body_split"]
        controller._schedule_save(0, 0)
        controller._flush_save()
    finally:
        first._refresh_timer.stop()
        first.close()

    second = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)
    try:
        second.resize(1560, 980)
        second._sync_responsive_layouts()
        restored = workspace_store.load_ui_layout("body_split", "horizontal")
        assert restored == saved_sizes
        assert second.body_split.sizes() == saved_sizes
    finally:
        second._refresh_timer.stop()
        second.close()


def test_findings_workspace_surfaces_scanner_issue_summary(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-issues",
            scan_name="Issue Heavy Run",
            run_dir=str(tmp_path / "run-issues"),
            state="completed",
            elapsed_seconds=120.0,
            eta_seconds=0.0,
            current_task="Idle",
            total_tasks=5,
            completed_tasks=5,
            engagement_name="Client Alpha",
            target_input="example.com",
            execution_issues=[
                {
                    "issue_id": "issue_1",
                    "kind": "tool",
                    "label": "nmap execution",
                    "status": "failed",
                    "message": "permission denied",
                    "impact": "Network coverage may be incomplete.",
                    "suggested_action": "Review permissions and retry.",
                }
            ],
            execution_issues_summary={"total_count": 1, "completeness_status": "partial"},
            completeness_status="partial",
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id

        window._update_output_snapshot(snapshot.run_id)

        assert window.scanner_panel.issues_model.rowCount() == 1
        assert "Open Scanner > Issues" in window.output_tab.attention_banner.text()
        assert window.output_tab.health_card.value_label.text() == "Partial"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_open_health_selects_scanner_health_tab(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-health",
            scan_name="Health Focus Run",
            run_dir=str(tmp_path / "run-health"),
            state="failed",
            elapsed_seconds=30.0,
            eta_seconds=None,
            current_task="Nuclei",
            total_tasks=3,
            completed_tasks=2,
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id
        window._update_output_snapshot(snapshot.run_id)
        window._update_run_action_state()

        window.open_health_button.click()

        assert window.section_stack.currentWidget() is window.runs_page
        assert window.scanner_panel.tabs.tabText(window.scanner_panel.tabs.currentIndex()) == "Health"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_selected_run_syncs_findings_and_scanner_panels(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-sync",
            scan_name="Sync Run",
            run_dir=str(tmp_path / "run-sync"),
            state="running",
            elapsed_seconds=25.0,
            eta_seconds=50.0,
            current_task="Web Probe",
            total_tasks=4,
            completed_tasks=1,
        )
        window._run_snapshots[snapshot.run_id] = snapshot

        window._update_output_snapshot(snapshot.run_id)

        assert window.output_tab._snapshot is snapshot
        assert window.scanner_panel._snapshot is snapshot
    finally:
        window._refresh_timer.stop()
        window.close()


def test_worker_ready_navigates_to_scanner_and_focuses_tasks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-ready",
            scan_name="Ready Run",
            run_dir=str(tmp_path / "run-ready"),
            state="running",
            elapsed_seconds=0.0,
            eta_seconds=60.0,
            current_task="Starting",
            total_tasks=6,
            completed_tasks=0,
        )
        monkeypatch.setattr("attackcastle.gui.main_window.load_run_snapshot", lambda _path: snapshot)
        process = QProcess(window)

        window._handle_worker_event(
            process,
            WorkerEvent(event="worker.ready", payload={"run_dir": str(tmp_path / "run-ready")}),
        )

        assert window.section_stack.currentWidget() is window.runs_page
        assert window.scanner_panel.tabs.tabText(window.scanner_panel.tabs.currentIndex()) == "Tasks"
        assert window._selected_run_id == snapshot.run_id
    finally:
        window._refresh_timer.stop()
        window.close()


def test_worker_completed_keeps_current_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-complete",
            scan_name="Completed Run",
            run_dir=str(tmp_path / "run-complete"),
            state="completed",
            elapsed_seconds=90.0,
            eta_seconds=0.0,
            current_task="Idle",
            total_tasks=4,
            completed_tasks=4,
        )
        monkeypatch.setattr("attackcastle.gui.main_window.load_run_snapshot", lambda _path: snapshot)
        process = QProcess(window)
        window._navigate_to("assets")

        window._handle_worker_event(
            process,
            WorkerEvent(event="worker.completed", payload={"run_dir": str(tmp_path / "run-complete"), "scan_name": snapshot.scan_name}),
        )

        assert window.section_stack.currentWidget() is window.assets_tab
        assert window._selected_run_id == snapshot.run_id
    finally:
        window._refresh_timer.stop()
        window.close()


def test_apply_task_event_merges_structured_detail_without_crashing(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-task-merge",
            scan_name="Task Merge Run",
            run_dir=str(tmp_path / "run-task-merge"),
            state="running",
            elapsed_seconds=0.0,
            eta_seconds=30.0,
            current_task="Starting",
            total_tasks=1,
            completed_tasks=0,
        )

        window._apply_task_event(
            snapshot,
            "task.started",
            {
                "task": "resolve-hosts",
                "label": "Resolve Hosts",
                "status": "running",
                "started_at": "2026-04-09T01:00:00+00:00",
                "attempt": 1,
                "reason": "dependencies_satisfied",
            },
        )
        window._apply_task_event(
            snapshot,
            "task.completed",
            {
                "task": "resolve-hosts",
                "label": "Resolve Hosts",
                "status": "completed",
                "ended_at": "2026-04-09T01:00:05+00:00",
            },
        )

        assert len(snapshot.tasks) == 1
        assert snapshot.tasks[0]["status"] == "completed"
        assert snapshot.tasks[0]["started_at"] == "2026-04-09T01:00:00+00:00"
        assert snapshot.tasks[0]["ended_at"] == "2026-04-09T01:00:05+00:00"
        assert snapshot.tasks[0]["detail"] == {"attempt": 1, "reason": "dependencies_satisfied"}
        assert snapshot.completed_tasks == 1
    finally:
        window._refresh_timer.stop()
        window.close()


def test_worker_runtime_result_events_update_snapshot_debug_data(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-live-results",
            scan_name="Live Result Run",
            run_dir=str(tmp_path / "run-live-results"),
            state="running",
            elapsed_seconds=0.0,
            eta_seconds=30.0,
            current_task="Enumerate Subdomains",
            total_tasks=1,
            completed_tasks=0,
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        process = QProcess(window)

        window._handle_worker_event(
            process,
            WorkerEvent(
                event="task_result.recorded",
                payload={
                    "run_id": snapshot.run_id,
                    "result": {
                        "task_id": "task-subfinder",
                        "task_type": "EnumerateSubdomains",
                        "status": "completed",
                    },
                },
            ),
        )
        window._handle_worker_event(
            process,
            WorkerEvent(
                event="tool_execution.recorded",
                payload={
                    "run_id": snapshot.run_id,
                    "execution": {
                        "execution_id": "exec-subfinder",
                        "tool_name": "subfinder",
                        "status": "completed",
                    },
                },
            ),
        )
        window._handle_worker_event(
            process,
            WorkerEvent(
                event="artifact.available",
                payload={
                    "run_id": snapshot.run_id,
                    "artifact_path": str(tmp_path / "subfinder.stdout.txt"),
                    "kind": "stdout",
                    "source_tool": "subfinder",
                    "caption": "EnumerateSubdomains stdout",
                    "artifact_id": "artifact-subfinder",
                    "source_task_id": "task-subfinder",
                    "source_execution_id": "exec-subfinder",
                },
            ),
        )

        assert snapshot.task_results[0]["task_id"] == "task-subfinder"
        assert snapshot.tool_executions[0]["execution_id"] == "exec-subfinder"
        assert snapshot.evidence_artifacts[0]["artifact_id"] == "artifact-subfinder"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_engagement_actions_disable_when_selection_is_cleared(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        store = WorkspaceStore(tmp_path / "workspace.json")
        store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
        window._engagements = store.load_engagements()
        window._sync_engagement_list()

        window._engagement_selected(-1)

        assert window._selected_engagement_id == ""
        assert window._get_selected_engagement() is None
        assert not window.edit_engagement_button.isEnabled()
        assert not window.delete_engagement_button.isEnabled()
        assert window.workspace_list.count() == 0
        assert window.start_scan_button.isEnabled()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_workspace_tab_reflects_only_the_active_workspace(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    workspace_store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
    workspace_store.save_engagement(Engagement(engagement_id="eng_beta", name="Beta"))
    workspace_store.set_active_workspace("eng_alpha")
    window = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)

    try:
        assert window._selected_engagement_id == "eng_alpha"
        assert window._get_selected_engagement() is not None
        assert window.workspace_list.count() == 1
        assert "Alpha" in window.workspace_list.item(0).text()
        assert "Active workspace" in window.workspace_tab_context_label.text()
        assert not window.edit_engagement_button.isVisible()
        assert not window.edit_engagement_button.isEnabled()
        assert not window.open_workspace_button.isVisible()
        assert not window.open_workspace_button.isEnabled()
        assert window.start_scan_button.isEnabled()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_overview_checklist_add_updates_visible_rows(tmp_path: Path) -> None:
    window, _store = _make_workspace_window(tmp_path, "eng_alpha", ("eng_alpha", "Alpha"))

    try:
        assert window.overview_checklist_input.text() == ""
        assert len(window._overview_checklist_rows) == 0

        window.overview_checklist_input.setText("Confirm scope boundaries")
        window.overview_checklist_add_button.click()

        assert len(window._overview_checklist_rows) == 1
        assert window._overview_state.checklist_items[0].label == "Confirm scope boundaries"
        assert window.overview_checklist_input.text() == ""
    finally:
        window._refresh_timer.stop()
        window.close()


def test_overview_checklist_row_click_toggles_completion(tmp_path: Path) -> None:
    window, _store = _make_workspace_window(tmp_path, "eng_alpha", ("eng_alpha", "Alpha"))

    try:
        window._add_overview_checklist_item("Validate exclusions")
        row = next(iter(window._overview_checklist_rows.values()))
        window.show()
        QApplication.processEvents()

        QTest.mouseClick(row, Qt.LeftButton, pos=row.rect().center())

        assert window._overview_state.checklist_items[0].completed is True
        assert row.toggle_button.text() == "X"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_overview_checklist_delete_removes_item(tmp_path: Path) -> None:
    window, _store = _make_workspace_window(tmp_path, "eng_alpha", ("eng_alpha", "Alpha"))

    try:
        window._add_overview_checklist_item("Review attack path")
        row = next(iter(window._overview_checklist_rows.values()))
        row.delete_button.setVisible(True)
        row.delete_button.click()

        assert window._overview_state.checklist_items == []
        assert len(window._overview_checklist_rows) == 0
    finally:
        window._refresh_timer.stop()
        window.close()


def test_workspace_overview_state_persists_across_window_reopen(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    workspace_store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
    workspace_store.set_active_workspace("eng_alpha")

    first = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)
    try:
        first._add_overview_checklist_item("Capture recon notes")
        first.overview_notes_edit.setPlainText("Important operator context")
        first._persist_overview_state()
    finally:
        first._refresh_timer.stop()
        first.close()

    second = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)
    try:
        assert len(second._overview_state.checklist_items) == 1
        assert second._overview_state.checklist_items[0].label == "Capture recon notes"
        assert second.overview_notes_edit.toPlainText() == "Important operator context"
    finally:
        second._refresh_timer.stop()
        second.close()


def test_ad_hoc_overview_state_does_not_persist_across_window_reopen(tmp_path: Path) -> None:
    first = _make_window(tmp_path)
    try:
        first._add_overview_checklist_item("Temporary ad-hoc note")
        first.overview_notes_edit.setPlainText("Lost on refresh")
    finally:
        first._refresh_timer.stop()
        first.close()

    second = _make_window(tmp_path)
    try:
        assert second._overview_state.checklist_items == []
        assert second.overview_notes_edit.toPlainText() == ""
    finally:
        second._refresh_timer.stop()
        second.close()


def test_workspace_switch_swaps_overview_state_between_saved_workspaces(tmp_path: Path) -> None:
    window, _store = _make_workspace_window(
        tmp_path,
        "eng_alpha",
        ("eng_alpha", "Alpha"),
        ("eng_beta", "Beta"),
    )

    try:
        window._add_overview_checklist_item("Alpha task")
        window.overview_notes_edit.setPlainText("Alpha notes")
        window._persist_overview_state()

        assert window._switch_workspace("eng_beta") is True
        assert window._overview_state.checklist_items == []
        assert window.overview_notes_edit.toPlainText() == ""

        window._add_overview_checklist_item("Beta task")
        window.overview_notes_edit.setPlainText("Beta notes")
        window._persist_overview_state()

        assert window._switch_workspace("eng_alpha") is True
        assert len(window._overview_state.checklist_items) == 1
        assert window._overview_state.checklist_items[0].label == "Alpha task"
        assert window.overview_notes_edit.toPlainText() == "Alpha notes"
    finally:
        window._refresh_timer.stop()
        window.close()


def test_main_window_surfaces_tooltips_on_primary_controls(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert "workflow areas" in window.nav_list.toolTip().lower()
        assert "active workspace" in window.start_scan_button.toolTip().lower()
        assert "double-click" in window.workspace_run_table.toolTip().lower()
        assert "selected run" in window.open_output_button.toolTip().lower()
        assert "active for this gui session" in window.settings_workspace_combo.toolTip().lower()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_settings_page_can_switch_active_workspace(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    workspace_store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
    workspace_store.save_engagement(Engagement(engagement_id="eng_beta", name="Beta"))
    workspace_store.set_active_workspace("eng_alpha")
    window = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)

    try:
        target_index = window.settings_workspace_combo.findData("eng_beta")
        assert target_index >= 0

        window.settings_workspace_combo.setCurrentIndex(target_index)
        window.apply_workspace_button.click()

        assert window._active_workspace_id == "eng_beta"
        assert window.workspace_list.count() == 1
        assert "Beta" in window.workspace_list.item(0).text()
        assert "eng_beta" == workspace_store.get_active_workspace_id()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_settings_page_can_delete_active_workspace_and_its_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    workspace_home = tmp_path / "alpha-home"
    run_dir = workspace_home / "run_alpha"
    run_dir.mkdir(parents=True)
    (run_dir / "data.txt").write_text("alpha", encoding="utf-8")
    workspace_store.save_workspace(Workspace(workspace_id="eng_alpha", name="Alpha", home_dir=str(workspace_home)))
    workspace_store.set_active_workspace("eng_alpha")
    workspace_store.register_run(RunRegistryEntry(run_id="run-alpha", run_dir=str(run_dir), workspace_id="eng_alpha"))
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    window = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)

    try:
        assert workspace_home.exists()
        window.delete_active_workspace_data_button.click()

        assert workspace_store.get_active_workspace_id() == ""
        assert workspace_store.load_workspaces() == []
        assert not workspace_home.exists()
        assert "Deleted workspace Alpha" in window.general_status.text()
        assert "No active workspace is selected" in window.danger_zone_status_label.text()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_settings_page_can_delete_all_workspaces_and_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    profile_store = GuiProfileStore(tmp_path / "profiles.json")
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    extension_store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    alpha_home = tmp_path / "alpha-home"
    beta_home = tmp_path / "beta-home"
    alpha_run = alpha_home / "run_alpha"
    beta_run = beta_home / "run_beta"
    alpha_run.mkdir(parents=True)
    beta_run.mkdir(parents=True)
    (alpha_run / "data.txt").write_text("alpha", encoding="utf-8")
    (beta_run / "data.txt").write_text("beta", encoding="utf-8")
    workspace_store.save_workspace(Workspace(workspace_id="eng_alpha", name="Alpha", home_dir=str(alpha_home)))
    workspace_store.save_workspace(Workspace(workspace_id="eng_beta", name="Beta", home_dir=str(beta_home)))
    workspace_store.set_active_workspace("eng_alpha")
    workspace_store.register_run(RunRegistryEntry(run_id="run-alpha", run_dir=str(alpha_run), workspace_id="eng_alpha"))
    workspace_store.register_run(RunRegistryEntry(run_id="run-beta", run_dir=str(beta_run), workspace_id="eng_beta"))
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    window = MainWindow(store=profile_store, workspace_store=workspace_store, extension_store=extension_store)

    try:
        window.delete_all_workspaces_data_button.click()

        assert workspace_store.load_workspaces() == []
        assert workspace_store.get_active_workspace_id() == ""
        assert not alpha_home.exists()
        assert not beta_home.exists()
        assert "Deleted 2 workspaces" in window.general_status.text()
    finally:
        window._refresh_timer.stop()
        window.close()


def test_send_control_action_warns_when_run_folder_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _make_window(tmp_path)

    try:
        snapshot = RunSnapshot(
            run_id="run-missing",
            scan_name="Missing Folder Run",
            run_dir=str(tmp_path / "missing-run"),
            state="running",
            elapsed_seconds=5.0,
            eta_seconds=10.0,
            current_task="Nmap",
            total_tasks=2,
            completed_tasks=1,
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id
        warnings: list[str] = []
        monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(str(args[2])) or QMessageBox.Ok)

        window._send_control_action("pause")

        assert "no longer available" in window.general_status.text()
        assert warnings
        assert "Expected path" in warnings[0]
        assert not any(entry.action == "control.requested" for entry in window._audit_entries)
    finally:
        window._refresh_timer.stop()
        window.close()


def test_retry_selected_run_uses_fallback_when_gui_metadata_is_invalid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _make_window(tmp_path)

    try:
        run_dir = tmp_path / "run-retry"
        (run_dir / "data").mkdir(parents=True)
        (run_dir / "data" / "gui_session.json").write_text("{invalid", encoding="utf-8")
        (run_dir / "data" / "gui_requested_profile.json").write_text("[]", encoding="utf-8")
        snapshot = RunSnapshot(
            run_id="run-retry",
            scan_name="Retry Me",
            run_dir=str(run_dir),
            state="failed",
            elapsed_seconds=120.0,
            eta_seconds=None,
            current_task="Nuclei",
            total_tasks=4,
            completed_tasks=4,
            workspace_id=window._active_workspace_id,
            workspace_name=window._active_workspace().name if window._active_workspace() is not None else "Client One",
            target_input="example.com",
        )
        window._run_snapshots[snapshot.run_id] = snapshot
        window._selected_run_id = snapshot.run_id
        launched_requests = []
        monkeypatch.setattr(window, "_launch_request", lambda request: launched_requests.append(request))

        window._retry_selected_run()

        assert len(launched_requests) == 1
        request = launched_requests[0]
        assert request.scan_name == "Retry Me Retry"
        assert request.target_input == "example.com"
        assert request.profile.name == "Unnamed Profile"
        assert request.output_directory == ad_hoc_output_home()
        assert "fallback metadata" in window.general_status.text()
        assert any(entry.action == "scan.retry" for entry in window._audit_entries)
        fallback_entries = [entry for entry in window._audit_entries if entry.action == "scan.retry.fallback"]
        assert len(fallback_entries) == 1
        assert len(fallback_entries[0].details["warnings"]) == 2
    finally:
        window._refresh_timer.stop()
        window.close()
