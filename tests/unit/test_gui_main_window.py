from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QProcess, QRect, Qt
from PySide6.QtGui import QShortcut
from PySide6.QtWidgets import QApplication, QFrame, QGroupBox, QLabel, QMessageBox, QPushButton

from attackcastle.gui.main_window import MainWindow
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.models import Engagement, RunSnapshot
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.worker_protocol import WorkerEvent
from attackcastle.gui.workspace_store import WorkspaceStore, ad_hoc_output_home


def _make_window(tmp_path: Path) -> MainWindow:
    app = QApplication.instance() or QApplication([])
    _ = app
    return MainWindow(
        store=GuiProfileStore(tmp_path / "profiles.json"),
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        extension_store=GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json"),
    )


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
        assert "No Workspace" in window.header_workspace_label.text()
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
        assert window.width() == MainWindow._fit_restore_dimension(1280, 1024, 0.72, 680)
        assert window.height() == MainWindow._fit_restore_dimension(840, 700, 0.74, 520)
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


def test_header_omits_removed_branding_and_run_context_sections(tmp_path: Path) -> None:
    window = _make_window(tmp_path)

    try:
        assert not window.findChildren(QLabel, "logoBadge")
        assert not window.findChildren(QLabel, "appTitle")
        assert not window.findChildren(QLabel, "appSubtitle")
        assert window.header_context_label.isHidden()
        assert not window.header_workspace_label.isHidden()
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
        assert window.output_tab.main_split.orientation() == Qt.Horizontal
    finally:
        window._refresh_timer.stop()
        window.close()


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
                    "label": "masscan execution",
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
