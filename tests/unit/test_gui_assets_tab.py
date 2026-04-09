from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from attackcastle.gui.asset_inventory import build_entity_note
from attackcastle.gui.assets_tab import AssetsTab
from attackcastle.gui.models import Engagement, RunSnapshot
from attackcastle.gui.workspace_store import WorkspaceStore


def _make_snapshot(tmp_path: Path) -> RunSnapshot:
    return RunSnapshot(
        run_id="run-assets",
        scan_name="Asset Workspace Run",
        run_dir=str(tmp_path / "run-assets"),
        state="completed",
        elapsed_seconds=42.0,
        eta_seconds=0.0,
        current_task="Idle",
        total_tasks=4,
        completed_tasks=4,
        workspace_id="eng_1",
        workspace_name="Client Alpha",
        target_input="example.com",
        assets=[
            {"asset_id": "asset-1", "kind": "host", "name": "example.com", "ip": "203.0.113.10", "aliases": ["www.example.com"]},
        ],
        services=[
            {"service_id": "svc-1", "asset_id": "asset-1", "port": 443, "protocol": "tcp", "state": "open", "name": "https"},
        ],
        web_apps=[
            {"webapp_id": "web-1", "asset_id": "asset-1", "service_id": "svc-1", "url": "https://example.com", "status_code": 200, "title": "Example"},
        ],
        endpoints=[
            {"endpoint_id": "ep-1", "webapp_id": "web-1", "asset_id": "asset-1", "service_id": "svc-1", "kind": "rest", "method": "GET", "url": "https://example.com/api/users"},
        ],
        parameters=[
            {"parameter_id": "param-1", "webapp_id": "web-1", "endpoint_id": "ep-1", "name": "id", "location": "query", "sensitive": False},
        ],
        forms=[
            {"form_id": "form-1", "webapp_id": "web-1", "action_url": "https://example.com/login", "method": "POST", "field_names": ["username", "password"], "has_password": True},
        ],
        login_surfaces=[
            {"login_surface_id": "login-1", "webapp_id": "web-1", "url": "https://example.com/login", "reasons": ["password_form"], "username_fields": ["username"], "password_fields": ["password"]},
        ],
        site_map=[
            {"source": "web.discovery.urls", "url": "https://example.com/login", "entity_id": "web-1"},
        ],
        technologies=[
            {"tech_id": "tech-1", "asset_id": "asset-1", "webapp_id": "web-1", "name": "nginx", "version": "1.25", "category": "server", "source_tool": "whatweb"},
        ],
    )


def _make_tab() -> tuple[AssetsTab, list[tuple[str, str]], dict[str, dict[str, object]]]:
    app = QApplication.instance() or QApplication([])
    _ = app
    launched: list[tuple[str, str]] = []
    notes: dict[str, dict[str, object]] = {}

    def load_notes(workspace_id: str):
        return dict(notes.get(workspace_id, {}))

    def save_note(workspace_id: str, note):
        notes.setdefault(workspace_id, {})[note.signature] = note

    tab = AssetsTab(
        launch_scan=lambda target, label: launched.append((target, label)),
        load_notes=load_notes,
        save_note=save_note,
    )
    tab.resize(1280, 900)
    tab.show()
    app.processEvents()
    return tab, launched, notes


def test_assets_tab_populates_grouped_inventory_tables(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()

        assert tab.assets_model.rowCount() == 1
        assert tab.services_model.rowCount() == 1
        assert tab.web_apps_model.rowCount() == 1
        assert tab.endpoints_model.rowCount() == 1
        assert tab.technologies_model.rowCount() == 1
        row = tab.services_model.index(0, 0).data(Qt.UserRole)
        assert row["__target"] == "203.0.113.10:443"
    finally:
        tab.close()


def test_assets_tab_context_menu_exposes_scan_and_notes_actions(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        row = tab.assets_model.index(0, 0).data(Qt.UserRole)
        menu, scan_action, notes_action = tab._build_context_menu(tab.assets_view, "asset", row)

        assert [action.text() for action in menu.actions()] == ["Scan Asset", "Add Notes"]
        assert scan_action.isEnabled() is True
        assert notes_action.isEnabled() is True
    finally:
        tab.close()


def test_assets_tab_double_click_opens_docked_detail_panel_and_close_collapses_it(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        index = tab.services_model.index(0, 0)

        tab._open_detail_for_index(tab.services_view, index)
        assert tab.main_split.sizes()[1] > 0
        assert "203.0.113.10:443" in tab.detail_summary.text()

        tab.detail_close_button.click()

        assert tab.main_split.sizes()[1] == 0
    finally:
        tab.close()


def test_assets_tab_loads_workspace_notes_for_matching_entity_signatures(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    workspace_store = WorkspaceStore(tmp_path / "workspace.json")
    snapshot = _make_snapshot(tmp_path)
    workspace_store.save_engagement(Engagement(engagement_id=snapshot.workspace_id, name=snapshot.workspace_name))
    asset_row = snapshot.assets[0]
    note = build_entity_note("asset", asset_row, snapshot, "Priority host")
    workspace_store.save_entity_note(note, snapshot.workspace_id)
    tab = AssetsTab(
        launch_scan=lambda _target, _label: None,
        load_notes=lambda workspace_id: workspace_store.load_entity_notes(workspace_id),
        save_note=lambda workspace_id, entity_note: workspace_store.save_entity_note(entity_note, workspace_id),
    )
    tab.resize(1280, 900)
    tab.show()
    app.processEvents()

    try:
        tab.set_snapshot(snapshot)
        app.processEvents()

        row = tab.assets_model.index(0, 0).data(Qt.UserRole)
        assert row["__note_preview"] == "Priority host"
    finally:
        tab.close()
