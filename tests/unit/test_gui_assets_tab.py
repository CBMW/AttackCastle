from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication

from attackcastle.gui.asset_graph_builder import AssetGraphBuilder
from attackcastle.gui.asset_graph_models import GraphBuildOptions
from attackcastle.gui.asset_inventory import build_entity_note, build_workspace_inventory_snapshot
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
        assert tab.main_split.count() == 2
        assert [tab.asset_views.tabText(index) for index in range(tab.asset_views.count())] == ["Inventory", "Graph View"]
        row = tab.services_model.index(0, 0).data(Qt.UserRole)
        assert row["__target"] == "203.0.113.10:443"
    finally:
        tab.close()


def test_assets_tab_keeps_docked_detail_panel_secondary_on_wide_layout(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.resize(1400, 900)
        tab.sync_responsive_mode(tab.width())
        app.processEvents()

        assert tab.main_split.orientation() == Qt.Horizontal
        sizes = tab.main_split.sizes()
        assert sizes[0] > sizes[1]

        tab.sync_responsive_mode(1180)
        assert tab.main_split.orientation() == Qt.Vertical
    finally:
        tab.close()


def test_assets_tab_keeps_web_inventory_empty_until_web_apps_are_confirmed(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()
    snapshot = _make_snapshot(tmp_path)
    snapshot.web_apps = []
    snapshot.endpoints = []
    snapshot.parameters = []
    snapshot.forms = []
    snapshot.login_surfaces = []
    snapshot.technologies = []

    try:
        tab.set_snapshot(snapshot)
        app.processEvents()

        assert tab.assets_model.rowCount() == 1
        assert tab.services_model.rowCount() == 1
        assert tab.web_apps_model.rowCount() == 0

        confirmed_snapshot = _make_snapshot(tmp_path)
        tab.set_snapshot(confirmed_snapshot)
        app.processEvents()

        assert tab.web_apps_model.rowCount() == 1
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
        menu, scan_action, notes_action, graph_action = tab._build_context_menu(tab.assets_view, "asset", row)

        assert [action.text() for action in menu.actions()] == ["Scan Asset", "Add Notes", "Focus in Graph"]
        assert scan_action.isEnabled() is True
        assert notes_action.isEnabled() is True
        assert graph_action.isEnabled() is True
    finally:
        tab.close()


def test_assets_tab_header_context_menu_exposes_copy_actions(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        (
            menu,
            copy_all_action,
            copy_row_action,
            copy_column_action,
        ) = tab._build_header_context_menu(tab.web_apps_view, 0, 0)

        assert [action.text() for action in menu.actions()] == [
            "Copy All",
            "Copy Row Data",
            "Copy Column Data (URL)",
        ]
        assert copy_all_action.isEnabled() is True
        assert copy_row_action.isEnabled() is True
        assert copy_column_action.isEnabled() is True
    finally:
        tab.close()


def test_assets_tab_header_copy_actions_use_displayed_table_data(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()

        tab._copy_table_column_data(tab.web_apps_view, 0)
        assert app.clipboard().text() == "https://example.com"

        tab.assets_view.setCurrentIndex(tab.assets_model.index(0, 0))
        tab._copy_table_row_data(tab.assets_view, 0)
        assert app.clipboard().text() == (
            "Kind\tName\tIP\tAliases\tServices\tWeb Apps\tNote\n"
            "host\texample.com\t203.0.113.10\twww.example.com\t1\t1\t"
        )

        tab._copy_table_all_data(tab.web_apps_view)
        assert app.clipboard().text() == (
            "URL\tStatus\tTitle\tForms\tNote\n"
            "https://example.com\t200\tExample\t0\t"
        )
    finally:
        tab.close()


def test_assets_tab_header_context_menu_copies_clicked_column(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    tab, _launched, _notes = _make_tab()

    def choose_column_action(menu, _global_point):
        return next(
            action
            for action in menu.actions()
            if action.text().startswith("Copy Column Data")
        )

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        monkeypatch.setattr(tab, "_exec_header_context_menu", choose_column_action)

        header = tab.web_apps_view.horizontalHeader()
        point = QPoint(
            header.sectionViewportPosition(0) + header.sectionSize(0) // 2,
            header.height() // 2,
        )
        tab._open_header_context_menu(tab.web_apps_view, point)

        assert app.clipboard().text() == "https://example.com"
    finally:
        tab.close()


def test_assets_tab_can_focus_inventory_row_in_graph_view(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        row = tab.assets_model.index(0, 0).data(Qt.UserRole)

        tab._focus_row_in_graph("asset", row)
        app.processEvents()

        assert tab.asset_views.currentWidget() is tab.graph_view
        assert "centered" in tab.detail_text.toPlainText().lower()
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


def test_assets_tab_reopening_same_row_keeps_detail_panel_visible(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        index = tab.services_model.index(0, 0)

        tab._open_detail_for_index(tab.services_view, index)
        initial_sizes = tab.main_split.sizes()

        tab._open_detail_for_index(tab.services_view, index)

        assert tab.main_split.sizes()[1] > 0
        assert tab._active_detail_signature
        assert tab.main_split.sizes()[1] >= initial_sizes[1]
    finally:
        tab.close()


def test_assets_tab_keeps_open_detail_panel_across_snapshot_refresh(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _launched, _notes = _make_tab()

    try:
        tab.set_snapshot(_make_snapshot(tmp_path))
        app.processEvents()
        index = tab.services_model.index(0, 0)

        tab._open_detail_for_index(tab.services_view, index)
        assert tab.main_split.sizes()[1] > 0

        updated = _make_snapshot(tmp_path)
        updated.services[0]["banner"] = "nginx refreshed banner"
        tab.set_snapshot(updated)
        app.processEvents()

        assert tab.main_split.sizes()[1] > 0
        assert tab._active_detail_signature
        assert "nginx refreshed banner" in tab.detail_text.toPlainText()
        assert tab.services_view.selectionModel().currentIndex().row() == 0
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


def test_workspace_inventory_snapshot_merges_all_runs_and_deduplicates_relations(tmp_path: Path) -> None:
    first = _make_snapshot(tmp_path)
    second = RunSnapshot(
        run_id="run-assets-2",
        scan_name="Asset Workspace Run 2",
        run_dir=str(tmp_path / "run-assets-2"),
        state="completed",
        elapsed_seconds=30.0,
        eta_seconds=0.0,
        current_task="Idle",
        total_tasks=2,
        completed_tasks=2,
        workspace_id=first.workspace_id,
        workspace_name=first.workspace_name,
        target_input="api.example.com",
        assets=[
            {"asset_id": "asset-2", "kind": "host", "name": "example.com", "ip": "203.0.113.10", "aliases": ["api.example.com"]},
            {"asset_id": "asset-3", "kind": "host", "name": "admin.example.com", "ip": "203.0.113.11"},
        ],
        services=[
            {"service_id": "svc-2", "asset_id": "asset-2", "port": 443, "protocol": "tcp", "state": "open", "name": "https"},
            {"service_id": "svc-3", "asset_id": "asset-3", "port": 8443, "protocol": "tcp", "state": "open", "name": "https-alt"},
        ],
        web_apps=[
            {"webapp_id": "web-2", "asset_id": "asset-2", "service_id": "svc-2", "url": "https://example.com", "status_code": 200, "title": "Example API"},
            {"webapp_id": "web-3", "asset_id": "asset-3", "service_id": "svc-3", "url": "https://admin.example.com:8443", "status_code": 200, "title": "Admin"},
        ],
        endpoints=[
            {"endpoint_id": "ep-2", "webapp_id": "web-2", "asset_id": "asset-2", "service_id": "svc-2", "kind": "rest", "method": "GET", "url": "https://example.com/api/users"},
            {"endpoint_id": "ep-3", "webapp_id": "web-3", "asset_id": "asset-3", "service_id": "svc-3", "kind": "rest", "method": "POST", "url": "https://admin.example.com:8443/api/login"},
        ],
        parameters=[],
        forms=[],
        login_surfaces=[],
        site_map=[
            {"source": "web.discovery.urls", "url": "https://admin.example.com:8443/api/login", "entity_id": "web-3"},
        ],
        technologies=[
            {"tech_id": "tech-2", "asset_id": "asset-2", "webapp_id": "web-2", "name": "nginx", "version": "1.25", "category": "server", "source_tool": "httpx"},
            {"tech_id": "tech-3", "asset_id": "asset-3", "webapp_id": "web-3", "name": "gunicorn", "version": "22.0", "category": "server", "source_tool": "whatweb"},
        ],
    )

    aggregate = build_workspace_inventory_snapshot([first, second], workspace_id=first.workspace_id, workspace_name=first.workspace_name)

    assert aggregate is not None
    assert len(aggregate.assets) == 2
    assert len(aggregate.services) == 2
    assert len(aggregate.web_apps) == 2
    assert len(aggregate.endpoints) == 2
    assert len(aggregate.technologies) == 2

    example_asset = next(row for row in aggregate.assets if row.get("name") == "example.com")
    assert sorted(example_asset.get("aliases") or []) == ["api.example.com", "www.example.com"]

    example_service = next(row for row in aggregate.services if row.get("port") == 443)
    assert example_service.get("asset_id") == example_asset.get("asset_id")

    example_web_app = next(row for row in aggregate.web_apps if row.get("url") == "https://example.com")
    assert example_web_app.get("service_id") == example_service.get("service_id")


def test_asset_graph_builder_creates_workspace_topology_and_finding_edges(tmp_path: Path) -> None:
    snapshot = _make_snapshot(tmp_path)
    snapshot.findings = [
        {
            "finding_id": "finding-1",
            "title": "Public Login Portal",
            "severity": "medium",
            "affected_entities": [{"entity_type": "web_app", "entity_id": "web-1"}],
        }
    ]
    snapshot.evidence_bundles = [
        {
            "bundle_id": "bundle-1",
            "label": "Homepage Proof",
            "entity_type": "web_app",
            "entity_id": "web-1",
            "asset_id": "asset-1",
            "summary": "Screenshot evidence",
            "screenshot_paths": [str(tmp_path / "proof.png")],
        }
    ]
    snapshot.relationships = [
        {
            "relationship_id": "rel-1",
            "source_entity_type": "asset",
            "source_entity_id": "asset-1",
            "target_entity_type": "web_app",
            "target_entity_id": "web-1",
            "relationship_type": "discovered_by",
            "source_tool": "httpx",
        }
    ]
    builder = AssetGraphBuilder()

    graph = builder.build(
        snapshot,
        options=GraphBuildOptions(
            root_node_id="asset::asset-1",
            include_provenance=True,
            include_findings=True,
            include_evidence=True,
            direct_neighbors_only=False,
            depth=2,
        ),
    )

    node_types = {node.node_type for node in graph.nodes}
    edge_types = {edge.edge_type for edge in graph.edges}
    assert {"workspace", "domain", "port", "service", "web_app", "endpoint", "technology", "finding", "evidence_bundle"}.issubset(node_types)
    assert {"contains", "hosts_port", "identifies_service", "serves", "has_endpoint", "uses_technology", "produces_finding", "has_evidence"}.issubset(edge_types)
