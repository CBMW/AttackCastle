from __future__ import annotations

import json
from typing import Any, Callable

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.asset_inventory import (
    asset_discovery_source,
    build_detail_payload,
    build_entity_note,
    entity_signature,
    row_label,
    scan_target_for_row,
)
from attackcastle.gui.common import (
    MappingTableModel,
    PAGE_SECTION_SPACING,
    PersistentSplitterController,
    SURFACE_FLAT,
    SURFACE_PRIMARY,
    apply_responsive_splitter,
    build_flat_container,
    build_inspector_panel,
    build_surface_frame,
    configure_tab_widget,
    configure_scroll_surface,
    ensure_table_defaults,
    set_plain_text_preserving_scroll,
    set_tooltip,
    style_button,
    splitter_orientation_key,
    title_case_label,
)
from attackcastle.gui.models import EntityNote, HttpHistoryEntry, RunSnapshot


class EntityNoteDialog(QDialog):
    def __init__(self, label: str, existing_note: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Asset Notes")
        self.setModal(True)
        self.resize(520, 320)

        layout = QVBoxLayout(self)
        helper = QLabel(f"Notes for {label}")
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        layout.addWidget(helper)

        form = QFormLayout()
        self.note_edit = configure_scroll_surface(QPlainTextEdit())
        self.note_edit.setMinimumHeight(180)
        self.note_edit.setPlainText(existing_note)
        form.addRow("Notes", self.note_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def note_text(self) -> str:
        return self.note_edit.toPlainText().strip()


class AssetsTab(QWidget):
    def __init__(
        self,
        launch_scan: Callable[[str, str], None],
        load_notes: Callable[[str], dict[str, EntityNote]],
        save_note: Callable[[str, EntityNote], None],
        send_to_attacker: Callable[[str, dict[str, Any], RunSnapshot, str], None] | None = None,
        attacker_action_types: Callable[[str], list[tuple[str, str]]] | None = None,
        send_http_history_to_attacker: Callable[[HttpHistoryEntry], None] | None = None,
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._launch_scan = launch_scan
        self._load_notes = load_notes
        self._save_note = save_note
        self._send_to_attacker = send_to_attacker
        self._attacker_action_types = attacker_action_types
        self._send_http_history_to_attacker = send_http_history_to_attacker
        self._snapshot: RunSnapshot | None = None
        self._http_history_entries: list[HttpHistoryEntry] = []
        self._notes: dict[str, EntityNote] = {}
        self._active_detail_signature = ""
        self._active_detail_kind = ""
        self._active_detail_row: dict[str, Any] = {}
        self._active_detail_table: QTableView | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        # Keep the inventory side as the one primary panel; tables inside tabs stay flat to avoid stacked cards.
        content_panel, content_layout = build_surface_frame(
            object_name="assetInventoryPanel",
            surface=SURFACE_PRIMARY,
            spacing=PAGE_SECTION_SPACING,
        )

        toolbar, toolbar_layout = build_surface_frame(
            object_name="toolbarStrip",
            surface=SURFACE_FLAT,
            padding=0,
            spacing=PAGE_SECTION_SPACING,
        )
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search assets, services, URLs, notes, routes, or technologies")
        self.search_edit.textChanged.connect(self._refresh_models)
        set_tooltip(self.search_edit, "Search across discovered asset inventory and stored operator notes.")
        search_row.addWidget(self.search_edit, 1)
        toolbar_layout.addLayout(search_row)

        self.assets_model = MappingTableModel(
            [
                ("Source", asset_discovery_source),
                ("Name", "name"),
                ("IP", lambda row: row.get("ip") or ""),
                ("Aliases", lambda row: ", ".join(row.get("aliases") or [])),
                ("Services", lambda row: row.get("__service_count") or 0),
                ("Web Apps", lambda row: row.get("__web_count") or 0),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.services_model = MappingTableModel(
            [
                ("Asset", lambda row: row.get("__asset_label") or ""),
                ("Port", "port"),
                ("Protocol", "protocol"),
                ("State", "state"),
                ("Name", lambda row: row.get("name") or ""),
                ("Banner", lambda row: row.get("banner") or ""),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.web_apps_model = MappingTableModel(
            [
                ("URL", "url"),
                ("Status", lambda row: row.get("status_code") or ""),
                ("Title", lambda row: row.get("title") or ""),
                ("Forms", lambda row: row.get("forms_count") or 0),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.endpoints_model = MappingTableModel(
            [
                ("Kind", "kind"),
                ("Method", lambda row: row.get("method") or ""),
                ("URL", "url"),
                ("Tags", lambda row: ", ".join(row.get("tags") or [])),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.parameters_model = MappingTableModel(
            [
                ("Name", "name"),
                ("Location", "location"),
                ("Sensitive", lambda row: "Yes" if row.get("sensitive") else "No"),
                ("Endpoint", lambda row: row.get("endpoint_id") or ""),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.forms_model = MappingTableModel(
            [
                ("Action", "action_url"),
                ("Method", "method"),
                ("Fields", lambda row: ", ".join(row.get("field_names") or [])),
                ("Password", lambda row: "Yes" if row.get("has_password") else "No"),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.login_surfaces_model = MappingTableModel(
            [
                ("URL", "url"),
                ("Reasons", lambda row: ", ".join(row.get("reasons") or [])),
                ("Username Fields", lambda row: ", ".join(row.get("username_fields") or [])),
                ("Password Fields", lambda row: ", ".join(row.get("password_fields") or [])),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.site_map_model = MappingTableModel(
            [
                ("Source", "source"),
                ("URL", "url"),
                ("Entity", "entity_id"),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.technologies_model = MappingTableModel(
            [
                ("Name", "name"),
                ("Version", lambda row: row.get("version") or ""),
                ("Category", lambda row: row.get("category") or ""),
                ("Source", lambda row: row.get("source_tool") or ""),
                ("Note", lambda row: row.get("__note_preview") or ""),
            ]
        )
        self.http_history_model = MappingTableModel(
            [
                ("Time", lambda row: row.get("timestamp") or ""),
                ("Method", "method"),
                ("Host", "host"),
                ("Path", "path"),
                ("Status", lambda row: row.get("response_status") or ""),
                ("MIME", lambda row: row.get("content_type") or ""),
                ("Length", lambda row: row.get("size") or 0),
                ("TLS", lambda row: "Yes" if row.get("tls") else "No"),
                ("Error", lambda row: row.get("error") or ""),
            ]
        )

        self.assets_view = self._make_table(self.assets_model, "asset")
        self.services_view = self._make_table(self.services_model, "service")
        self.web_apps_view = self._make_table(self.web_apps_model, "web_app")
        self.endpoints_view = self._make_table(self.endpoints_model, "endpoint")
        self.parameters_view = self._make_table(self.parameters_model, "parameter")
        self.forms_view = self._make_table(self.forms_model, "form")
        self.login_surfaces_view = self._make_table(self.login_surfaces_model, "login_surface")
        self.site_map_view = self._make_table(self.site_map_model, "site_map")
        self.technologies_view = self._make_table(self.technologies_model, "technology")
        self.http_history_view = self._make_table(self.http_history_model, "http_history")

        self.inventory_tabs = QTabWidget()
        configure_tab_widget(self.inventory_tabs, role="group")
        self.inventory_tabs.addTab(self._table_surface("Discovered Assets", self.assets_view), "Assets")
        self.inventory_tabs.addTab(self._table_surface("Discovered Services", self.services_view), "Services")

        web_page = build_flat_container()
        web_layout = QVBoxLayout(web_page)
        web_layout.setContentsMargins(0, 0, 0, 0)
        self.web_tabs = QTabWidget()
        configure_tab_widget(self.web_tabs, role="group")
        self.web_tabs.addTab(self._table_surface("Web Applications", self.web_apps_view), "Web Apps")
        self.web_tabs.addTab(self._table_surface("Endpoints", self.endpoints_view), "Endpoints")
        self.web_tabs.addTab(self._table_surface("Parameters", self.parameters_view), "Parameters")
        self.web_tabs.addTab(self._table_surface("Forms", self.forms_view), "Forms")
        self.web_tabs.addTab(self._table_surface("Login Surfaces", self.login_surfaces_view), "Login")
        self.web_tabs.addTab(self._table_surface("Routes", self.site_map_view), "Routes")
        web_layout.addWidget(self.web_tabs)
        self.inventory_tabs.addTab(web_page, "Web")

        self.inventory_tabs.addTab(self._table_surface("HTTP History", self.http_history_view), "HTTP History")
        self.inventory_tabs.addTab(self._table_surface("Technology Inventory", self.technologies_view), "Technology")
        inventory_page = build_flat_container()
        inventory_layout = QVBoxLayout(inventory_page)
        inventory_layout.setContentsMargins(0, 0, 0, 0)
        inventory_layout.setSpacing(PAGE_SECTION_SPACING)
        inventory_layout.addWidget(toolbar)
        inventory_layout.addWidget(self.inventory_tabs, 1)
        self.graph_view = build_flat_container()
        graph_layout = QVBoxLayout(self.graph_view)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_label = QLabel("Graph View")
        graph_label.setObjectName("sectionTitle")
        graph_layout.addWidget(graph_label)
        graph_layout.addStretch(1)
        self.asset_views = QTabWidget()
        configure_tab_widget(self.asset_views, role="group")
        self.asset_views.addTab(inventory_page, "Inventory")
        self.asset_views.addTab(self.graph_view, "Graph View")
        content_layout.addWidget(self.asset_views, 1)

        detail_body = build_flat_container()
        detail_body_layout = QVBoxLayout(detail_body)
        detail_body_layout.setContentsMargins(0, 0, 0, 0)
        detail_body_layout.setSpacing(PAGE_SECTION_SPACING)
        card_header = QHBoxLayout()
        self.detail_title = QLabel("Asset Details")
        self.detail_title.setObjectName("sectionTitle")
        card_header.addWidget(self.detail_title)
        card_header.addStretch(1)
        self.detail_close_button = QPushButton("Close")
        style_button(self.detail_close_button, role="secondary")
        self.detail_close_button.clicked.connect(self._hide_detail_card)
        card_header.addWidget(self.detail_close_button)
        detail_body_layout.addLayout(card_header)
        self.detail_summary = QLabel("")
        self.detail_summary.setObjectName("helperText")
        self.detail_summary.setWordWrap(True)
        detail_body_layout.addWidget(self.detail_summary)
        self.detail_text = configure_scroll_surface(QTextEdit())
        self.detail_text.setReadOnly(True)
        self.detail_text.setObjectName("consoleText")
        self.detail_text.setMinimumHeight(280)
        detail_body_layout.addWidget(self.detail_text, 1)
        self.detail_title.setText("Asset Details")
        self.detail_summary.setText("Select an asset, service, route, or technology to inspect details.")
        self.detail_text.setPlainText("Choose an item from the inventory to open the docked inspector.")
        self.detail_card, _detail_title, _detail_summary = build_inspector_panel(
            "Selection Inspector",
            detail_body,
            summary_text="Selected entity details, notes context, and launch actions stay docked here while the inventory tables remain primary.",
        )
        self.detail_card.setMinimumWidth(0)

        self.main_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (5, 2))
        self.main_split_controller = PersistentSplitterController(
            self.main_split,
            "assets_main_split",
            layout_loader,
            layout_saver,
            self,
        )
        self.main_split.addWidget(content_panel)
        self.main_split.addWidget(self.detail_card)
        layout.addWidget(self.main_split, 1)
        self.sync_responsive_mode(self.width())

    def _section(self, title: str, widget: QWidget) -> QWidget:
        section = build_flat_container()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget)
        return section

    def _table_surface(self, title: str, table: QTableView) -> QWidget:
        section, layout = build_surface_frame(surface=SURFACE_FLAT, padding=0, spacing=0)
        layout.addWidget(table, 1)
        return section

    def apply_theme(self, tokens: dict[str, Any] | None = None) -> None:
        return None

    def _make_table(self, model: MappingTableModel, entity_kind: str) -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setProperty("entity_kind", entity_kind)
        table.setModel(model)
        policies = {
            "asset": (
                {"mode": "content", "min": 110, "max": 140},
                {"mode": "stretch", "min": 180},
                {"mode": "content", "min": 110, "max": 160},
                {"mode": "stretch", "min": 220},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "content", "min": 100, "max": 120},
                {"mode": "stretch", "min": 220},
            ),
            "service": (
                {"mode": "stretch", "min": 180},
                {"mode": "content", "min": 80, "max": 90},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "content", "min": 90, "max": 120},
                {"mode": "content", "min": 120, "max": 170},
                {"mode": "stretch", "min": 240},
                {"mode": "stretch", "min": 220},
            ),
            "web_app": (
                {"mode": "stretch", "min": 280},
                {"mode": "content", "min": 80, "max": 100},
                {"mode": "stretch", "min": 220},
                {"mode": "content", "min": 80, "max": 100},
                {"mode": "stretch", "min": 220},
            ),
            "endpoint": (
                {"mode": "content", "min": 90, "max": 120},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "stretch", "min": 320},
                {"mode": "stretch", "min": 180},
                {"mode": "stretch", "min": 220},
            ),
            "parameter": (
                {"mode": "stretch", "min": 160},
                {"mode": "content", "min": 110, "max": 140},
                {"mode": "content", "min": 90, "max": 100},
                {"mode": "stretch", "min": 220},
                {"mode": "stretch", "min": 220},
            ),
            "form": (
                {"mode": "stretch", "min": 300},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "stretch", "min": 220},
                {"mode": "content", "min": 90, "max": 100},
                {"mode": "stretch", "min": 220},
            ),
            "login_surface": (
                {"mode": "stretch", "min": 260},
                {"mode": "stretch", "min": 220},
                {"mode": "stretch", "min": 220},
                {"mode": "stretch", "min": 220},
                {"mode": "stretch", "min": 220},
            ),
            "site_map": (
                {"mode": "content", "min": 110, "max": 140},
                {"mode": "stretch", "min": 320},
                {"mode": "stretch", "min": 180},
                {"mode": "stretch", "min": 220},
            ),
            "technology": (
                {"mode": "stretch", "min": 180},
                {"mode": "content", "min": 100, "max": 140},
                {"mode": "content", "min": 110, "max": 160},
                {"mode": "content", "min": 110, "max": 150},
                {"mode": "stretch", "min": 220},
            ),
            "http_history": (
                {"mode": "content", "min": 170, "max": 230},
                {"mode": "content", "min": 80, "max": 100},
                {"mode": "stretch", "min": 190},
                {"mode": "stretch", "min": 260},
                {"mode": "content", "min": 80, "max": 100},
                {"mode": "content", "min": 130, "max": 180},
                {"mode": "content", "min": 90, "max": 120},
                {"mode": "content", "min": 70, "max": 90},
                {"mode": "stretch", "min": 160},
            ),
        }
        ensure_table_defaults(table, column_policies=policies.get(entity_kind), minimum_rows=9)
        table.doubleClicked.connect(lambda index, view=table: self._open_detail_for_index(view, index))
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda point, view=table: self._open_context_menu(view, point))
        header = table.horizontalHeader()
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(
            lambda point, view=table: self._open_header_context_menu(view, point)
        )
        set_tooltip(
            table,
            "Double-click for an expandable detail card. Right-click rows for scan and notes actions, "
            "or column titles to copy table data.",
        )
        return table

    def focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def sync_responsive_mode(self, width: int) -> None:
        self.main_split.setOrientation(Qt.Horizontal if width >= 1280 else Qt.Vertical)
        if width >= 1280:
            self.main_split_controller.apply([max(int(width * 0.78), 820), max(int(width * 0.22), 300)])
        else:
            self.main_split_controller.apply([max(int(self.height() * 0.68), 420), max(int(self.height() * 0.32), 220)])

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        previous_workspace_id = self._snapshot.workspace_id if self._snapshot is not None else ""
        next_workspace_id = snapshot.workspace_id if snapshot is not None else ""
        workspace_changed = bool(previous_workspace_id and next_workspace_id and previous_workspace_id != next_workspace_id)
        self._snapshot = snapshot
        self._notes = self._load_notes(snapshot.workspace_id if snapshot is not None else "") if snapshot is not None else {}
        if snapshot is None or workspace_changed:
            self._hide_detail_card()
        self._refresh_models()
        if snapshot is not None and not workspace_changed:
            self._restore_active_detail()

    def set_http_history(self, entries: list[HttpHistoryEntry]) -> None:
        self._http_history_entries = [entry for entry in entries if isinstance(entry, HttpHistoryEntry)]
        self._refresh_http_history_model()

    def add_http_history_entry(self, entry: HttpHistoryEntry) -> None:
        if not isinstance(entry, HttpHistoryEntry):
            return
        self._http_history_entries.append(entry)
        self._http_history_entries = self._http_history_entries[-5000:]
        self._refresh_http_history_model()

    def _refresh_models(self) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            self.detail_title.setText("Asset Details")
            self.detail_summary.setText("Select an asset, service, route, or technology to inspect details.")
            self.detail_text.setPlainText("Choose an item from the inventory to open the docked inspector.")
            for model in (
                self.assets_model,
                self.services_model,
                self.web_apps_model,
                self.endpoints_model,
                self.parameters_model,
                self.forms_model,
                self.login_surfaces_model,
                self.site_map_model,
                self.technologies_model,
            ):
                model.set_rows([])
            self._refresh_http_history_model()
            return

        assets = self._enrich_rows("asset", snapshot.assets)
        services = self._enrich_rows("service", snapshot.services)
        web_apps = self._enrich_rows("web_app", snapshot.web_apps)
        endpoints = self._enrich_rows("endpoint", snapshot.endpoints)
        parameters = self._enrich_rows("parameter", snapshot.parameters)
        forms = self._enrich_rows("form", snapshot.forms)
        login_surfaces = self._enrich_rows("login_surface", snapshot.login_surfaces)
        routes = self._enrich_rows("site_map", snapshot.site_map)
        technologies = self._enrich_rows("technology", snapshot.technologies)

        filtered_assets = self._filter_rows(assets)
        filtered_services = self._filter_rows(services)
        filtered_web_apps = self._filter_rows(web_apps)
        filtered_endpoints = self._filter_rows(endpoints)
        filtered_parameters = self._filter_rows(parameters)
        filtered_forms = self._filter_rows(forms)
        filtered_login_surfaces = self._filter_rows(login_surfaces)
        filtered_routes = self._filter_rows(routes)
        filtered_technologies = self._filter_rows(technologies)

        self.assets_model.set_rows(filtered_assets)
        self.services_model.set_rows(filtered_services)
        self.web_apps_model.set_rows(filtered_web_apps)
        self.endpoints_model.set_rows(filtered_endpoints)
        self.parameters_model.set_rows(filtered_parameters)
        self.forms_model.set_rows(filtered_forms)
        self.login_surfaces_model.set_rows(filtered_login_surfaces)
        self.site_map_model.set_rows(filtered_routes)
        self.technologies_model.set_rows(filtered_technologies)
        self._refresh_http_history_model()

    def _refresh_http_history_model(self) -> None:
        rows = [self._http_history_row(entry) for entry in self._http_history_entries]
        filtered_rows = self._filter_rows(rows)
        self.http_history_model.set_rows(filtered_rows)

    def _http_history_row(self, entry: HttpHistoryEntry) -> dict[str, Any]:
        row = entry.to_dict()
        row["__entity_kind"] = "http_history"
        row["__label"] = f"{entry.method or 'HTTP'} {entry.host}{entry.path}"
        row["__target"] = entry.url
        row["__signature"] = entry.history_id
        row["__entry"] = entry
        return row

    def _detail_sources(self) -> dict[str, tuple[QTableView, MappingTableModel]]:
        return {
            "asset": (self.assets_view, self.assets_model),
            "service": (self.services_view, self.services_model),
            "web_app": (self.web_apps_view, self.web_apps_model),
            "endpoint": (self.endpoints_view, self.endpoints_model),
            "parameter": (self.parameters_view, self.parameters_model),
            "form": (self.forms_view, self.forms_model),
            "login_surface": (self.login_surfaces_view, self.login_surfaces_model),
            "site_map": (self.site_map_view, self.site_map_model),
            "technology": (self.technologies_view, self.technologies_model),
            "http_history": (self.http_history_view, self.http_history_model),
        }

    def _restore_active_detail(self) -> None:
        if self._active_detail_signature and self._active_detail_kind:
            source = self._detail_sources().get(self._active_detail_kind)
            if source is None:
                return
            table, model = source
            for row_index in range(model.rowCount()):
                index = model.index(row_index, 0)
                row = index.data(Qt.UserRole) or {}
                if not isinstance(row, dict):
                    continue
                if str(row.get("__signature") or "") != self._active_detail_signature:
                    continue
                selection = table.selectionModel()
                if selection is not None:
                    selection.setCurrentIndex(index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
                table.setCurrentIndex(index)
                table.selectRow(row_index)
                self._show_detail(self._active_detail_kind, row, table)
                return

    def _enrich_rows(self, entity_kind: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        snapshot = self._snapshot
        if snapshot is None:
            return []
        services_by_asset: dict[str, int] = {}
        web_by_asset: dict[str, int] = {}
        for service in snapshot.services:
            asset_id = str(service.get("asset_id") or "")
            services_by_asset[asset_id] = services_by_asset.get(asset_id, 0) + 1
        for web_app in snapshot.web_apps:
            asset_id = str(web_app.get("asset_id") or "")
            web_by_asset[asset_id] = web_by_asset.get(asset_id, 0) + 1

        asset_labels = {
            str(asset.get("asset_id") or ""): row_label("asset", asset, snapshot)
            for asset in snapshot.assets
        }
        result: list[dict[str, Any]] = []
        for item in rows:
            row = dict(item)
            signature = entity_signature(entity_kind, row, snapshot)
            note = self._notes.get(signature)
            row["__entity_kind"] = entity_kind
            row["__signature"] = signature
            row["__target"] = scan_target_for_row(entity_kind, row, snapshot)
            row["__label"] = row_label(entity_kind, row, snapshot)
            row["__note_preview"] = (note.note[:72] + "...") if note is not None and len(note.note) > 72 else (note.note if note is not None else "")
            row["__note_value"] = note.note if note is not None else ""
            row["__service_count"] = services_by_asset.get(str(row.get("asset_id") or ""), 0)
            row["__web_count"] = web_by_asset.get(str(row.get("asset_id") or ""), 0)
            row["__asset_label"] = asset_labels.get(str(row.get("asset_id") or ""), "")
            result.append(row)
        return result

    def _filter_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.search_edit.text().strip().lower()
        if not search:
            return rows
        filtered: list[dict[str, Any]] = []
        for row in rows:
            if search in json.dumps(row, sort_keys=True).lower():
                filtered.append(row)
        return filtered

    def _open_context_menu(self, table: QTableView, point: QPoint) -> None:
        index = table.indexAt(point)
        if not index.isValid():
            selection = table.selectionModel()
            if selection is not None and selection.currentIndex().isValid():
                index = selection.currentIndex()
            elif table.model() is not None and table.model().rowCount() > 0:
                index = table.model().index(0, 0)
        if not index.isValid():
            return
        table.selectRow(index.row())
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict):
            return
        entity_kind = str(table.property("entity_kind") or row.get("__entity_kind") or "")
        if entity_kind == "http_history":
            menu, send_action, _notes_action = self._build_context_menu(table, entity_kind, row)
            action = menu.exec(table.viewport().mapToGlobal(point))
            if action is send_action and self._send_http_history_to_attacker is not None:
                entry = row.get("__entry")
                if isinstance(entry, HttpHistoryEntry):
                    self._send_http_history_to_attacker(entry)
            return
        if self._snapshot is None:
            return
        built_menu = self._build_context_menu(table, entity_kind, row)
        menu, scan_action, notes_action = built_menu[:3]
        graph_action = built_menu[3] if len(built_menu) > 3 else None
        target = str(row.get("__target") or "")
        action = menu.exec(table.viewport().mapToGlobal(point))
        if action is scan_action and target:
            self._launch_scan(target, row.get("__label") or row_label(entity_kind, row, self._snapshot))
        elif action is notes_action:
            self._edit_note_for_row(entity_kind, row)
        elif graph_action is not None and action is graph_action:
            self._focus_row_in_graph(entity_kind, row)
        elif action is not None and self._send_to_attacker is not None:
            action_payload = action.data()
            if isinstance(action_payload, dict) and action_payload.get("action") == "send_to_attacker":
                self._send_to_attacker(
                    entity_kind,
                    row,
                    self._snapshot,
                    str(action_payload.get("workspace_type") or ""),
                )

    def _build_context_menu(self, table: QTableView, entity_kind: str, row: dict[str, Any]) -> tuple[Any, ...]:
        target = str(row.get("__target") or "")
        menu = QMenu(table)
        if entity_kind == "http_history":
            send_menu = QMenu("Send to Attacker", menu)
            menu.addMenu(send_menu)
            menu._attackcastle_send_menu = send_menu  # type: ignore[attr-defined]
            send_action = send_menu.addAction("HTTP Replay")
            send_action.setEnabled(
                self._send_http_history_to_attacker is not None
                and isinstance(row.get("__entry"), HttpHistoryEntry)
                and bool(str(row.get("raw_repeater_request") or ""))
            )
            send_menu.setEnabled(send_action.isEnabled())
            notes_action = menu.addAction("Add Notes")
            notes_action.setEnabled(False)
            return menu, send_action, notes_action
        scan_action = menu.addAction("Scan Asset")
        scan_action.setEnabled(bool(target))
        if self._send_to_attacker is not None:
            send_menu = QMenu("Send to Attacker", menu)
            menu.addMenu(send_menu)
            menu._attackcastle_send_menu = send_menu  # type: ignore[attr-defined]
            action_types = (
                self._attacker_action_types(entity_kind)
                if self._attacker_action_types is not None
                else []
            )
            for workspace_type, label in action_types:
                attack_action = send_menu.addAction(label)
                attack_action.setData(
                    {
                        "action": "send_to_attacker",
                        "workspace_type": workspace_type,
                    }
                )
            send_menu.setEnabled(bool(action_types))
        notes_action = menu.addAction("Add Notes")
        if self._send_to_attacker is not None:
            return menu, scan_action, notes_action
        graph_action = menu.addAction("Focus in Graph")
        graph_action.setEnabled(entity_kind in {"asset", "service", "web_app", "endpoint", "technology"})
        return menu, scan_action, notes_action, graph_action

    def _open_header_context_menu(self, table: QTableView, point: QPoint) -> None:
        model = table.model()
        if model is None:
            return
        header = table.horizontalHeader()
        column = header.logicalIndexAt(point)
        if not (0 <= column < model.columnCount()):
            return
        row = self._current_table_row(table)
        menu, copy_all_action, copy_row_action, copy_column_action = self._build_header_context_menu(
            table,
            column,
            row,
        )
        action = self._exec_header_context_menu(menu, header.mapToGlobal(point))
        if action is copy_all_action:
            self._copy_table_all_data(table)
        elif action is copy_row_action and row >= 0:
            self._copy_table_row_data(table, row)
        elif action is copy_column_action:
            self._copy_table_column_data(table, column)

    def _exec_header_context_menu(self, menu: QMenu, global_point: QPoint):
        return menu.exec(global_point)

    def _build_header_context_menu(
        self,
        table: QTableView,
        column: int,
        row: int | None = None,
    ) -> tuple[QMenu, Any, Any, Any]:
        model = table.model()
        row_count = model.rowCount() if model is not None else 0
        column_count = model.columnCount() if model is not None else 0
        resolved_row = self._current_table_row(table) if row is None else row
        column_label = self._table_header_label(table, column)
        menu = QMenu(table)
        copy_all_action = menu.addAction("Copy All")
        copy_all_action.setEnabled(row_count > 0 and column_count > 0)
        copy_row_action = menu.addAction("Copy Row Data")
        copy_row_action.setEnabled(0 <= resolved_row < row_count and column_count > 0)
        copy_column_action = menu.addAction(f"Copy Column Data ({column_label})")
        copy_column_action.setEnabled(0 <= column < column_count and row_count > 0)
        return menu, copy_all_action, copy_row_action, copy_column_action

    def _current_table_row(self, table: QTableView) -> int:
        selection = table.selectionModel()
        if selection is not None:
            current = selection.currentIndex()
            if current.isValid():
                return current.row()
            selected_rows = selection.selectedRows()
            if selected_rows:
                return selected_rows[0].row()
        model = table.model()
        if model is not None and model.rowCount() > 0:
            return 0
        return -1

    def _table_header_label(self, table: QTableView, column: int) -> str:
        model = table.model()
        if model is None or not (0 <= column < model.columnCount()):
            return "Column"
        return str(
            model.headerData(column, Qt.Horizontal, Qt.DisplayRole)
            or f"Column {column + 1}"
        )

    def _table_headers(self, table: QTableView) -> list[str]:
        model = table.model()
        if model is None:
            return []
        return [
            self._table_header_label(table, column)
            for column in range(model.columnCount())
        ]

    def _table_display_value(self, table: QTableView, row: int, column: int) -> str:
        model = table.model()
        if model is None:
            return ""
        index = model.index(row, column)
        return str(index.data(Qt.DisplayRole) or "") if index.isValid() else ""

    def _tsv_cell(self, value: str) -> str:
        return (
            str(value)
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\t", " ")
            .replace("\n", " ")
        )

    def _copy_to_clipboard(self, text: str, status: str) -> None:
        app = QApplication.instance()
        if app is None:
            return
        app.clipboard().setText(text)
        self.detail_summary.setText(status)

    def _copy_table_all_data(self, table: QTableView) -> None:
        model = table.model()
        if model is None:
            return
        rows = ["\t".join(self._tsv_cell(header) for header in self._table_headers(table))]
        for row in range(model.rowCount()):
            rows.append(
                "\t".join(
                    self._tsv_cell(self._table_display_value(table, row, column))
                    for column in range(model.columnCount())
                )
            )
        self._copy_to_clipboard(
            "\n".join(rows),
            f"Copied {model.rowCount()} row(s) from this table.",
        )

    def _copy_table_row_data(self, table: QTableView, row: int) -> None:
        model = table.model()
        if model is None or not (0 <= row < model.rowCount()):
            return
        headers = "\t".join(self._tsv_cell(header) for header in self._table_headers(table))
        values = "\t".join(
            self._tsv_cell(self._table_display_value(table, row, column))
            for column in range(model.columnCount())
        )
        self._copy_to_clipboard(f"{headers}\n{values}", "Copied the selected row.")

    def _copy_table_column_data(self, table: QTableView, column: int) -> None:
        model = table.model()
        if model is None or not (0 <= column < model.columnCount()):
            return
        values = [
            self._tsv_cell(self._table_display_value(table, row, column))
            for row in range(model.rowCount())
        ]
        column_label = self._table_header_label(table, column)
        self._copy_to_clipboard(
            "\n".join(values),
            f"Copied {len(values)} value(s) from {column_label}.",
        )

    def _edit_note_for_row(self, entity_kind: str, row: dict[str, Any]) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            return
        signature = str(row.get("__signature") or entity_signature(entity_kind, row, snapshot))
        existing = self._notes.get(signature)
        dialog = EntityNoteDialog(str(row.get("__label") or row_label(entity_kind, row, snapshot)), existing.note if existing is not None else "", self)
        if dialog.exec() != QDialog.Accepted:
            return
        note = build_entity_note(entity_kind, row, snapshot, dialog.note_text())
        self._save_note(snapshot.workspace_id, note)
        self._notes[note.signature] = note
        self._refresh_models()
        if self.detail_card.isVisible() and self._active_detail_signature == note.signature:
            self._show_detail(entity_kind, row, self._active_detail_table)

    def _open_detail_for_index(self, table: QTableView, index: QModelIndex) -> None:
        row = index.data(Qt.UserRole) or {}
        entity_kind = str(table.property("entity_kind") or row.get("__entity_kind") or "")
        if not isinstance(row, dict) or not entity_kind:
            return
        table.selectRow(index.row())
        self._show_detail(entity_kind, row, table)

    def _show_detail(self, entity_kind: str, row: dict[str, Any], table: QTableView | None) -> None:
        if entity_kind == "http_history":
            self._show_http_history_detail(row, table)
            return
        snapshot = self._snapshot
        if snapshot is None:
            return
        signature = str(row.get("__signature") or entity_signature(entity_kind, row, snapshot))
        note = self._notes.get(signature)
        payload = build_detail_payload(entity_kind, row, snapshot, note=note)
        self._active_detail_signature = signature
        self._active_detail_kind = entity_kind
        self._active_detail_row = dict(row)
        self._active_detail_table = table
        self.detail_title.setText(str(row.get("__label") or row_label(entity_kind, row, snapshot)))
        summary_parts = [title_case_label(entity_kind), str(row.get("__target") or "")]
        if note is not None and note.note.strip():
            summary_parts.append("Has project notes")
        self.detail_summary.setText(" | ".join(part for part in summary_parts if part))
        set_plain_text_preserving_scroll(self.detail_text, self._build_detail_text(payload))
        self._expand_detail_card()

    def _show_http_history_detail(self, row: dict[str, Any], table: QTableView | None) -> None:
        entry = row.get("__entry")
        if not isinstance(entry, HttpHistoryEntry):
            return
        self._active_detail_signature = entry.history_id
        self._active_detail_kind = "http_history"
        self._active_detail_row = dict(row)
        self._active_detail_table = table
        self.detail_title.setText(f"{entry.method or 'HTTP'} {entry.url or entry.path}")
        status = f"{entry.response_status} {entry.response_reason}".strip() if entry.response_status else "No response"
        self.detail_summary.setText(
            " | ".join(
                part
                for part in (
                    entry.host,
                    status,
                    f"{entry.duration_ms} ms" if entry.duration_ms else "",
                    "TLS" if entry.tls else "",
                    entry.error,
                )
                if part
            )
        )
        set_plain_text_preserving_scroll(self.detail_text, self._build_http_history_detail_text(entry))
        self._expand_detail_card()

    def _build_http_history_detail_text(self, entry: HttpHistoryEntry) -> str:
        request_headers = "\n".join(f"{key}: {value}" for key, value in entry.request_headers.items())
        response_headers = "\n".join(f"{key}: {value}" for key, value in entry.response_headers.items())
        response_line = (
            f"HTTP/1.1 {entry.response_status} {entry.response_reason}".rstrip()
            if entry.response_status
            else "No response captured"
        )
        return "\n".join(
            [
                "Request",
                entry.raw_repeater_request or f"{entry.method} {entry.path} HTTP/1.1\nHost: {entry.host}\n{request_headers}",
                "",
                "Response",
                response_line,
                response_headers,
                "",
                entry.response_body_preview,
            ]
        )

    def _focus_row_in_graph(self, entity_kind: str, row: dict[str, Any]) -> None:
        if hasattr(self, "asset_views") and hasattr(self, "graph_view"):
            self.asset_views.setCurrentWidget(self.graph_view)
        label = str(row.get("__label") or row.get("name") or row.get("url") or row.get("host") or title_case_label(entity_kind))
        self.detail_title.setText("Graph View")
        self.detail_summary.setText("Focused inventory entity")
        self.detail_text.setPlainText(f"Graph view centered on {label}.")
        self._expand_detail_card()

    def _build_detail_text(self, payload: dict[str, Any]) -> str:
        lines: list[str] = []
        for key, value in payload.items():
            if isinstance(value, list):
                lines.append(f"{title_case_label(str(key))}: {len(value)} item(s)")
                for item in value[:10]:
                    lines.append(f"  - {item}")
            elif isinstance(value, dict):
                lines.append(f"{title_case_label(str(key))}:")
                for inner_key, inner_value in value.items():
                    if str(inner_key).startswith("__"):
                        continue
                    lines.append(f"  {title_case_label(str(inner_key))}: {inner_value}")
            else:
                lines.append(f"{title_case_label(str(key))}: {value}")
        return "\n".join(lines)

    def _expand_detail_card(self) -> None:
        sizes = self.main_split.sizes()
        if len(sizes) < 2 or sizes[1] > 0:
            return
        if self.main_split.orientation() == Qt.Horizontal:
            fallback = [max(int(self.width() * 0.7), 720), max(int(self.width() * 0.3), 320)]
        else:
            fallback = [max(int(self.height() * 0.68), 420), max(int(self.height() * 0.32), 220)]
        target_sizes = self.main_split_controller.saved_or_current_sizes(fallback) or fallback
        if len(target_sizes) >= 2 and target_sizes[1] == 0:
            remembered = self.main_split_controller._last_nonzero_sizes.get(splitter_orientation_key(self.main_split))
            if remembered is not None:
                target_sizes = remembered
            else:
                target_sizes = fallback
        self.main_split.setSizes(target_sizes)

    def _hide_detail_card(self) -> None:
        sizes = self.main_split.sizes()
        if len(sizes) >= 2:
            total = max(sum(sizes), 1)
            self.main_split.setSizes([total, 0])
        self._active_detail_signature = ""
        self._active_detail_kind = ""
        self._active_detail_row = {}
        self._active_detail_table = None

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())
