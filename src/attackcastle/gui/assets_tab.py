from __future__ import annotations

import json
from typing import Any, Callable

from PySide6.QtCore import QModelIndex, QPoint, Qt
from PySide6.QtWidgets import (
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
    build_inspector_panel,
    build_surface_frame,
    configure_scroll_surface,
    ensure_table_defaults,
    set_tooltip,
    style_button,
    splitter_orientation_key,
    title_case_label,
)
from attackcastle.gui.models import EntityNote, RunSnapshot


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
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._launch_scan = launch_scan
        self._load_notes = load_notes
        self._save_note = save_note
        self._snapshot: RunSnapshot | None = None
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
            spacing=8,
        )
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search assets, services, URLs, notes, routes, or technologies")
        self.search_edit.textChanged.connect(self._refresh_models)
        set_tooltip(self.search_edit, "Search across discovered asset inventory and stored operator notes.")
        search_row.addWidget(self.search_edit, 1)
        toolbar_layout.addLayout(search_row)
        content_layout.addWidget(toolbar)

        self.assets_model = MappingTableModel(
            [
                ("Kind", "kind"),
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

        self.assets_view = self._make_table(self.assets_model, "asset")
        self.services_view = self._make_table(self.services_model, "service")
        self.web_apps_view = self._make_table(self.web_apps_model, "web_app")
        self.endpoints_view = self._make_table(self.endpoints_model, "endpoint")
        self.parameters_view = self._make_table(self.parameters_model, "parameter")
        self.forms_view = self._make_table(self.forms_model, "form")
        self.login_surfaces_view = self._make_table(self.login_surfaces_model, "login_surface")
        self.site_map_view = self._make_table(self.site_map_model, "site_map")
        self.technologies_view = self._make_table(self.technologies_model, "technology")

        self.inventory_tabs = QTabWidget()
        self.inventory_tabs.setObjectName("subTabs")
        self.inventory_tabs.setDocumentMode(True)
        self.inventory_tabs.addTab(self._table_surface("Discovered Assets", self.assets_view), "Assets")
        self.inventory_tabs.addTab(self._table_surface("Discovered Services", self.services_view), "Services")

        web_page = QWidget()
        web_layout = QVBoxLayout(web_page)
        web_layout.setContentsMargins(0, 0, 0, 0)
        self.web_tabs = QTabWidget()
        self.web_tabs.setObjectName("subTabs")
        self.web_tabs.setDocumentMode(True)
        self.web_tabs.addTab(self._table_surface("Web Applications", self.web_apps_view), "Web Apps")
        self.web_tabs.addTab(self._table_surface("Endpoints", self.endpoints_view), "Endpoints")
        self.web_tabs.addTab(self._table_surface("Parameters", self.parameters_view), "Parameters")
        self.web_tabs.addTab(self._table_surface("Forms", self.forms_view), "Forms")
        self.web_tabs.addTab(self._table_surface("Login Surfaces", self.login_surfaces_view), "Login")
        self.web_tabs.addTab(self._table_surface("Routes", self.site_map_view), "Routes")
        web_layout.addWidget(self.web_tabs)
        self.inventory_tabs.addTab(web_page, "Web")

        self.inventory_tabs.addTab(self._table_surface("Technology Inventory", self.technologies_view), "Technology")
        content_layout.addWidget(self.inventory_tabs, 1)

        detail_body = QWidget()
        detail_body_layout = QVBoxLayout(detail_body)
        detail_body_layout.setContentsMargins(0, 0, 0, 0)
        detail_body_layout.setSpacing(10)
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
        section = QWidget()
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
        }
        ensure_table_defaults(table, column_policies=policies.get(entity_kind), minimum_rows=9)
        table.doubleClicked.connect(lambda index, view=table: self._open_detail_for_index(view, index))
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda point, view=table: self._open_context_menu(view, point))
        set_tooltip(table, "Double-click for an expandable detail card. Right-click for scan and notes actions.")
        return table

    def focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def sync_responsive_mode(self, width: int) -> None:
        self.main_split.setOrientation(Qt.Horizontal if width >= 1280 else Qt.Vertical)
        if width >= 1280:
            self.main_split_controller.apply([max(int(width * 0.74), 760), max(int(width * 0.26), 340)])
        else:
            self.main_split_controller.apply([max(int(self.height() * 0.68), 420), max(int(self.height() * 0.32), 220)])

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot
        self._notes = self._load_notes(snapshot.workspace_id if snapshot is not None else "") if snapshot is not None else {}
        self._hide_detail_card()
        self._refresh_models()

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
        if not index.isValid() or self._snapshot is None:
            return
        table.selectRow(index.row())
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict):
            return
        entity_kind = str(table.property("entity_kind") or row.get("__entity_kind") or "")
        menu, scan_action, notes_action = self._build_context_menu(table, entity_kind, row)
        target = str(row.get("__target") or "")
        action = menu.exec(table.viewport().mapToGlobal(point))
        if action is scan_action and target:
            self._launch_scan(target, row.get("__label") or row_label(entity_kind, row, self._snapshot))
        elif action is notes_action:
            self._edit_note_for_row(entity_kind, row)

    def _build_context_menu(self, table: QTableView, entity_kind: str, row: dict[str, Any]) -> tuple[QMenu, Any, Any]:
        target = str(row.get("__target") or "")
        menu = QMenu(table)
        scan_action = menu.addAction("Scan Asset")
        scan_action.setEnabled(bool(target))
        notes_action = menu.addAction("Add Notes")
        return menu, scan_action, notes_action

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
            summary_parts.append("Has workspace notes")
        self.detail_summary.setText(" | ".join(part for part in summary_parts if part))
        self.detail_text.setPlainText(self._build_detail_text(payload))
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
