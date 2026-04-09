from __future__ import annotations

import json
from typing import Any, Callable

from PySide6.QtCore import QEvent, QModelIndex, QPoint, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
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
    SummaryCard,
    configure_scroll_surface,
    ensure_table_defaults,
    set_tooltip,
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
        layout.setSpacing(16)

        hero = QFrame()
        hero.setObjectName("heroPanel")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 18, 18, 18)
        hero_layout.setSpacing(10)
        self.title_label = QLabel("Assets Workspace")
        self.title_label.setObjectName("heroTitle")
        self.summary_label = QLabel("Select a run to organize discovered hosts, services, URLs, routes, and technologies.")
        self.summary_label.setObjectName("outputSummary")
        self.status_label = QLabel("No run selected")
        self.status_label.setObjectName("headerMeta")
        hero_layout.addWidget(self.title_label)
        hero_layout.addWidget(self.summary_label)
        hero_layout.addWidget(self.status_label)
        layout.addWidget(hero)

        cards = QGridLayout()
        cards.setHorizontalSpacing(12)
        cards.setVerticalSpacing(12)
        self.assets_card = SummaryCard("Assets")
        self.services_card = SummaryCard("Services")
        self.web_card = SummaryCard("Web")
        self.routes_card = SummaryCard("Routes")
        self.technologies_card = SummaryCard("Technologies")
        self.notes_card = SummaryCard("Notes")
        self.summary_cards = (
            self.assets_card,
            self.services_card,
            self.web_card,
            self.routes_card,
            self.technologies_card,
            self.notes_card,
        )
        for index, card in enumerate(self.summary_cards):
            cards.addWidget(card, index // 3, index % 3)
        layout.addLayout(cards)

        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(16, 16, 16, 16)
        toolbar_layout.setSpacing(10)
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search assets, services, URLs, notes, routes, or technologies")
        self.search_edit.textChanged.connect(self._refresh_models)
        set_tooltip(self.search_edit, "Search across discovered asset inventory and stored operator notes.")
        search_row.addWidget(self.search_edit, 1)
        toolbar_layout.addLayout(search_row)
        self.results_label = QLabel("Inventory will appear here once a run is selected.")
        self.results_label.setObjectName("helperText")
        self.results_label.setWordWrap(True)
        toolbar_layout.addWidget(self.results_label)
        layout.addWidget(toolbar)

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
        self.inventory_tabs.addTab(self._section("Discovered Assets", self.assets_view), "Assets")
        self.inventory_tabs.addTab(self._section("Discovered Services", self.services_view), "Services")

        web_page = QWidget()
        web_layout = QVBoxLayout(web_page)
        web_layout.setContentsMargins(0, 0, 0, 0)
        self.web_tabs = QTabWidget()
        self.web_tabs.setObjectName("subTabs")
        self.web_tabs.setDocumentMode(True)
        self.web_tabs.addTab(self._section("Web Applications", self.web_apps_view), "Web Apps")
        self.web_tabs.addTab(self._section("Endpoints", self.endpoints_view), "Endpoints")
        self.web_tabs.addTab(self._section("Parameters", self.parameters_view), "Parameters")
        self.web_tabs.addTab(self._section("Forms", self.forms_view), "Forms")
        self.web_tabs.addTab(self._section("Login Surfaces", self.login_surfaces_view), "Login")
        self.web_tabs.addTab(self._section("Routes", self.site_map_view), "Routes")
        web_layout.addWidget(self.web_tabs)
        self.inventory_tabs.addTab(web_page, "Web")

        self.inventory_tabs.addTab(self._section("Technology Inventory", self.technologies_view), "Technology")
        layout.addWidget(self.inventory_tabs, 1)

        self.detail_card = QFrame(self)
        self.detail_card.setObjectName("subtlePanel")
        self.detail_card.hide()
        self.detail_card.setFixedWidth(440)
        self.detail_card.raise_()
        detail_layout = QVBoxLayout(self.detail_card)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(10)
        card_header = QHBoxLayout()
        self.detail_title = QLabel("Asset Details")
        self.detail_title.setObjectName("sectionTitle")
        card_header.addWidget(self.detail_title)
        card_header.addStretch(1)
        self.detail_close_button = QPushButton("Close")
        self.detail_close_button.setProperty("variant", "secondary")
        self.detail_close_button.clicked.connect(self._hide_detail_card)
        card_header.addWidget(self.detail_close_button)
        detail_layout.addLayout(card_header)
        self.detail_summary = QLabel("")
        self.detail_summary.setObjectName("helperText")
        self.detail_summary.setWordWrap(True)
        detail_layout.addWidget(self.detail_summary)
        self.detail_text = configure_scroll_surface(QTextEdit())
        self.detail_text.setReadOnly(True)
        self.detail_text.setObjectName("consoleText")
        self.detail_text.setMinimumHeight(280)
        detail_layout.addWidget(self.detail_text, 1)

        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

    def closeEvent(self, event) -> None:  # noqa: N802
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self)
        super().closeEvent(event)

    def eventFilter(self, obj: object, event: object) -> bool:
        if not hasattr(self, "detail_card") or self.detail_card is None or not self.detail_card.isVisible():
            return False
        if isinstance(event, QEvent) and event.type() == QEvent.KeyPress and getattr(event, "key", lambda: None)() == Qt.Key_Escape:
            self._hide_detail_card()
            return False
        if isinstance(event, QEvent) and event.type() == QEvent.MouseButtonPress:
            global_pos = None
            if hasattr(event, "globalPosition"):
                global_pos = event.globalPosition().toPoint()
            elif hasattr(event, "globalPos"):
                global_pos = event.globalPos()
            if global_pos is not None:
                local_pos = self.detail_card.mapFromGlobal(global_pos)
                if not self.detail_card.rect().contains(local_pos):
                    self._hide_detail_card()
        return False

    def _section(self, title: str, widget: QWidget) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget)
        return section

    def _make_table(self, model: MappingTableModel, entity_kind: str) -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setProperty("entity_kind", entity_kind)
        table.setModel(model)
        ensure_table_defaults(table)
        table.doubleClicked.connect(lambda index, view=table: self._open_detail_for_index(view, index))
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda point, view=table: self._open_context_menu(view, point))
        set_tooltip(table, "Double-click for an expandable detail card. Right-click for scan and notes actions.")
        return table

    def focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot
        self._notes = self._load_notes(snapshot.workspace_id if snapshot is not None else "") if snapshot is not None else {}
        self._hide_detail_card()
        self._refresh_models()

    def _refresh_models(self) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            self.title_label.setText("Assets Workspace")
            self.summary_label.setText("Select a run to organize discovered hosts, services, URLs, routes, and technologies.")
            self.status_label.setText("No run selected")
            self.results_label.setText("Inventory will appear here once a run is selected.")
            for card, hint in (
                (self.assets_card, "Observed host and domain inventory"),
                (self.services_card, "Open ports and named services"),
                (self.web_card, "Web apps, endpoints, forms, and login surfaces"),
                (self.routes_card, "Mapped routes and related discovery"),
                (self.technologies_card, "Detected technology stack"),
                (self.notes_card, "Workspace-scoped notes on discovered entities"),
            ):
                card.set_value("0", hint)
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

        self.title_label.setText(snapshot.scan_name)
        self.summary_label.setText(
            f"Workspace: {snapshot.workspace_name or 'Unassigned'} | Target: {snapshot.target_input or 'n/a'}"
        )
        self.status_label.setText(
            f"Assets {len(snapshot.assets)} | Services {len(snapshot.services)} | Web {len(snapshot.web_apps)} | Routes {len(snapshot.site_map)} | Notes {len([note for note in self._notes.values() if note.note.strip()])}"
        )
        self.results_label.setText(
            "Showing "
            f"{len(filtered_assets)}/{len(snapshot.assets)} assets, "
            f"{len(filtered_services)}/{len(snapshot.services)} services, "
            f"{len(filtered_web_apps)}/{len(snapshot.web_apps)} web apps, "
            f"{len(filtered_endpoints)}/{len(snapshot.endpoints)} endpoints, "
            f"{len(filtered_routes)}/{len(snapshot.site_map)} routes, "
            f"{len(filtered_technologies)}/{len(snapshot.technologies)} technologies"
        )
        self.assets_card.set_value(str(len(snapshot.assets)), "Observed hosts, domains, and IP-backed entities")
        self.services_card.set_value(str(len(snapshot.services)), "Open ports and parsed service banners")
        self.web_card.set_value(
            str(len(snapshot.web_apps) + len(snapshot.endpoints) + len(snapshot.forms)),
            f"{len(snapshot.login_surfaces)} login surfaces and {len(snapshot.parameters)} parameters",
        )
        self.routes_card.set_value(str(len(snapshot.site_map)), "Mapped routes and discovery URLs")
        self.technologies_card.set_value(str(len(snapshot.technologies)), "Detected technologies tied to discovered assets")
        note_count = len([note for note in self._notes.values() if note.note.strip()])
        self.notes_card.set_value(str(note_count), "Workspace-scoped operator notes for rediscovered entities")

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
        if self.detail_card.isVisible() and self._active_detail_signature == signature:
            self._hide_detail_card()
            return
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
        self._position_detail_card(table)
        self.detail_card.show()
        self.detail_card.raise_()

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

    def _position_detail_card(self, table: QTableView | None) -> None:
        margin = 18
        card_width = min(440, max(self.width() - margin * 2, 320))
        self.detail_card.setFixedWidth(card_width)
        x = max(self.width() - card_width - margin, margin)
        y = 150
        if table is not None:
            anchor = table.mapTo(self, QPoint(0, 0))
            y = max(anchor.y() + 12, 150)
        max_y = max(self.height() - self.detail_card.sizeHint().height() - margin, margin)
        self.detail_card.move(x, min(y, max_y))
        self.detail_card.resize(card_width, min(max(320, self.height() - y - margin), 520))

    def _hide_detail_card(self) -> None:
        self.detail_card.hide()
        self._active_detail_signature = ""
        self._active_detail_kind = ""
        self._active_detail_row = {}
        self._active_detail_table = None

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if self.detail_card.isVisible():
            self._position_detail_card(self._active_detail_table)
