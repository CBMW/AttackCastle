from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QItemSelectionModel, QModelIndex, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    FINDING_STATUSES,
    FlowButtonRow,
    MappingTableModel,
    PAGE_SECTION_SPACING,
    PersistentSplitterController,
    SEVERITY_ORDER,
    SURFACE_FLAT,
    apply_responsive_splitter,
    apply_form_layout_defaults,
    build_flat_container,
    configure_tab_widget,
    configure_scroll_surface,
    ensure_table_defaults,
    set_tooltip,
    set_tooltips,
    style_button,
    title_case_label,
)
from attackcastle.gui.models import FindingState, RunSnapshot


class OutputTab(QWidget):
    def __init__(
        self,
        save_finding_state: Callable[[str, FindingState], None],
        open_path: Callable[[str], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._persist_finding_state = save_finding_state
        self._open_path = open_path
        self._snapshot: RunSnapshot | None = None
        self._finding_states: dict[str, FindingState] = {}
        self._current_finding_id = ""
        self._current_path = ""
        self._preview_path = ""
        self._active_detail_kind = ""
        self._active_detail_identity = ""
        self._active_detail_table: QTableView | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        top_panel = build_flat_container()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(PAGE_SECTION_SPACING)

        filter_panel = QFrame()
        filter_panel.setObjectName("toolbarStrip")
        filter_panel.setProperty("surface", SURFACE_FLAT)
        filter_layout = QVBoxLayout(filter_panel)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(PAGE_SECTION_SPACING)
        self.filter_grid = QGridLayout()
        self.filter_grid.setHorizontalSpacing(PAGE_SECTION_SPACING)
        self.filter_grid.setVerticalSpacing(PAGE_SECTION_SPACING)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search findings and workflow notes")
        self.search_edit.textChanged.connect(self._refresh_models)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "critical", "high", "medium", "low", "info"])
        self.severity_filter.currentTextChanged.connect(self._refresh_models)
        self.workflow_filter = QComboBox()
        self.workflow_filter.addItems(["All Workflow States", *FINDING_STATUSES])
        self.workflow_filter.currentTextChanged.connect(self._refresh_models)
        self.filter_controls: list[tuple[QLabel, QWidget]] = [
            (QLabel("Search"), self.search_edit),
            (QLabel("Severity"), self.severity_filter),
            (QLabel("Workflow"), self.workflow_filter),
        ]
        set_tooltips(
            (
                (self.search_edit, "Search across findings and workflow details."),
                (self.severity_filter, "Filter findings and related tables by severity."),
                (self.workflow_filter, "Filter findings by workflow state."),
            )
        )
        filter_layout.addLayout(self.filter_grid)
        top_layout.addWidget(filter_panel)

        self.findings_model = MappingTableModel(
            [("Severity", "effective_severity"), ("Workflow", "workflow_status"), ("Report", lambda row: "Yes" if row.get("include_in_report") else "No"), ("Title", "title"), ("Category", "category")]
        )

        self.findings_view = self._make_table(self.findings_model, self._finding_selected)

        self.detail_text = configure_scroll_surface(QTextEdit())
        self.detail_text.setObjectName("consoleText")
        self.detail_text.setReadOnly(True)
        self.raw_text = configure_scroll_surface(QTextEdit())
        self.raw_text.setObjectName("consoleText")
        self.raw_text.setReadOnly(True)
        self.inspector_summary = QLabel("Select an item to inspect technical details and artifacts.")
        self.inspector_summary.setObjectName("helperText")
        self.inspector_summary.setWordWrap(True)
        self.inspector_summary.setMaximumWidth(260)
        self.inspector_summary.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.screenshot_preview = QLabel("Screenshot preview")
        self.screenshot_preview.setObjectName("previewSurface")
        self.screenshot_preview.setAlignment(Qt.AlignCenter)
        self.screenshot_preview.setMinimumHeight(160)
        self.preview_meta_label = QLabel("No artifact selected")
        self.preview_meta_label.setObjectName("helperText")
        self.preview_meta_label.setWordWrap(True)
        self.open_path_button = QPushButton("Open File")
        self.open_path_button.clicked.connect(self.open_current_artifact)
        style_button(self.open_path_button, role="secondary")
        self.open_folder_button = QPushButton("Open Folder")
        self.open_folder_button.clicked.connect(self._open_current_folder)
        style_button(self.open_folder_button, role="secondary")

        self.finding_status_combo = QComboBox()
        self.finding_status_combo.addItems(FINDING_STATUSES)
        self.finding_severity_combo = QComboBox()
        self.finding_severity_combo.addItems(["", "critical", "high", "medium", "low", "info"])
        self.finding_include_checkbox = QCheckBox("Include in report")
        self.finding_note_edit = configure_scroll_surface(QPlainTextEdit())
        self.finding_note_edit.setMinimumHeight(60)
        self.finding_repro_edit = configure_scroll_surface(QPlainTextEdit())
        self.finding_repro_edit.setMinimumHeight(60)
        self.finding_save_button = QPushButton("Save Workflow State")
        self.finding_save_button.clicked.connect(self._save_workflow_state)
        style_button(self.finding_save_button)
        set_tooltips(
            (
                (self.open_path_button, "Open the currently selected artifact file."),
                (self.open_folder_button, "Open the folder that contains the currently selected artifact."),
                (self.finding_status_combo, "Set the workflow state for the selected finding."),
                (self.finding_severity_combo, "Override the effective severity for the selected finding."),
                (self.finding_include_checkbox, "Control whether the selected finding should appear in the report staging queue."),
                (self.finding_note_edit, "Record analyst notes or triage context for the selected finding."),
                (self.finding_repro_edit, "Capture reproduction notes or operator follow-up guidance."),
                (self.finding_save_button, "Save the current workflow overrides for the selected finding."),
            )
        )

        main_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (3, 2))
        main_split.setObjectName("outputSplit")
        self.main_split = main_split
        main_split.addWidget(self._table_surface("Findings Queue", self.findings_view))

        self.inspector_tabs = QTabWidget()
        configure_tab_widget(self.inspector_tabs, role="inspector")
        self.inspector_tabs.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.inspector_tabs.setCornerWidget(self.inspector_summary, Qt.TopRightCorner)
        self.inspector_tabs.addTab(self._section("Details", self.detail_text), "Details")
        self.inspector_tabs.addTab(self._section("Raw", self.raw_text), "Raw")
        workflow_widget = build_flat_container()
        workflow_layout = QFormLayout(workflow_widget)
        apply_form_layout_defaults(workflow_layout)
        workflow_layout.addRow("Status", self.finding_status_combo)
        workflow_layout.addRow("Severity Override", self.finding_severity_combo)
        workflow_layout.addRow("Report", self.finding_include_checkbox)
        workflow_layout.addRow("Analyst Note", self.finding_note_edit)
        workflow_layout.addRow("Reproduction Steps", self.finding_repro_edit)
        workflow_layout.addRow("", self.finding_save_button)
        self.inspector_tabs.addTab(self._section("Workflow", workflow_widget), "Workflow")
        preview_widget = build_flat_container()
        preview_layout = QVBoxLayout(preview_widget)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.addWidget(self.screenshot_preview)
        preview_layout.addWidget(self.preview_meta_label)
        preview_actions = FlowButtonRow()
        preview_actions.addWidget(self.open_path_button)
        preview_actions.addWidget(self.open_folder_button)
        preview_layout.addWidget(preview_actions)
        self.preview_tab_index = self.inspector_tabs.addTab(self._section("Preview", preview_widget), "Preview")
        self.inspector_tabs.setTabToolTip(0, "Review formatted details for the selected row.")
        self.inspector_tabs.setTabToolTip(1, "Review the raw JSON-style payload for the selected row.")
        self.inspector_tabs.setTabToolTip(2, "Edit workflow overrides for the selected finding.")
        self.inspector_tabs.setTabToolTip(self.preview_tab_index, "Preview screenshots and inspect artifact paths.")
        main_split.addWidget(self.inspector_tabs)
        self.main_split_controller = PersistentSplitterController(
            self.main_split,
            "findings_main_split",
            layout_loader,
            layout_saver,
            self,
        )
        layout.addWidget(top_panel)
        layout.addWidget(main_split, 1)
        self.sync_responsive_mode(self.width())

    def _section(self, title: str, widget: QWidget) -> QWidget:
        section = build_flat_container()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget)
        return section

    def _table_surface(self, title: str, table: QTableView) -> QWidget:
        surface = build_flat_container()
        layout = QVBoxLayout(surface)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(table, 1)
        return surface

    def _make_table(self, model: MappingTableModel, callback: Callable[[QModelIndex], None]) -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setModel(model)
        headings = [str(column[0]).lower() for column in model._columns]
        policies = []
        for heading in headings:
            if heading in {"state", "status", "severity", "workflow", "change", "include", "report", "port", "eta", "elapsed", "forms", "priority", "confidence", "replay", "auto"}:
                policies.append({"mode": "content", "min": 90, "max": 130})
            elif heading in {"url", "title", "next action", "summary", "snippet", "artifact", "path", "note"}:
                policies.append({"mode": "stretch", "min": 220})
            elif heading in {"kind", "category", "family", "tool", "source", "protocol", "method"}:
                policies.append({"mode": "content", "min": 110, "max": 160})
            else:
                policies.append({"mode": "mixed", "min": 140, "width": 180})
        ensure_table_defaults(table, column_policies=policies, minimum_rows=9)
        table.clicked.connect(callback)
        set_tooltip(table, "Select a row to inspect more detail in the panel on the right.")
        return table

    def sync_responsive_mode(self, width: int) -> None:
        self._arrange_filter_controls(width)
        self.main_split.setOrientation(Qt.Horizontal if width >= 1280 else Qt.Vertical)
        if width >= 1280:
            self.main_split_controller.apply([max(int(width * 0.68), 700), max(int(width * 0.32), 340)])
        else:
            self.main_split_controller.apply([max(int(self.height() * 0.6), 320), max(int(self.height() * 0.4), 260)])

    def _arrange_filter_controls(self, width: int) -> None:
        while self.filter_grid.count():
            self.filter_grid.takeAt(0)
        if width >= 1480:
            column = 0
            for label, widget in self.filter_controls:
                self.filter_grid.addWidget(label, 0, column)
                self.filter_grid.addWidget(widget, 0, column + 1)
                column += 2
        elif width >= 1180:
            row = 0
            column = 0
            for label, widget in self.filter_controls:
                self.filter_grid.addWidget(label, row, column)
                self.filter_grid.addWidget(widget, row, column + 1)
                column += 2
                if column >= 6:
                    row += 1
                    column = 0
        else:
            for row, (label, widget) in enumerate(self.filter_controls):
                self.filter_grid.addWidget(label, row, 0)
                self.filter_grid.addWidget(widget, row, 1)

    def focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def focus_findings(self) -> None:
        self.findings_view.setFocus()

    def open_current_artifact(self) -> None:
        if self._current_path:
            self._open_path(self._current_path)

    def has_current_artifact(self) -> bool:
        return bool(self._current_path)

    def set_snapshot(self, snapshot: RunSnapshot | None, finding_states: dict[str, FindingState] | None = None) -> None:
        previous_run_id = self._snapshot.run_id if self._snapshot is not None else ""
        next_run_id = snapshot.run_id if snapshot is not None else ""
        run_changed = bool(previous_run_id and next_run_id and previous_run_id != next_run_id)
        self._snapshot = snapshot
        self._finding_states = finding_states or {}
        if run_changed:
            self._clear_active_detail()
            self.detail_text.clear()
            self.raw_text.clear()
            self.inspector_summary.setText("Select an item to inspect technical details and artifacts.")
            self._current_finding_id = ""
            self._set_current_path("")
            self._reset_finding_editor()
        self._refresh_models()

    def _refresh_models(self) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            self.findings_model.set_rows([])
            self.detail_text.clear()
            self.raw_text.clear()
            self.inspector_summary.setText("Select an item to inspect technical details and artifacts.")
            self.screenshot_preview.setPixmap(QPixmap())
            self.screenshot_preview.setText("Screenshot preview")
            self.preview_meta_label.setText("No artifact selected")
            self._current_finding_id = ""
            self._set_current_path("")
            self._clear_active_detail()
            self._reset_finding_editor()
            return

        findings = self._merge_finding_state(snapshot.findings)
        filtered_findings = self._filter_findings(findings)
        self.findings_model.set_rows(filtered_findings)
        if self._active_detail_kind:
            self._restore_active_detail()
        elif not self.detail_text.toPlainText():
            self.detail_text.setPlainText("Select a finding for details.")

    def _merge_finding_state(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for finding in findings:
            row = dict(finding)
            state = self._finding_states.get(str(row.get("finding_id") or ""))
            base_severity = str(row.get("severity") or "info").lower()
            row["workflow_status"] = state.status if state else "needs-validation"
            row["analyst_note"] = state.analyst_note if state else ""
            row["include_in_report"] = state.include_in_report if state else True
            row["severity_override"] = state.severity_override if state else ""
            row["effective_severity"] = (state.severity_override if state else "") or base_severity
            row["reproduce_steps"] = state.reproduce_steps if state else ""
            rows.append(row)
        rows.sort(key=lambda row: (SEVERITY_ORDER.get(str(row.get("effective_severity") or "info").lower(), 99), str(row.get("title") or "")))
        return rows

    def _filter_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.search_edit.text().strip().lower()
        result: list[dict[str, Any]] = []
        for row in rows:
            if search and search not in json.dumps(row, sort_keys=True).lower():
                continue
            result.append(row)
        return result

    def _filter_findings(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        severity = self.severity_filter.currentText()
        workflow = self.workflow_filter.currentText()
        result: list[dict[str, Any]] = []
        for row in self._filter_rows(rows):
            if severity != "All Severities" and str(row.get("effective_severity") or "").lower() != severity:
                continue
            if workflow != "All Workflow States" and str(row.get("workflow_status") or "") != workflow:
                continue
            result.append(row)
        return result

    def _finding_selected(self, index: QModelIndex) -> None:
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="finding", table=self.findings_view)
        self._current_finding_id = str(row.get("finding_id") or "")
        self.finding_status_combo.setCurrentText(str(row.get("workflow_status") or "needs-validation"))
        self.finding_severity_combo.setCurrentText(str(row.get("severity_override") or ""))
        self.finding_include_checkbox.setChecked(bool(row.get("include_in_report", True)))
        self.finding_note_edit.setPlainText(str(row.get("analyst_note") or ""))
        self.finding_repro_edit.setPlainText(str(row.get("reproduce_steps") or ""))

    def _show_details(
        self,
        row: dict[str, Any],
        *,
        kind: str = "",
        table: QTableView | None = None,
        identity_row: dict[str, Any] | None = None,
    ) -> None:
        if kind:
            self._active_detail_kind = kind
            self._active_detail_identity = self._row_identity(kind, identity_row or row)
            self._active_detail_table = table
        detail_keys = [title_case_label(str(key)) for key in row.keys()]
        if detail_keys:
            self.inspector_summary.setText(f"Inspecting {', '.join(detail_keys[:3])}{'...' if len(detail_keys) > 3 else ''}")
        else:
            self.inspector_summary.setText("Select an item to inspect technical details and artifacts.")
        self.detail_text.setPlainText(self._build_technical_text(row))
        self.raw_text.setPlainText(json.dumps(row, indent=2, sort_keys=True))

    def _clear_active_detail(self) -> None:
        self._active_detail_kind = ""
        self._active_detail_identity = ""
        self._active_detail_table = None

    def _row_identity(self, kind: str, row: dict[str, Any]) -> str:
        primary_id = row.get("finding_id") if kind == "finding" else None
        if primary_id not in (None, ""):
            return f"{kind}:{primary_id}"
        values = [str(row.get(field) or "") for field in ("finding_id", "title", "category")]
        identity = "|".join(values).strip("|")
        return identity or json.dumps(row, sort_keys=True, default=str)

    def _detail_sources(self) -> dict[str, tuple[QTableView, MappingTableModel]]:
        return {"finding": (self.findings_view, self.findings_model)}

    def _restore_active_detail(self) -> None:
        if not self._active_detail_kind or not self._active_detail_identity:
            return
        source = self._detail_sources().get(self._active_detail_kind)
        if source is None or self._snapshot is None:
            return
        table, model = source
        for row_index in range(model.rowCount()):
            index = model.index(row_index, 0)
            row = index.data(Qt.UserRole) or {}
            if not isinstance(row, dict):
                continue
            if self._row_identity(self._active_detail_kind, row) != self._active_detail_identity:
                continue
            selection = table.selectionModel()
            if selection is not None:
                selection.setCurrentIndex(index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            table.setCurrentIndex(index)
            table.selectRow(row_index)
            self._show_details(row, kind=self._active_detail_kind, table=table)
            return

    def _build_technical_text(self, payload: dict[str, Any]) -> str:
        lines = []
        for key, value in payload.items():
            if isinstance(value, list):
                lines.append(f"{title_case_label(str(key))}: {len(value)} item(s)")
                for item in value[:10]:
                    lines.append(f"  - {item}")
            elif isinstance(value, dict):
                lines.append(f"{title_case_label(str(key))}:")
                for inner_key, inner_value in value.items():
                    lines.append(f"  {title_case_label(str(inner_key))}: {inner_value}")
            else:
                lines.append(f"{title_case_label(str(key))}: {value}")
        return "\n".join(lines)

    def _set_current_path(self, path: str) -> None:
        self._current_path = path
        self.open_path_button.setEnabled(bool(path))
        self.open_folder_button.setEnabled(bool(path))
        self.preview_meta_label.setText(path or "No artifact selected")

    def _open_current_folder(self) -> None:
        if not self._current_path:
            return
        target = Path(self._current_path)
        folder = target if target.is_dir() else target.parent
        self._open_path(str(folder))

    def _render_preview(self) -> None:
        if not self._preview_path:
            self.screenshot_preview.setPixmap(QPixmap())
            self.screenshot_preview.setText("Screenshot preview")
            return
        pixmap = QPixmap(self._preview_path)
        if pixmap.isNull():
            self.screenshot_preview.setPixmap(QPixmap())
            self.screenshot_preview.setText(self._preview_path)
            return
        scaled = pixmap.scaled(self.screenshot_preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.screenshot_preview.setPixmap(scaled)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())
        self._render_preview()

    def _save_workflow_state(self) -> None:
        if not self._current_finding_id or self._snapshot is None:
            QMessageBox.information(self, "No Finding", "Select a finding before saving workflow state.")
            return
        state = FindingState(
            finding_id=self._current_finding_id,
            status=self.finding_status_combo.currentText(),
            analyst_note=self.finding_note_edit.toPlainText().strip(),
            severity_override=self.finding_severity_combo.currentText(),
            include_in_report=self.finding_include_checkbox.isChecked(),
            reproduce_steps=self.finding_repro_edit.toPlainText().strip(),
        )
        self._finding_states[self._current_finding_id] = state
        self._persist_finding_state(self._snapshot.run_id, state)
        self._refresh_models()

    def _reset_finding_editor(self) -> None:
        self.finding_status_combo.setCurrentText("needs-validation")
        self.finding_severity_combo.setCurrentText("")
        self.finding_include_checkbox.setChecked(True)
        self.finding_note_edit.clear()
        self.finding_repro_edit.clear()
