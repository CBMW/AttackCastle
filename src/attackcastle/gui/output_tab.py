from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QEvent, QItemSelectionModel, QModelIndex, QTimer, Qt
from PySide6.QtGui import QPixmap, QTextOption
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
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
    size_dialog_to_screen,
    style_button,
    title_case_label,
)
from attackcastle.gui.models import FindingState, RunSnapshot, now_iso


RISK_LEVELS = ("high", "medium", "low")
RATING_SEVERITY_MATRIX = {
    ("high", "high"): "critical",
    ("medium", "high"): "high",
    ("low", "high"): "medium",
    ("high", "medium"): "medium",
    ("medium", "medium"): "medium",
    ("low", "medium"): "low",
    ("high", "low"): "low",
    ("medium", "low"): "low",
    ("low", "low"): "low",
}
MANUAL_FINDING_TEXT_LIMIT = 1000
ROOT_CAUSE_TAGS = (
    "Misconfigured System",
    "Unsafe Practices",
    "Unmanaged Vuln",
    "Human Factor Vuln",
    "Flawed Foundation",
    "Governance Oversight",
)
REPORT_TAGS = (
    "Mobile App",
    "WIFI Pentest",
    "Internal Infra Pentest",
    "External Infra Pentest",
    "Web App",
    "API Pentest",
    "Source Code Review",
    "Cloud Hardening",
)
TRANSIENT_FINDING_FIELDS = {
    "workflow_status",
    "analyst_note",
    "include_in_report",
    "report_flag_touched",
    "severity_override",
    "effective_severity",
}


class SearchableDropDownComboBox(QComboBox):
    def __init__(self) -> None:
        super().__init__()
        self.setEditable(True)
        line_edit = self.lineEdit()
        if line_edit is not None:
            line_edit.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if watched is self.lineEdit() and event.type() in {QEvent.FocusIn, QEvent.MouseButtonPress}:
            self._show_options()
        return super().eventFilter(watched, event)

    def focusInEvent(self, event) -> None:  # noqa: N802
        super().focusInEvent(event)
        self._show_options()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        super().mousePressEvent(event)
        self._show_options()

    def _show_options(self) -> None:
        QTimer.singleShot(0, self.showPopup)


class CreateFindingDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, finding: dict[str, Any] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Finding")
        self.setModal(True)
        self.setMinimumSize(720, 620)
        size_dialog_to_screen(self, default_width=940, default_height=860, min_width=720, min_height=620)
        self._loading_finding = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.finding_tabs = QTabWidget()
        configure_tab_widget(self.finding_tabs, role="group")
        self.finding_tabs.setObjectName("findingEditorTabs")
        layout.addWidget(self.finding_tabs, 1)

        self.title_edit = QLineEdit()
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["critical", "high", "medium", "low", "info"])
        self.root_cause_combo = self._searchable_combo(ROOT_CAUSE_TAGS, "Select or search root cause")
        self.report_tag_combo = self._searchable_combo(REPORT_TAGS, "Select or search report tag")
        self.cve_edit = QLineEdit()
        self.affected_assets_edit = QLineEdit()
        self.affected_assets_edit.setPlaceholderText("www.example.com, www.example2.com, 127.0.0.1")
        self.description_edit = self._text_edit(86)
        self.details_edit = self._text_edit(100)
        self.impact_combo = self._searchable_combo(RISK_LEVELS, "Select or search impact rating")
        self.likelihood_combo = self._searchable_combo(RISK_LEVELS, "Select or search likelihood rating")
        self.impact_edit = self._text_edit(90)
        self.likelihood_edit = self._text_edit(90)
        self.recommendations_edit = self._text_edit(90)
        self.supporting_evidence_edit = self._text_edit(90)
        self.impact_combo.currentTextChanged.connect(self._sync_severity_from_ratings)
        self.likelihood_combo.currentTextChanged.connect(self._sync_severity_from_ratings)

        summary_tab, summary_form = self._form_tab()
        summary_form.addRow("Title", self.title_edit)
        summary_form.addRow("Severity", self.severity_combo)
        summary_form.addRow("Root Cause", self.root_cause_combo)
        summary_form.addRow("Report Tag", self.report_tag_combo)
        summary_form.addRow("CVE", self.cve_edit)
        summary_form.addRow("Affected Assets", self.affected_assets_edit)
        summary_form.addRow("Description", self.description_edit)
        self.finding_tabs.addTab(summary_tab, "Summary")

        risk_tab, risk_form = self._form_tab()
        risk_form.addRow("Impact Rating", self.impact_combo)
        risk_form.addRow("Likelihood Rating", self.likelihood_combo)
        risk_form.addRow("Impact", self.impact_edit)
        risk_form.addRow("Likelihood", self.likelihood_edit)
        self.finding_tabs.addTab(risk_tab, "Risk")

        guidance_tab, guidance_form = self._form_tab()
        guidance_form.addRow("Details", self.details_edit)
        guidance_form.addRow("Recommendations", self.recommendations_edit)
        self.finding_tabs.addTab(guidance_tab, "Guidance")

        evidence_tab, evidence_form = self._form_tab()
        evidence_form.addRow("Supporting Evidence", self.supporting_evidence_edit)
        self.finding_tabs.addTab(evidence_tab, "Evidence")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_button = buttons.button(QDialogButtonBox.Ok)
        if ok_button is not None:
            ok_button.setText("Save")
            style_button(ok_button)
        cancel_button = buttons.button(QDialogButtonBox.Cancel)
        if cancel_button is not None:
            style_button(cancel_button, role="secondary")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        if finding is not None:
            self._load_finding(finding)

    def _form_tab(self) -> tuple[QWidget, QFormLayout]:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        panel = QFrame()
        panel.setObjectName("launchPanelGroup")
        form = QFormLayout(panel)
        form.setContentsMargins(12, 14, 12, 12)
        apply_form_layout_defaults(form)
        layout.addWidget(panel, 1)
        return tab, form

    def _searchable_combo(self, options: tuple[str, ...], placeholder: str) -> QComboBox:
        combo = SearchableDropDownComboBox()
        combo.setInsertPolicy(QComboBox.NoInsert)
        combo.addItems(list(options))
        combo.setCurrentText("")
        combo.setMinimumWidth(320)
        line_edit = combo.lineEdit()
        if line_edit is not None:
            line_edit.setPlaceholderText(placeholder)
        completer = combo.completer()
        if completer is not None:
            completer.setCaseSensitivity(Qt.CaseInsensitive)
            completer.setFilterMode(Qt.MatchContains)
        return combo

    def _text_edit(self, minimum_height: int) -> QPlainTextEdit:
        editor = configure_scroll_surface(QPlainTextEdit())
        editor.setMinimumHeight(minimum_height)
        editor.setMinimumWidth(320)
        editor.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        editor.setPlainText("")
        editor.setReadOnly(False)
        editor.setUndoRedoEnabled(True)
        editor.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        editor.setTabChangesFocus(False)
        editor.setTextInteractionFlags(Qt.TextEditorInteraction)
        editor.document().setMaximumBlockCount(0)
        editor.textChanged.connect(lambda editor=editor: self._enforce_text_limit(editor))
        return editor

    def _valid_rating_text(self, combo: QComboBox) -> str:
        value = combo.currentText().strip().lower()
        return value if value in RISK_LEVELS else ""

    def _sync_severity_from_ratings(self, *_args: object) -> None:
        if self._loading_finding:
            return
        likelihood = self._valid_rating_text(self.likelihood_combo)
        impact = self._valid_rating_text(self.impact_combo)
        severity = RATING_SEVERITY_MATRIX.get((likelihood, impact))
        if severity:
            self.severity_combo.setCurrentText(severity)

    def _enforce_text_limit(self, editor: QPlainTextEdit) -> None:
        text = editor.toPlainText()
        if len(text) <= MANUAL_FINDING_TEXT_LIMIT:
            return
        cursor = editor.textCursor()
        position = min(cursor.position(), MANUAL_FINDING_TEXT_LIMIT)
        editor.blockSignals(True)
        editor.setPlainText(text[:MANUAL_FINDING_TEXT_LIMIT])
        cursor = editor.textCursor()
        cursor.setPosition(position)
        editor.setTextCursor(cursor)
        editor.blockSignals(False)

    def accept(self) -> None:
        super().accept()

    def _load_finding(self, finding: dict[str, Any]) -> None:
        self._loading_finding = True
        try:
            self.title_edit.setText(str(finding.get("title") or ""))
            severity = str(finding.get("severity") or "info").strip().lower()
            if severity in {"critical", "high", "medium", "low", "info"}:
                self.severity_combo.setCurrentText(severity)
            self.root_cause_combo.setCurrentText(str(finding.get("root_cause") or ""))
            self.report_tag_combo.setCurrentText(str(finding.get("report_tag") or ""))
            self.cve_edit.setText(str(finding.get("cve") or self._first_cve_reference(finding)))
            self.affected_assets_edit.setText(self._affected_assets_text(finding))
            self.description_edit.setPlainText(str(finding.get("description") or ""))
            self.details_edit.setPlainText(str(finding.get("details") or ""))
            self.impact_combo.setCurrentText(self._risk_text(finding, "impact", "impact_rating"))
            self.likelihood_combo.setCurrentText(self._risk_text(finding, "likelihood", "likelihood_rating"))
            self.impact_edit.setPlainText(self._narrative_text(finding, "impact", "impact_description"))
            self.likelihood_edit.setPlainText(self._narrative_text(finding, "likelihood", "likelihood_description"))
            self.recommendations_edit.setPlainText(self._recommendations_text(finding))
            self.supporting_evidence_edit.setPlainText(str(finding.get("supporting_evidence") or ""))
        finally:
            self._loading_finding = False

    def _first_cve_reference(self, finding: dict[str, Any]) -> str:
        references = finding.get("references")
        if isinstance(references, list):
            for reference in references:
                value = str(reference).strip()
                if value.upper().startswith("CVE-"):
                    return value
        return ""

    def _affected_assets_text(self, finding: dict[str, Any]) -> str:
        raw_assets = finding.get("affected_assets")
        if isinstance(raw_assets, str):
            return raw_assets
        if isinstance(raw_assets, list):
            return ", ".join(str(item) for item in raw_assets if str(item).strip())
        raw_entities = finding.get("affected_entities")
        values: list[str] = []
        if isinstance(raw_entities, list):
            for entity in raw_entities:
                if not isinstance(entity, dict):
                    if str(entity).strip():
                        values.append(str(entity))
                    continue
                value = (
                    entity.get("label")
                    or entity.get("name")
                    or entity.get("url")
                    or entity.get("host")
                    or entity.get("ip")
                    or entity.get("entity_id")
                )
                if value:
                    values.append(str(value))
        return ", ".join(values)

    def _risk_text(self, finding: dict[str, Any], legacy_key: str, rating_key: str | None = None) -> str:
        for key in (rating_key, legacy_key):
            if not key:
                continue
            value = str(finding.get(key) or "").strip().lower()
            if value in RISK_LEVELS:
                return value
        return ""

    def _narrative_text(self, finding: dict[str, Any], legacy_key: str, narrative_key: str) -> str:
        narrative = str(finding.get(narrative_key) or "").strip()
        if narrative:
            return narrative
        value = str(finding.get(legacy_key) or "")
        return "" if value.strip().lower() in RISK_LEVELS else value

    def _recommendations_text(self, finding: dict[str, Any]) -> str:
        recommendations = finding.get("recommendations")
        if isinstance(recommendations, list):
            return "\n".join(str(item) for item in recommendations if str(item).strip())
        if recommendations:
            return str(recommendations)
        items = finding.get("recommendation_items")
        if isinstance(items, list):
            return "\n".join(str(item) for item in items if str(item).strip())
        return ""

    def build_finding(self, finding_id: str, timestamp: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
        affected_assets = [item.strip() for item in self.affected_assets_edit.text().split(",") if item.strip()]
        recommendations_text = self.recommendations_edit.toPlainText()
        cve = self.cve_edit.text().strip()
        references = [cve] if cve else []
        impact_rating = self._valid_rating_text(self.impact_combo)
        likelihood_rating = self._valid_rating_text(self.likelihood_combo)
        impact_text = self.impact_edit.toPlainText()
        likelihood_text = self.likelihood_edit.toPlainText()
        finding = {
            key: value
            for key, value in dict(existing or {}).items()
            if key not in TRANSIENT_FINDING_FIELDS
        }
        reproduction_steps = str(finding.get("reproduction_steps") or finding.get("reproduce_steps") or "")
        finding.update(
            {
                "finding_id": finding_id,
                "template_id": finding.get("template_id") or "manual",
                "title": self.title_edit.text().strip() or "Manual finding",
                "severity": self.severity_combo.currentText(),
                "category": finding.get("category") or "manual",
                "root_cause": self.root_cause_combo.currentText().strip(),
                "report_tag": self.report_tag_combo.currentText().strip(),
                "cve": cve,
                "description": self.description_edit.toPlainText(),
                "details": self.details_edit.toPlainText(),
                "impact_rating": impact_rating,
                "likelihood_rating": likelihood_rating,
                "impact_description": impact_text,
                "likelihood_description": likelihood_text,
                "impact": impact_text if impact_text.strip() else impact_rating,
                "likelihood": likelihood_text if likelihood_text.strip() else likelihood_rating,
                "recommendations": recommendations_text,
                "recommendation_items": [line.strip() for line in recommendations_text.splitlines() if line.strip()],
                "supporting_evidence": self.supporting_evidence_edit.toPlainText(),
                "reproduction_steps": reproduction_steps,
                "reproduce_steps": reproduction_steps,
                "affected_assets": affected_assets,
                "affected_entities": [{"kind": "asset", "label": item} for item in affected_assets],
                "references": references,
                "first_detected": finding.get("first_detected") or timestamp,
                "last_detected": finding.get("last_detected") or timestamp,
                "updated_at": timestamp,
                "source": finding.get("source") or "manual",
                "status": finding.get("status") or "manual",
            }
        )
        return finding


class OutputTab(QWidget):
    def __init__(
        self,
        save_finding_state: Callable[[str, FindingState], None],
        open_path: Callable[[str], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
        load_manual_findings: Callable[[str], list[dict[str, Any]]] | None = None,
        save_manual_findings: Callable[[str, list[dict[str, Any]]], None] | None = None,
        report_exports_enabled: bool = False,
    ) -> None:
        super().__init__(parent)
        self._persist_finding_state = save_finding_state
        self._open_path = open_path
        self._load_manual_findings = load_manual_findings
        self._save_manual_findings = save_manual_findings
        self._report_exports_enabled = report_exports_enabled
        self._snapshot: RunSnapshot | None = None
        self._finding_states: dict[str, FindingState] = {}
        self._current_finding_id = ""
        self._current_path = ""
        self._preview_path = ""
        self._active_detail_kind = ""
        self._active_detail_identity = ""
        self._active_detail_table: QTableView | None = None
        self._manual_findings_by_run: dict[str, list[dict[str, Any]]] = {}
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
            [
                ("Report", lambda row: "Yes" if row.get("include_in_report") and row.get("report_flag_touched") else ""),
                ("Severity", "effective_severity"),
                ("Title", "title"),
                ("Root Cause", lambda row: row.get("root_cause") or row.get("category") or ""),
                ("First Detected", lambda row: self._finding_timestamp(row, "first_detected")),
                ("Last Detected", lambda row: self._finding_timestamp(row, "last_detected")),
                ("Impact", lambda row: self._risk_level(row, "impact", "impact_rating")),
                ("Likelihood", lambda row: self._risk_level(row, "likelihood", "likelihood_rating")),
                ("Affected Assets", self._format_affected_assets),
            ]
        )

        self.findings_view = self._make_table(self.findings_model, self._finding_selected)
        self.findings_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_view.customContextMenuRequested.connect(self._open_finding_context_menu)
        self.add_finding_button = QPushButton("+")
        self.add_finding_button.setObjectName("scannerStartButton")
        self.add_finding_button.clicked.connect(self._create_finding)
        self.add_finding_button.setToolTip("Create a manual finding.")
        self.add_finding_button.setAccessibleName("Create Finding")
        self.add_finding_button.setMinimumSize(24, 24)
        self.add_finding_button.setMaximumSize(28, 28)
        self.add_finding_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

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
        layout.setSpacing(4)
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(0)
        header.addStretch(1)
        if table is self.findings_view:
            header.addWidget(self.add_finding_button, 0, Qt.AlignRight | Qt.AlignVCenter)
        layout.addLayout(header)
        layout.addWidget(table, 1)
        return surface

    def _make_table(self, model: MappingTableModel, callback: Callable[[QModelIndex], None]) -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setModel(model)
        headings = [str(column[0]).lower() for column in model._columns]
        policies = []
        for heading in headings:
            if heading in {"state", "status", "severity", "workflow", "change", "include", "report", "port", "eta", "elapsed", "forms", "priority", "confidence", "replay", "auto", "impact", "likelihood"}:
                policies.append({"mode": "content", "min": 90, "max": 130})
            elif heading in {"url", "title", "next action", "summary", "snippet", "artifact", "path", "note", "root cause", "affected assets"}:
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

    def report_findings(self) -> list[dict[str, Any]]:
        if self._snapshot is None:
            manual_findings = list(self._manual_findings_by_run.get(self._manual_findings_key(), []))
            return self._merge_finding_state(manual_findings)
        return self._merge_finding_state(self._combined_findings(self._snapshot))

    def set_report_exports_enabled(self, enabled: bool) -> None:
        self._report_exports_enabled = bool(enabled)

    def set_snapshot(self, snapshot: RunSnapshot | None, finding_states: dict[str, FindingState] | None = None) -> None:
        previous_run_id = self._snapshot.run_id if self._snapshot is not None else ""
        next_run_id = snapshot.run_id if snapshot is not None else ""
        run_changed = bool(previous_run_id and next_run_id and previous_run_id != next_run_id)
        self._snapshot = snapshot
        self._finding_states = finding_states or {}
        self._ensure_manual_findings_loaded()
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
            manual_findings = list(self._manual_findings_by_run.get(self._manual_findings_key(), []))
            filtered_findings = self._filter_findings(self._merge_finding_state(manual_findings))
            self.findings_model.set_rows(filtered_findings)
            if not filtered_findings:
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

        findings = self._merge_finding_state(self._combined_findings(snapshot))
        filtered_findings = self._filter_findings(findings)
        self.findings_model.set_rows(filtered_findings)
        if self._active_detail_kind:
            self._restore_active_detail()
        elif not self.detail_text.toPlainText():
            self.detail_text.setPlainText("Select a finding for details.")

    def _merge_finding_state(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for finding in findings:
            if finding.get("_removed"):
                continue
            row = dict(finding)
            state = self._finding_states.get(str(row.get("finding_id") or ""))
            base_severity = str(row.get("severity") or "info").lower()
            row["workflow_status"] = state.status if state else str(row.get("workflow_status") or "needs-validation")
            row["analyst_note"] = state.analyst_note if state else str(row.get("analyst_note") or "")
            row["include_in_report"] = state.include_in_report if state else bool(row.get("include_in_report", True))
            row["report_flag_touched"] = state.report_flag_touched if state else bool(row.get("report_flag_touched", False))
            row["severity_override"] = state.severity_override if state else ""
            row["effective_severity"] = (state.severity_override if state else "") or base_severity
            row["reproduce_steps"] = state.reproduce_steps if state else str(row.get("reproduce_steps") or row.get("reproduction_steps") or "")
            rows.append(row)
        rows.sort(key=lambda row: (SEVERITY_ORDER.get(str(row.get("effective_severity") or "info").lower(), 99), str(row.get("title") or "")))
        return rows

    def _manual_findings_key(self) -> str:
        return self._snapshot.run_id if self._snapshot is not None else "__manual__"

    def _ensure_manual_findings_loaded(self) -> None:
        key = self._manual_findings_key()
        if self._load_manual_findings is None:
            return
        self._manual_findings_by_run[key] = [
            dict(row)
            for row in self._load_manual_findings(key)
            if isinstance(row, dict) and str(row.get("finding_id") or "").strip()
        ]

    def _persist_manual_findings(self, key: str) -> None:
        if self._save_manual_findings is None:
            return
        self._save_manual_findings(key, list(self._manual_findings_by_run.get(key, [])))

    def _upsert_manual_finding(self, key: str, finding: dict[str, Any]) -> None:
        finding_id = str(finding.get("finding_id") or "").strip()
        if not finding_id:
            return
        rows = self._manual_findings_by_run.setdefault(key, [])
        for index, row in enumerate(rows):
            if str(row.get("finding_id") or "") == finding_id:
                rows[index] = dict(finding)
                break
        else:
            rows.append(dict(finding))
        self._persist_manual_findings(key)

    def _update_snapshot_finding(self, finding: dict[str, Any]) -> None:
        if self._snapshot is None:
            return
        finding_id = str(finding.get("finding_id") or "").strip()
        if not finding_id:
            return
        for index, row in enumerate(self._snapshot.findings):
            if str(row.get("finding_id") or "") == finding_id:
                self._snapshot.findings[index] = dict(finding)
                return
        self._snapshot.findings.append(dict(finding))

    def _combined_findings(self, snapshot: RunSnapshot) -> list[dict[str, Any]]:
        anonymous_rows: list[dict[str, Any]] = []
        ordered_ids: list[str] = []
        rows_by_id: dict[str, dict[str, Any]] = {}
        for row in snapshot.findings:
            finding_id = str(row.get("finding_id") or "")
            if finding_id:
                if finding_id not in rows_by_id:
                    ordered_ids.append(finding_id)
                rows_by_id[finding_id] = dict(row)
            else:
                anonymous_rows.append(dict(row))
        for row in self._manual_findings_by_run.get(self._manual_findings_key(), []):
            finding_id = str(row.get("finding_id") or "")
            if not finding_id:
                continue
            if row.get("_removed"):
                if finding_id in rows_by_id:
                    rows_by_id.pop(finding_id, None)
                if finding_id in ordered_ids:
                    ordered_ids.remove(finding_id)
                continue
            if finding_id not in rows_by_id:
                ordered_ids.append(finding_id)
            rows_by_id[finding_id] = dict(row)
        return anonymous_rows + [rows_by_id[finding_id] for finding_id in ordered_ids if finding_id in rows_by_id]

    def _remove_snapshot_finding(self, finding_id: str) -> None:
        if self._snapshot is None:
            return
        self._snapshot.findings = [
            dict(row)
            for row in self._snapshot.findings
            if str(row.get("finding_id") or "") != finding_id
        ]

    def _remove_manual_finding(self, key: str, finding_id: str, *, tombstone: bool) -> None:
        rows = [
            dict(row)
            for row in self._manual_findings_by_run.get(key, [])
            if str(row.get("finding_id") or "") != finding_id
        ]
        if tombstone:
            rows.append(
                {
                    "finding_id": finding_id,
                    "_removed": True,
                    "updated_at": now_iso(),
                }
            )
        if rows:
            self._manual_findings_by_run[key] = rows
        else:
            self._manual_findings_by_run.pop(key, None)
        self._persist_manual_findings(key)

    def _duplicate_finding(self, row: dict[str, Any]) -> None:
        timestamp = now_iso()
        finding_id = self._next_manual_finding_id(timestamp)
        duplicate = {
            key: value
            for key, value in dict(row).items()
            if key not in TRANSIENT_FINDING_FIELDS and key != "_removed"
        }
        duplicate.update(
            {
                "finding_id": finding_id,
                "template_id": "manual",
                "title": f"{str(row.get('title') or 'Manual finding').strip() or 'Manual finding'} (Copy)",
                "first_detected": timestamp,
                "last_detected": timestamp,
                "updated_at": timestamp,
                "source": "manual",
                "status": "manual",
            }
        )
        key = self._manual_findings_key()
        self._upsert_manual_finding(key, duplicate)
        self._update_snapshot_finding(duplicate)
        self._refresh_models()
        self._select_finding_by_id(finding_id)

    def _remove_finding(self, row: dict[str, Any]) -> None:
        finding_id = str(row.get("finding_id") or "").strip()
        if not finding_id:
            return
        key = self._manual_findings_key()
        manual_rows = self._manual_findings_by_run.get(key, [])
        exists_as_manual = any(str(item.get("finding_id") or "") == finding_id for item in manual_rows)
        self._remove_manual_finding(key, finding_id, tombstone=not exists_as_manual)
        self._remove_snapshot_finding(finding_id)
        self._finding_states.pop(finding_id, None)
        self._current_finding_id = ""
        self._clear_active_detail()
        self._reset_finding_editor()
        self._refresh_models()

    def _finding_timestamp(self, row: dict[str, Any], key: str) -> str:
        fallback_keys = (key, "detected_at", "created_at", "updated_at", "timestamp")
        for fallback_key in fallback_keys:
            value = str(row.get(fallback_key) or "").strip()
            if value:
                return value
        return ""

    def _risk_level(self, row: dict[str, Any], key: str, rating_key: str | None = None) -> str:
        value = str(row.get(rating_key or "") or "").strip().lower()
        if value in RISK_LEVELS:
            return value
        value = str(row.get(key) or "").strip().lower()
        if value in RISK_LEVELS:
            return value
        if key == "impact":
            severity = str(row.get("effective_severity") or row.get("severity") or "").strip().lower()
            if severity in {"critical", "high"}:
                return "high"
            if severity == "medium":
                return "medium"
            if severity in {"low", "info"}:
                return "low"
        for level in RISK_LEVELS:
            if level in value:
                return level
        return ""

    def _format_affected_assets(self, row: dict[str, Any]) -> str:
        raw_assets = row.get("affected_assets")
        if isinstance(raw_assets, str):
            return raw_assets
        if isinstance(raw_assets, list):
            return ", ".join(str(item) for item in raw_assets if str(item).strip())
        raw_entities = row.get("affected_entities")
        values: list[str] = []
        if isinstance(raw_entities, list):
            for entity in raw_entities:
                if isinstance(entity, dict):
                    value = (
                        entity.get("label")
                        or entity.get("name")
                        or entity.get("url")
                        or entity.get("host")
                        or entity.get("ip")
                        or entity.get("entity_id")
                    )
                    if value:
                        values.append(str(value))
                elif str(entity).strip():
                    values.append(str(entity))
        return ", ".join(values)

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

    def _create_finding(self) -> None:
        dialog = CreateFindingDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        timestamp = now_iso()
        finding_id = self._next_manual_finding_id(timestamp)
        finding = dialog.build_finding(finding_id, timestamp)
        key = self._manual_findings_key()
        self._upsert_manual_finding(key, finding)
        self._update_snapshot_finding(finding)
        self._refresh_models()
        self._select_finding_by_id(finding_id)

    def _edit_finding(self, row: dict[str, Any]) -> None:
        finding_id = str(row.get("finding_id") or "").strip()
        if not finding_id:
            return
        dialog = CreateFindingDialog(self, row)
        if dialog.exec() != QDialog.Accepted:
            return
        timestamp = now_iso()
        finding = dialog.build_finding(finding_id, timestamp, existing=row)
        key = self._manual_findings_key()
        self._upsert_manual_finding(key, finding)
        self._update_snapshot_finding(finding)
        self._refresh_models()
        self._select_finding_by_id(finding_id)

    def _next_manual_finding_id(self, timestamp: str) -> str:
        cleaned = "".join(character for character in timestamp if character.isalnum())
        base = f"manual_{cleaned}"
        existing_ids = {
            str(row.get("finding_id") or "")
            for rows in self._manual_findings_by_run.values()
            for row in rows
        }
        if self._snapshot is not None:
            existing_ids.update(str(row.get("finding_id") or "") for row in self._snapshot.findings)
        if base not in existing_ids:
            return base
        suffix = 2
        while f"{base}_{suffix}" in existing_ids:
            suffix += 1
        return f"{base}_{suffix}"

    def _select_finding_by_id(self, finding_id: str) -> None:
        for row_index in range(self.findings_model.rowCount()):
            index = self.findings_model.index(row_index, 0)
            row = index.data(Qt.UserRole) or {}
            if not isinstance(row, dict) or str(row.get("finding_id") or "") != finding_id:
                continue
            selection = self.findings_view.selectionModel()
            if selection is not None:
                selection.setCurrentIndex(index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            self.findings_view.setCurrentIndex(index)
            self.findings_view.selectRow(row_index)
            self._finding_selected(index)
            return

    def _state_for_finding_id(self, finding_id: str) -> FindingState:
        state = self._finding_states.get(finding_id)
        if state is not None:
            return state
        return FindingState(finding_id=finding_id)

    def _open_finding_context_menu(self, point) -> None:
        index = self.findings_view.indexAt(point)
        if not index.isValid():
            return
        self.findings_view.selectRow(index.row())
        self._finding_selected(index)
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict):
            return
        finding_id = str(row.get("finding_id") or "")
        if not finding_id:
            return
        menu = self._build_finding_context_menu(row)
        menu.exec(self.findings_view.viewport().mapToGlobal(point))

    def _build_finding_context_menu(self, row: dict[str, Any]) -> QMenu:
        finding_id = str(row.get("finding_id") or "")
        menu = QMenu(self.findings_view)
        edit_action = menu.addAction("Edit Finding")
        edit_action.triggered.connect(lambda _checked=False, selected=row: self._edit_finding(dict(selected)))
        duplicate_action = menu.addAction("Duplicate finding")
        duplicate_action.triggered.connect(lambda _checked=False, selected=row: self._duplicate_finding(dict(selected)))
        remove_action = menu.addAction("Remove Finding")
        remove_action.triggered.connect(lambda _checked=False, selected=row: self._remove_finding(dict(selected)))
        menu.addSeparator()
        if self._report_exports_enabled:
            action = menu.addAction("Include In Reports Exports")
            action.setCheckable(True)
            action.setChecked(bool(row.get("include_in_report")) and bool(row.get("report_flag_touched")))
            action.triggered.connect(lambda checked=False, fid=finding_id: self._toggle_report_finding(fid, checked))
        return menu

    def _toggle_report_finding(self, finding_id: str, enabled: bool) -> None:
        state = self._state_for_finding_id(finding_id)
        state.include_in_report = bool(enabled)
        state.report_flag_touched = True
        state.updated_at = now_iso()
        self._finding_states[finding_id] = state
        if self._snapshot is not None:
            self._persist_finding_state(self._snapshot.run_id, state)
        self._refresh_models()
        self._select_finding_by_id(finding_id)

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
            report_flag_touched=True,
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
