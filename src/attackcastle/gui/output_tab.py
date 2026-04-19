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

from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
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
    build_inspector_panel,
    build_table_section,
    configure_scroll_surface,
    ensure_table_defaults,
    format_progress,
    is_previewable_image,
    set_tooltip,
    set_tooltips,
    style_button,
    summarize_target_input,
    title_case_label,
)
from attackcastle.gui.models import FindingState, RunSnapshot


class OutputTab(QWidget):
    def __init__(
        self,
        resolve_snapshot: Callable[[str], RunSnapshot | None],
        save_finding_state: Callable[[str, FindingState], None],
        open_path: Callable[[str], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._resolve_snapshot = resolve_snapshot
        self._persist_finding_state = save_finding_state
        self._open_path = open_path
        self._snapshot: RunSnapshot | None = None
        self._compare_snapshot: RunSnapshot | None = None
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

        top_panel = QWidget()
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
        self.search_edit.setPlaceholderText("Search findings, evidence, validation results, or report notes")
        self.search_edit.textChanged.connect(self._refresh_models)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "critical", "high", "medium", "low", "info"])
        self.severity_filter.currentTextChanged.connect(self._refresh_models)
        self.workflow_filter = QComboBox()
        self.workflow_filter.addItems(["All Workflow States", *FINDING_STATUSES])
        self.workflow_filter.currentTextChanged.connect(self._refresh_models)
        self.diff_filter = QComboBox()
        self.diff_filter.addItems(["All Items", "New Since Compare"])
        self.diff_filter.currentTextChanged.connect(self._refresh_models)
        self.compare_combo = QComboBox()
        self.compare_combo.currentIndexChanged.connect(self._compare_changed)
        self.filter_controls: list[tuple[QLabel, QWidget]] = [
            (QLabel("Search"), self.search_edit),
            (QLabel("Severity"), self.severity_filter),
            (QLabel("Workflow"), self.workflow_filter),
            (QLabel("Diff"), self.diff_filter),
            (QLabel("Compare"), self.compare_combo),
        ]
        set_tooltips(
            (
                (self.search_edit, "Search across findings, validation records, evidence, and report staging details."),
                (self.severity_filter, "Filter findings and related tables by severity."),
                (self.workflow_filter, "Filter findings by workflow state."),
                (self.diff_filter, "Limit results to changes that appeared since the selected comparison run."),
                (self.compare_combo, "Choose another run to compare against the current selection."),
            )
        )
        filter_layout.addLayout(self.filter_grid)
        top_layout.addWidget(filter_panel)

        self.assets_model = MappingTableModel(
            [("Change", "change"), ("Kind", "kind"), ("Name", "name"), ("IP", lambda row: row.get("ip") or ""), ("Aliases", lambda row: ", ".join(row.get("aliases") or []))]
        )
        self.services_model = MappingTableModel(
            [("Change", "change"), ("Asset", "asset_id"), ("Port", "port"), ("Protocol", "protocol"), ("State", "state"), ("Name", lambda row: row.get("name") or "")]
        )
        self.findings_model = MappingTableModel(
            [("Change", "change"), ("Severity", "effective_severity"), ("Workflow", "workflow_status"), ("Report", lambda row: "Yes" if row.get("include_in_report") else "No"), ("Title", "title"), ("Category", "category")]
        )
        self.web_apps_model = MappingTableModel(
            [("Change", "change"), ("URL", "url"), ("Status", lambda row: row.get("status_code") or ""), ("Title", lambda row: row.get("title") or ""), ("Forms", lambda row: row.get("forms_count") or 0)]
        )
        self.endpoints_model = MappingTableModel(
            [("Kind", "kind"), ("Method", lambda row: row.get("method") or ""), ("URL", "url"), ("Tags", lambda row: ", ".join(row.get("tags") or []))]
        )
        self.parameters_model = MappingTableModel(
            [("Name", "name"), ("Location", "location"), ("Sensitive", lambda row: "Yes" if row.get("sensitive") else "No"), ("Endpoint", lambda row: row.get("endpoint_id") or "")]
        )
        self.forms_model = MappingTableModel(
            [("Action", "action_url"), ("Method", "method"), ("Fields", lambda row: ", ".join(row.get("field_names") or [])), ("Password", lambda row: "Yes" if row.get("has_password") else "No")]
        )
        self.login_surfaces_model = MappingTableModel(
            [("URL", "url"), ("Reasons", lambda row: ", ".join(row.get("reasons") or [])), ("Username Fields", lambda row: ", ".join(row.get("username_fields") or [])), ("Password Fields", lambda row: ", ".join(row.get("password_fields") or []))]
        )
        self.technologies_model = MappingTableModel(
            [("Name", "name"), ("Version", lambda row: row.get("version") or ""), ("Category", lambda row: row.get("category") or ""), ("Source", lambda row: row.get("source_tool") or "")]
        )
        self.site_map_model = MappingTableModel(
            [("Change", "change"), ("Source", "source"), ("URL", "url"), ("Entity", "entity_id")]
        )
        self.hypotheses_model = MappingTableModel(
            [("Exploit Class", "exploit_class"), ("Status", "status"), ("Priority", "priority_score"), ("Title", "title")]
        )
        self.surface_signals_model = MappingTableModel(
            [("Signal", "signal_type"), ("Confidence", "confidence"), ("Summary", "summary"), ("Target", lambda row: row.get("entity_id") or row.get("parameter_name") or "")]
        )
        self.attack_paths_model = MappingTableModel(
            [("Priority", "priority_score"), ("Status", "status"), ("Playbook", "playbook_key"), ("Wave", "wave"), ("Next Action", "next_action")]
        )
        self.investigation_steps_model = MappingTableModel(
            [("Status", "status"), ("Step", "step_key"), ("Auto", lambda row: "Yes" if row.get("auto_runnable") else "No"), ("Goal", "title")]
        )
        self.validation_tasks_model = MappingTableModel(
            [("Status", "status"), ("Approval", "approval_class"), ("Task", "title"), ("Next Action", "next_action")]
        )
        self.replay_requests_model = MappingTableModel(
            [("Method", "method"), ("URL", "url"), ("Tags", lambda row: ", ".join(row.get("tags") or [])), ("Replay", lambda row: "Yes" if row.get("replay_enabled") else "No")]
        )
        self.validation_results_model = MappingTableModel(
            [("Status", "status"), ("Severity", "severity_hint"), ("Family", "family"), ("Title", "title")]
        )
        self.coverage_gaps_model = MappingTableModel(
            [("Source", "source"), ("Title", "title"), ("Reason", "reason"), ("URL", lambda row: row.get("url") or "")]
        )
        self.evidence_model = MappingTableModel(
            [("Kind", "kind"), ("Source", "source_tool"), ("Snippet", lambda row: row.get("snippet", "")[:120]), ("Artifact", lambda row: row.get("artifact_path") or "")]
        )
        self.artifacts_model = MappingTableModel(
            [("Kind", "kind"), ("Tool", "source_tool"), ("Path", "path"), ("Caption", "caption")]
        )
        self.screenshots_model = MappingTableModel(
            [("Tool", "source_tool"), ("Caption", "caption"), ("Path", "path")]
        )
        self.report_model = MappingTableModel(
            [("Include", lambda row: "Yes" if row.get("include_in_report") else "No"), ("Severity", "effective_severity"), ("Workflow", "workflow_status"), ("Title", "title"), ("Note", lambda row: row.get("analyst_note") or "")]
        )

        self.assets_view = self._make_table(self.assets_model, self._asset_selected)
        self.services_view = self._make_table(self.services_model, self._service_selected)
        self.findings_view = self._make_table(self.findings_model, self._finding_selected)
        self.web_apps_view = self._make_table(self.web_apps_model, self._web_app_selected)
        self.endpoints_view = self._make_table(self.endpoints_model, self._endpoint_selected)
        self.parameters_view = self._make_table(self.parameters_model, self._parameter_selected)
        self.forms_view = self._make_table(self.forms_model, self._form_selected)
        self.login_surfaces_view = self._make_table(self.login_surfaces_model, self._login_surface_selected)
        self.technologies_view = self._make_table(self.technologies_model, self._technology_selected)
        self.site_map_view = self._make_table(self.site_map_model, self._site_map_selected)
        self.hypotheses_view = self._make_table(self.hypotheses_model, self._hypothesis_selected)
        self.surface_signals_view = self._make_table(self.surface_signals_model, self._surface_signal_selected)
        self.attack_paths_view = self._make_table(self.attack_paths_model, self._attack_path_selected)
        self.investigation_steps_view = self._make_table(self.investigation_steps_model, self._investigation_step_selected)
        self.validation_tasks_view = self._make_table(self.validation_tasks_model, self._validation_task_selected)
        self.replay_requests_view = self._make_table(self.replay_requests_model, self._replay_request_selected)
        self.validation_results_view = self._make_table(self.validation_results_model, self._validation_result_selected)
        self.coverage_gaps_view = self._make_table(self.coverage_gaps_model, self._coverage_gap_selected)
        self.evidence_view = self._make_table(self.evidence_model, self._evidence_selected)
        self.artifacts_view = self._make_table(self.artifacts_model, self._artifact_selected)
        self.screenshots_view = self._make_table(self.screenshots_model, self._screenshot_selected)
        self.report_view = self._make_table(self.report_model, self._finding_selected)

        self.overview_text = configure_scroll_surface(QTextEdit())
        self.overview_text.setObjectName("richBrief")
        self.overview_text.setReadOnly(True)
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
                (self.open_path_button, "Open the currently selected artifact or evidence file."),
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
        self.primary_tabs = QTabWidget()
        self.primary_tabs.setObjectName("subTabs")
        self.primary_tabs.setDocumentMode(True)
        self.primary_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(PAGE_SECTION_SPACING)
        self.findings_tabs = QTabWidget()
        self.findings_tabs.setObjectName("subTabs")
        self.findings_tabs.setDocumentMode(True)
        self.findings_tabs.addTab(self._table_surface("Findings Queue", self.findings_view), "Findings")
        self.findings_tabs.addTab(self._table_surface("Report Staging", self.report_view), "Report")
        self.findings_tabs.addTab(self._section("Overview", self.overview_text), "Overview")
        findings_layout.addWidget(self.findings_tabs)
        self.primary_tabs.addTab(findings_page, "Findings")

        validation_page = QWidget()
        validation_layout = QVBoxLayout(validation_page)
        validation_layout.setContentsMargins(0, 0, 0, 0)
        self.validation_tabs = QTabWidget()
        self.validation_tabs.setObjectName("subTabs")
        self.validation_tabs.setDocumentMode(True)
        self.validation_tabs.addTab(self._table_surface("Coverage Lanes", self.attack_paths_view), "Coverage Lanes")
        self.validation_tabs.addTab(self._table_surface("Next Best Actions", self.investigation_steps_view), "Actions")
        self.validation_tabs.addTab(self._table_surface("Validation Queue", self.validation_tasks_view), "Queue")
        self.validation_tabs.addTab(self._table_surface("Surface Signals", self.surface_signals_view), "Signals")
        self.validation_tabs.addTab(self._table_surface("Hypotheses", self.hypotheses_view), "Hypotheses")
        self.validation_tabs.addTab(self._table_surface("Replay Requests", self.replay_requests_view), "Replay")
        self.validation_tabs.addTab(self._table_surface("Validation Results", self.validation_results_view), "Results")
        self.validation_tabs.addTab(self._table_surface("Coverage Gaps", self.coverage_gaps_view), "Coverage")
        validation_layout.addWidget(self.validation_tabs)
        self.primary_tabs.addTab(validation_page, "Validation")

        evidence_page = QWidget()
        evidence_layout = QVBoxLayout(evidence_page)
        evidence_layout.setContentsMargins(0, 0, 0, 0)
        self.evidence_tabs = QTabWidget()
        self.evidence_tabs.setObjectName("subTabs")
        self.evidence_tabs.setDocumentMode(True)
        self.evidence_tabs.addTab(self._table_surface("Evidence", self.evidence_view), "Evidence")
        self.evidence_tabs.addTab(self._table_surface("Artifacts", self.artifacts_view), "Artifacts")
        self.evidence_tabs.addTab(self._table_surface("Screenshots", self.screenshots_view), "Screenshots")
        evidence_layout.addWidget(self.evidence_tabs)
        self.primary_tabs.addTab(evidence_page, "Evidence")
        self.primary_tabs.setTabToolTip(0, "Review findings, report staging, and the run overview.")
        self.primary_tabs.setTabToolTip(1, "Inspect validation queues, signals, and coverage decisions.")
        self.primary_tabs.setTabToolTip(2, "Inspect evidence, artifacts, and screenshot captures.")
        main_split.addWidget(self.primary_tabs)

        self.inspector_tabs = QTabWidget()
        self.inspector_tabs.setObjectName("subTabs")
        self.inspector_tabs.setDocumentMode(True)
        self.inspector_tabs.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.inspector_tabs.setCornerWidget(self.inspector_summary, Qt.TopRightCorner)
        self.inspector_tabs.addTab(self._section("Details", self.detail_text), "Details")
        self.inspector_tabs.addTab(self._section("Raw", self.raw_text), "Raw")
        workflow_widget = QWidget()
        workflow_layout = QFormLayout(workflow_widget)
        apply_form_layout_defaults(workflow_layout)
        workflow_layout.addRow("Status", self.finding_status_combo)
        workflow_layout.addRow("Severity Override", self.finding_severity_combo)
        workflow_layout.addRow("Report", self.finding_include_checkbox)
        workflow_layout.addRow("Analyst Note", self.finding_note_edit)
        workflow_layout.addRow("Reproduction Steps", self.finding_repro_edit)
        workflow_layout.addRow("", self.finding_save_button)
        self.inspector_tabs.addTab(self._section("Workflow", workflow_widget), "Workflow")
        preview_widget = QWidget()
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
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget)
        return section

    def _table_surface(self, title: str, table: QTableView) -> QWidget:
        surface = QWidget()
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
        self.primary_tabs.setCurrentIndex(0)
        self.findings_tabs.setCurrentIndex(0)
        self.findings_view.setFocus()

    def open_current_artifact(self) -> None:
        if self._current_path:
            self._open_path(self._current_path)

    def has_current_artifact(self) -> bool:
        return bool(self._current_path)

    def set_compare_options(self, snapshots: list[RunSnapshot], current_run_id: str | None) -> None:
        self.compare_combo.blockSignals(True)
        self.compare_combo.clear()
        self.compare_combo.addItem("No comparison", "")
        for snapshot in snapshots:
            if snapshot.run_id == current_run_id:
                continue
            self.compare_combo.addItem(f"{snapshot.scan_name} ({snapshot.workspace_name or 'Unassigned'})", snapshot.run_id)
        self.compare_combo.blockSignals(False)

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
            for model in (
                self.assets_model,
                self.web_apps_model,
                self.endpoints_model,
                self.parameters_model,
                self.forms_model,
                self.login_surfaces_model,
                self.technologies_model,
                self.site_map_model,
                self.surface_signals_model,
                self.attack_paths_model,
                self.investigation_steps_model,
                self.hypotheses_model,
                self.validation_tasks_model,
                self.replay_requests_model,
                self.validation_results_model,
                self.coverage_gaps_model,
                self.evidence_model,
                self.artifacts_model,
                self.screenshots_model,
                self.report_model,
                self.services_model,
                self.findings_model,
            ):
                model.set_rows([])
            self.overview_text.clear()
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
        assets = self._mark_changes(snapshot.assets, self._compare_snapshot.assets if self._compare_snapshot else [], lambda row: f"{row.get('kind')}|{row.get('name')}|{row.get('ip')}")
        services = self._mark_changes(snapshot.services, self._compare_snapshot.services if self._compare_snapshot else [], lambda row: f"{row.get('asset_id')}|{row.get('port')}|{row.get('protocol')}")
        web_apps = self._mark_changes(snapshot.web_apps, self._compare_snapshot.web_apps if self._compare_snapshot else [], lambda row: str(row.get("url") or ""))
        technologies = self._mark_changes(snapshot.technologies, self._compare_snapshot.technologies if self._compare_snapshot else [], lambda row: f"{row.get('name')}|{row.get('version')}|{row.get('category')}")
        site_map = self._mark_changes(snapshot.site_map, self._compare_snapshot.site_map if self._compare_snapshot else [], lambda row: f"{row.get('source')}|{row.get('url')}")
        filtered_assets = self._filter_rows(assets)
        filtered_services = self._filter_rows(services)
        filtered_web_apps = self._filter_rows(web_apps)
        filtered_endpoints = self._filter_rows(snapshot.endpoints)
        filtered_parameters = self._filter_rows(snapshot.parameters)
        filtered_forms = self._filter_rows(snapshot.forms)
        filtered_login_surfaces = self._filter_rows(snapshot.login_surfaces)
        filtered_technologies = self._filter_rows(technologies)
        filtered_site_map = self._filter_rows(site_map)
        filtered_surface_signals = self._filter_rows(snapshot.surface_signals)
        filtered_attack_paths = self._filter_rows(snapshot.attack_paths)
        filtered_investigation_steps = self._filter_rows(snapshot.investigation_steps)
        filtered_hypotheses = self._filter_rows(snapshot.hypotheses)
        filtered_validation_tasks = self._filter_rows(snapshot.validation_tasks)
        filtered_replay_requests = self._filter_rows(snapshot.replay_requests)
        filtered_validation_results = self._filter_rows(snapshot.validation_results)
        filtered_coverage_gaps = self._filter_rows(snapshot.coverage_gaps)
        filtered_evidence = self._filter_rows(snapshot.evidence)
        filtered_artifacts = self._filter_rows(snapshot.artifacts)
        filtered_screenshots = self._filter_rows(snapshot.screenshots)
        execution_issues = list(snapshot.execution_issues or [])
        issue_summary = dict(snapshot.execution_issues_summary or {})
        if not execution_issues and (
            snapshot.errors
            or snapshot.warnings
            or snapshot.tasks
            or snapshot.tool_executions
            or snapshot.state in {"failed", "cancelled"}
        ):
            execution_issues = build_execution_issues(snapshot)
            issue_summary = summarize_execution_issues(snapshot, execution_issues)
        elif not issue_summary:
            issue_summary = summarize_execution_issues(snapshot, execution_issues)
        filtered_findings = self._filter_findings(findings)
        report_rows = [item for item in filtered_findings if item.get("include_in_report")]
        critical_high = sum(1 for item in findings if str(item.get("effective_severity", "")).lower() in {"critical", "high"})
        issue_count = int(issue_summary.get("total_count", 0) or 0)
        completeness_status = str(issue_summary.get("completeness_status") or getattr(snapshot, "completeness_status", "healthy"))
        self.assets_model.set_rows(filtered_assets)
        self.web_apps_model.set_rows(filtered_web_apps)
        self.endpoints_model.set_rows(filtered_endpoints)
        self.parameters_model.set_rows(filtered_parameters)
        self.forms_model.set_rows(filtered_forms)
        self.login_surfaces_model.set_rows(filtered_login_surfaces)
        self.technologies_model.set_rows(filtered_technologies)
        self.site_map_model.set_rows(filtered_site_map)
        self.surface_signals_model.set_rows(filtered_surface_signals)
        self.attack_paths_model.set_rows(filtered_attack_paths)
        self.investigation_steps_model.set_rows(filtered_investigation_steps)
        self.hypotheses_model.set_rows(filtered_hypotheses)
        self.validation_tasks_model.set_rows(filtered_validation_tasks)
        self.replay_requests_model.set_rows(filtered_replay_requests)
        self.validation_results_model.set_rows(filtered_validation_results)
        self.coverage_gaps_model.set_rows(filtered_coverage_gaps)
        self.evidence_model.set_rows(filtered_evidence)
        self.artifacts_model.set_rows(filtered_artifacts)
        self.screenshots_model.set_rows(filtered_screenshots)
        self.services_model.set_rows(filtered_services)
        self.findings_model.set_rows(filtered_findings)
        self.report_model.set_rows(report_rows)
        self.overview_text.setHtml(
            f"<h3>Operator Overview</h3>"
            f"<p><b>Workspace:</b> {snapshot.workspace_name or 'Unassigned'}<br>"
            f"<b>Target Summary:</b> {summarize_target_input(snapshot.target_input)}<br>"
            f"<b>Profile:</b> {snapshot.profile_name or 'Unknown'}<br>"
            f"<b>Current Task:</b> {snapshot.current_task}<br>"
            f"<b>Task Coverage:</b> {format_progress(snapshot.completed_tasks, snapshot.total_tasks)}</p>"
            f"<p><b>Attack Surface:</b> {len(snapshot.assets)} assets, {len(snapshot.services)} services, {len(snapshot.web_apps)} web apps, {len(snapshot.endpoints)} endpoints, {len(snapshot.parameters)} parameters, {len(snapshot.replay_requests)} replay requests, and {len(snapshot.site_map)} mapped routes.</p>"
            f"<p><b>Coverage Queue:</b> {len(snapshot.attack_paths)} coverage lanes, {len(snapshot.investigation_steps)} next actions, {len(snapshot.validation_tasks)} validation tasks, {len(snapshot.hypotheses)} hypotheses, {len(snapshot.validation_results)} recorded validation results, and {len(snapshot.coverage_gaps)} explicit coverage gaps.</p>"
            f"<p><b>Risk Picture:</b> {critical_high} critical/high findings and {len(report_rows)} report-ready findings are in active triage.</p>"
            f"<p><b>Execution Health:</b> {title_case_label(completeness_status)} with {issue_count} consolidated issue(s). Review Scanner &gt; Issues for impact and next actions.</p>"
        )
        if self._active_detail_kind:
            self._restore_active_detail()
        elif not self.detail_text.toPlainText():
            self.detail_text.setPlainText("Select a finding, validation item, or artifact for details.")

    def _compare_changed(self, _index: int) -> None:
        run_id = str(self.compare_combo.currentData() or "")
        self._compare_snapshot = self._resolve_snapshot(run_id) if run_id else None
        self._refresh_models()

    def _mark_changes(self, current: list[dict[str, Any]], compare: list[dict[str, Any]], signature: Callable[[dict[str, Any]], str]) -> list[dict[str, Any]]:
        compare_keys = {signature(item) for item in compare if signature(item)}
        rows: list[dict[str, Any]] = []
        for item in current:
            row = dict(item)
            row["change"] = "existing" if compare_keys and signature(row) in compare_keys else "new" if compare_keys else "live"
            rows.append(row)
        return rows

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
        diff_only = self.diff_filter.currentText() == "New Since Compare"
        result: list[dict[str, Any]] = []
        for row in rows:
            if diff_only and row.get("change") != "new":
                continue
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

    def _asset_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict) or self._snapshot is None:
            return
        asset_id = str(row.get("asset_id") or "")
        payload = {
            "asset": row,
            "related_services": [item for item in self._snapshot.services if str(item.get("asset_id") or "") == asset_id],
            "related_web_apps": [item for item in self._snapshot.web_apps if str(item.get("asset_id") or "") == asset_id],
        }
        self._show_details(payload, kind="asset", table=self.assets_view, identity_row=row)

    def _service_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="service", table=self.services_view)

    def _finding_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(0)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="finding", table=self.findings_view)
        self._current_finding_id = str(row.get("finding_id") or "")
        self.finding_status_combo.setCurrentText(str(row.get("workflow_status") or "needs-validation"))
        self.finding_severity_combo.setCurrentText(str(row.get("severity_override") or ""))
        self.finding_include_checkbox.setChecked(bool(row.get("include_in_report", True)))
        self.finding_note_edit.setPlainText(str(row.get("analyst_note") or ""))
        self.finding_repro_edit.setPlainText(str(row.get("reproduce_steps") or ""))

    def _web_app_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="web_app", table=self.web_apps_view)

    def _endpoint_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="endpoint", table=self.endpoints_view)

    def _parameter_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="parameter", table=self.parameters_view)

    def _form_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="form", table=self.forms_view)

    def _login_surface_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="login_surface", table=self.login_surfaces_view)

    def _technology_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="technology", table=self.technologies_view)

    def _site_map_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="site_map", table=self.site_map_view)

    def _evidence_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="evidence", table=self.evidence_view)
        path = str(row.get("artifact_path") or "")
        self._set_current_path(path)
        self._preview_if_possible(path)

    def _artifact_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="artifact", table=self.artifacts_view)
        path = str(row.get("path") or "")
        self._set_current_path(path)
        self._preview_if_possible(path)

    def _screenshot_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="screenshot", table=self.screenshots_view)
        path = str(row.get("path") or "")
        self._set_current_path(path)
        self._preview_path = path
        self._render_preview()
        self.inspector_tabs.setCurrentIndex(self.preview_tab_index)

    def _hypothesis_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="hypothesis", table=self.hypotheses_view)

    def _surface_signal_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="surface_signal", table=self.surface_signals_view)

    def _attack_path_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="attack_path", table=self.attack_paths_view)

    def _investigation_step_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="investigation_step", table=self.investigation_steps_view)

    def _validation_task_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="validation_task", table=self.validation_tasks_view)

    def _replay_request_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="replay_request", table=self.replay_requests_view)

    def _validation_result_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="validation_result", table=self.validation_results_view)

    def _coverage_gap_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row, kind="coverage_gap", table=self.coverage_gaps_view)

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
        primary_id_fields = {
            "asset": "asset_id",
            "service": "service_id",
            "finding": "finding_id",
            "web_app": "webapp_id",
            "endpoint": "endpoint_id",
            "parameter": "parameter_id",
            "form": "form_id",
            "login_surface": "login_surface_id",
            "technology": "tech_id",
            "hypothesis": "hypothesis_id",
            "surface_signal": "signal_id",
            "attack_path": "path_id",
            "investigation_step": "step_id",
            "validation_task": "task_id",
            "replay_request": "request_id",
            "validation_result": "result_id",
            "coverage_gap": "gap_id",
            "evidence": "evidence_id",
            "artifact": "artifact_id",
            "screenshot": "screenshot_id",
        }
        primary_id = row.get(primary_id_fields.get(kind, ""))
        if primary_id not in (None, ""):
            return f"{kind}:{primary_id}"
        id_fields = {
            "asset": ("asset_id", "kind", "name", "ip"),
            "service": ("service_id", "asset_id", "port", "protocol", "name"),
            "finding": ("finding_id", "title", "category"),
            "web_app": ("webapp_id", "url"),
            "endpoint": ("endpoint_id", "method", "url"),
            "parameter": ("parameter_id", "endpoint_id", "name", "location"),
            "form": ("form_id", "method", "action_url"),
            "login_surface": ("login_surface_id", "url"),
            "technology": ("tech_id", "asset_id", "webapp_id", "name", "version"),
            "site_map": ("source", "url", "entity_id"),
            "hypothesis": ("hypothesis_id", "title", "exploit_class"),
            "surface_signal": ("signal_id", "signal_type", "summary", "entity_id", "parameter_name"),
            "attack_path": ("path_id", "playbook_key", "wave", "next_action"),
            "investigation_step": ("step_id", "step_key", "title"),
            "validation_task": ("task_id", "title", "approval_class"),
            "replay_request": ("request_id", "method", "url"),
            "validation_result": ("result_id", "title", "family"),
            "coverage_gap": ("gap_id", "title", "url", "source"),
            "evidence": ("evidence_id", "artifact_path", "source_tool", "snippet"),
            "artifact": ("artifact_id", "path", "kind", "source_tool"),
            "screenshot": ("screenshot_id", "path", "caption", "source_tool"),
        }
        values = [str(row.get(field) or "") for field in id_fields.get(kind, ())]
        identity = "|".join(values).strip("|")
        return identity or json.dumps(row, sort_keys=True, default=str)

    def _detail_sources(self) -> dict[str, tuple[QTableView, MappingTableModel]]:
        return {
            "asset": (self.assets_view, self.assets_model),
            "service": (self.services_view, self.services_model),
            "finding": (self.findings_view, self.findings_model),
            "web_app": (self.web_apps_view, self.web_apps_model),
            "endpoint": (self.endpoints_view, self.endpoints_model),
            "parameter": (self.parameters_view, self.parameters_model),
            "form": (self.forms_view, self.forms_model),
            "login_surface": (self.login_surfaces_view, self.login_surfaces_model),
            "technology": (self.technologies_view, self.technologies_model),
            "site_map": (self.site_map_view, self.site_map_model),
            "hypothesis": (self.hypotheses_view, self.hypotheses_model),
            "surface_signal": (self.surface_signals_view, self.surface_signals_model),
            "attack_path": (self.attack_paths_view, self.attack_paths_model),
            "investigation_step": (self.investigation_steps_view, self.investigation_steps_model),
            "validation_task": (self.validation_tasks_view, self.validation_tasks_model),
            "replay_request": (self.replay_requests_view, self.replay_requests_model),
            "validation_result": (self.validation_results_view, self.validation_results_model),
            "coverage_gap": (self.coverage_gaps_view, self.coverage_gaps_model),
            "evidence": (self.evidence_view, self.evidence_model),
            "artifact": (self.artifacts_view, self.artifacts_model),
            "screenshot": (self.screenshots_view, self.screenshots_model),
        }

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
            if self._active_detail_kind == "asset":
                asset_id = str(row.get("asset_id") or "")
                payload = {
                    "asset": row,
                    "related_services": [item for item in self._snapshot.services if str(item.get("asset_id") or "") == asset_id],
                    "related_web_apps": [item for item in self._snapshot.web_apps if str(item.get("asset_id") or "") == asset_id],
                }
                self._show_details(payload, kind="asset", table=table, identity_row=row)
            else:
                self._show_details(row, kind=self._active_detail_kind, table=table)
            if self._active_detail_kind in {"evidence", "artifact", "screenshot"}:
                path = str(row.get("artifact_path") or row.get("path") or "")
                self._set_current_path(path)
                self._preview_path = path if self._active_detail_kind == "screenshot" or is_previewable_image(path) else ""
                self._render_preview()
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

    def _preview_if_possible(self, path: str) -> None:
        if not path or not is_previewable_image(path):
            self._preview_path = ""
            self._render_preview()
            return
        self._preview_path = path
        self._render_preview()
        self.inspector_tabs.setCurrentIndex(self.preview_tab_index)

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
