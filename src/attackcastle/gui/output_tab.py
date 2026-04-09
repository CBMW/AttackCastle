from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QModelIndex, Qt
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
    QProgressBar,
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
    PersistentSplitterController,
    SEVERITY_ORDER,
    SummaryCard,
    apply_responsive_splitter,
    configure_scroll_surface,
    ensure_table_defaults,
    format_duration,
    format_progress,
    is_previewable_image,
    progress_percent,
    refresh_widget_style,
    set_tooltip,
    set_tooltips,
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
        self._quick_filter = "all"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        hero = QFrame()
        hero.setObjectName("heroPanel")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 18, 18, 18)
        hero_layout.setSpacing(10)
        self.output_title = QLabel("Findings Workspace")
        self.output_title.setObjectName("heroTitle")
        self.summary_label = QLabel("Select a run from Workspace or Scanner to inspect findings, validation queues, and evidence.")
        self.summary_label.setObjectName("outputSummary")
        self.summary_label.setWordWrap(True)
        self.progress_label = QLabel("No run selected")
        self.progress_label.setObjectName("headerMeta")
        self.progress_label.setWordWrap(True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setValue(0)
        hero_layout.addWidget(self.output_title)
        hero_layout.addWidget(self.summary_label)
        hero_layout.addWidget(self.progress_label)
        hero_layout.addWidget(self.progress_bar)
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(16)
        top_layout.addWidget(hero)

        cards = QGridLayout()
        cards.setHorizontalSpacing(12)
        cards.setVerticalSpacing(12)
        self.summary_cards_grid = cards
        self.findings_card = SummaryCard("Findings")
        self.critical_card = SummaryCard("Critical + High")
        self.coverage_card = SummaryCard("Coverage")
        self.health_card = SummaryCard("Execution Health")
        self.assets_card = SummaryCard("Assets")
        self.evidence_card = SummaryCard("Evidence")
        self.summary_cards = (
            self.findings_card,
            self.critical_card,
            self.coverage_card,
            self.health_card,
            self.assets_card,
            self.evidence_card,
        )
        for idx, card in enumerate(self.summary_cards):
            cards.addWidget(card, idx // 3, idx % 3)
        top_layout.addLayout(cards)

        filter_panel = QFrame()
        filter_panel.setObjectName("toolbarPanel")
        filter_layout = QVBoxLayout(filter_panel)
        filter_layout.setContentsMargins(16, 16, 16, 16)
        filter_layout.setSpacing(12)
        self.filter_grid = QGridLayout()
        self.filter_grid.setHorizontalSpacing(10)
        self.filter_grid.setVerticalSpacing(10)
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
        self.filter_status_label = QLabel("Live inventory will appear here once a run is selected.")
        self.filter_status_label.setObjectName("helperText")
        self.filter_status_label.setWordWrap(True)
        filter_layout.addWidget(self.filter_status_label)
        self.attention_banner = QLabel("Select a run to focus findings, health signals, and validation changes.")
        self.attention_banner.setObjectName("attentionBanner")
        self.attention_banner.setProperty("tone", "neutral")
        self.attention_banner.setWordWrap(True)
        filter_layout.addWidget(self.attention_banner)

        quick_filter_row = FlowButtonRow()
        self.quick_filter_buttons: dict[str, QPushButton] = {}
        focus_label = QLabel("Focus")
        focus_label.setObjectName("helperText")
        quick_filter_row.addWidget(focus_label)
        for key, label in (
            ("all", "All Activity"),
            ("critical-high", "Critical / High"),
            ("needs-validation", "Needs Validation"),
            ("report-ready", "Report Ready"),
            ("new", "New Since Compare"),
        ):
            button = QPushButton(label)
            button.setCheckable(True)
            button.setProperty("variant", "chip")
            button.clicked.connect(lambda checked=False, selected=key: self._set_quick_filter(selected))
            set_tooltip(button, f"Focus the workspace on {label.lower()} items.")
            self.quick_filter_buttons[key] = button
            quick_filter_row.addWidget(button)
        filter_layout.addWidget(quick_filter_row)
        top_layout.addWidget(filter_panel)
        self.quick_filter_buttons["all"].setChecked(True)

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
        self.inspector_summary.setObjectName("warningBanner")
        self.inspector_summary.setWordWrap(True)
        self.screenshot_preview = QLabel("Screenshot preview")
        self.screenshot_preview.setObjectName("previewSurface")
        self.screenshot_preview.setAlignment(Qt.AlignCenter)
        self.screenshot_preview.setMinimumHeight(160)
        self.preview_meta_label = QLabel("No artifact selected")
        self.preview_meta_label.setObjectName("helperText")
        self.preview_meta_label.setWordWrap(True)
        self.open_path_button = QPushButton("Open File")
        self.open_path_button.clicked.connect(self.open_current_artifact)
        self.open_path_button.setProperty("variant", "secondary")
        self.open_folder_button = QPushButton("Open Folder")
        self.open_folder_button.clicked.connect(self._open_current_folder)
        self.open_folder_button.setProperty("variant", "secondary")

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

        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(12)
        self.findings_tabs = QTabWidget()
        self.findings_tabs.setObjectName("subTabs")
        self.findings_tabs.setDocumentMode(True)
        self.findings_tabs.addTab(self._section("Findings Queue", self.findings_view), "Findings")
        self.findings_tabs.addTab(self._section("Report Staging", self.report_view), "Report")
        self.findings_tabs.addTab(self._section("Overview", self.overview_text), "Overview")
        findings_layout.addWidget(self.findings_tabs)
        self.primary_tabs.addTab(findings_page, "Findings")

        validation_page = QWidget()
        validation_layout = QVBoxLayout(validation_page)
        validation_layout.setContentsMargins(0, 0, 0, 0)
        self.validation_tabs = QTabWidget()
        self.validation_tabs.setObjectName("subTabs")
        self.validation_tabs.setDocumentMode(True)
        self.validation_tabs.addTab(self._section("Coverage Lanes", self.attack_paths_view), "Coverage Lanes")
        self.validation_tabs.addTab(self._section("Next Best Actions", self.investigation_steps_view), "Actions")
        self.validation_tabs.addTab(self._section("Validation Queue", self.validation_tasks_view), "Queue")
        self.validation_tabs.addTab(self._section("Surface Signals", self.surface_signals_view), "Signals")
        self.validation_tabs.addTab(self._section("Hypotheses", self.hypotheses_view), "Hypotheses")
        self.validation_tabs.addTab(self._section("Replay Requests", self.replay_requests_view), "Replay")
        self.validation_tabs.addTab(self._section("Validation Results", self.validation_results_view), "Results")
        self.validation_tabs.addTab(self._section("Coverage Gaps", self.coverage_gaps_view), "Coverage")
        validation_layout.addWidget(self.validation_tabs)
        self.primary_tabs.addTab(validation_page, "Validation")

        evidence_page = QWidget()
        evidence_layout = QVBoxLayout(evidence_page)
        evidence_layout.setContentsMargins(0, 0, 0, 0)
        self.evidence_tabs = QTabWidget()
        self.evidence_tabs.setObjectName("subTabs")
        self.evidence_tabs.setDocumentMode(True)
        self.evidence_tabs.addTab(self._section("Evidence", self.evidence_view), "Evidence")
        self.evidence_tabs.addTab(self._section("Artifacts", self.artifacts_view), "Artifacts")
        self.evidence_tabs.addTab(self._section("Screenshots", self.screenshots_view), "Screenshots")
        evidence_layout.addWidget(self.evidence_tabs)
        self.primary_tabs.addTab(evidence_page, "Evidence")
        self.primary_tabs.setTabToolTip(0, "Review findings, report staging, and the run overview.")
        self.primary_tabs.setTabToolTip(1, "Inspect validation queues, signals, and coverage decisions.")
        self.primary_tabs.setTabToolTip(2, "Inspect evidence, artifacts, and screenshot captures.")
        main_split.addWidget(self.primary_tabs)

        self.inspector_tabs = QTabWidget()
        self.inspector_tabs.setObjectName("subTabs")
        self.inspector_tabs.setDocumentMode(True)
        self.inspector_tabs.setCornerWidget(self.inspector_summary, Qt.TopRightCorner)
        self.inspector_tabs.addTab(self._section("Details", self.detail_text), "Details")
        self.inspector_tabs.addTab(self._section("Raw", self.raw_text), "Raw")
        workflow_widget = QWidget()
        workflow_layout = QFormLayout(workflow_widget)
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
        self.content_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (2, 5))
        self.content_split_controller = PersistentSplitterController(
            self.content_split,
            "findings_content_split",
            layout_loader,
            layout_saver,
            self,
        )
        self.content_split.addWidget(top_panel)
        self.content_split.addWidget(main_split)
        layout.addWidget(self.content_split, 1)
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

    def _make_table(self, model: MappingTableModel, callback: Callable[[QModelIndex], None]) -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setModel(model)
        ensure_table_defaults(table)
        table.clicked.connect(callback)
        set_tooltip(table, "Select a row to inspect more detail in the panel on the right.")
        return table

    def sync_responsive_mode(self, width: int) -> None:
        columns = 3 if width >= 1480 else 2 if width >= 1180 else 1
        self._arrange_cards(self.summary_cards_grid, self.summary_cards, columns)
        self._arrange_filter_controls(width)
        top_height = 360 if width >= 1480 else 400 if width >= 1180 else 460
        self.content_split.setOrientation(Qt.Vertical)
        self.content_split_controller.apply([max(top_height, 260), max(self.height() - top_height, 360)])
        self.main_split.setOrientation(Qt.Horizontal if width >= 1180 else Qt.Vertical)
        if width >= 1180:
            self.main_split_controller.apply([max(int(width * 0.6), 520), max(int(width * 0.4), 360)])
        else:
            self.main_split_controller.apply([max(int(self.height() * 0.6), 320), max(int(self.height() * 0.4), 260)])

    def _arrange_cards(self, grid: QGridLayout, cards: tuple[SummaryCard, ...], columns: int) -> None:
        while grid.count():
            grid.takeAt(0)
        for index, card in enumerate(cards):
            grid.addWidget(card, index // columns, index % columns)

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
        self._snapshot = snapshot
        self._finding_states = finding_states or {}
        self._refresh_models()

    def _set_quick_filter(self, quick_filter: str) -> None:
        self._quick_filter = quick_filter
        for key, button in self.quick_filter_buttons.items():
            button.blockSignals(True)
            button.setChecked(key == quick_filter)
            button.blockSignals(False)
        self._refresh_models()

    def _refresh_models(self) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            self.output_title.setText("Findings Workspace")
            self.summary_label.setText("Select a run from Workspace or Scanner to inspect findings, validation queues, and evidence.")
            self.progress_label.setText("No run selected")
            self.progress_bar.setValue(0)
            for card, hint in (
                (self.findings_card, "Triage queue for the selected run"),
                (self.critical_card, "Escalate confirmed highs"),
                (self.coverage_card, "Execution coverage snapshot"),
                (self.health_card, "Warnings, errors, and tool transparency"),
                (self.assets_card, "Run inventory summary"),
                (self.evidence_card, "Artifacts and evidence linked to the run"),
            ):
                card.set_value("0", hint)
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
            self.filter_status_label.setText("Live inventory will appear here once a run is selected.")
            self.inspector_summary.setText("Select an item to inspect technical details and artifacts.")
            self.attention_banner.setText("Select a run to focus findings, health signals, and validation changes.")
            self.attention_banner.setProperty("tone", "neutral")
            refresh_widget_style(self.attention_banner)
            self.screenshot_preview.setPixmap(QPixmap())
            self.screenshot_preview.setText("Screenshot preview")
            self.preview_meta_label.setText("No artifact selected")
            self._current_finding_id = ""
            self._set_current_path("")
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
        needs_validation = sum(1 for item in findings if str(item.get("workflow_status") or "") == "needs-validation")
        issue_count = int(issue_summary.get("total_count", 0) or 0)
        completeness_status = str(issue_summary.get("completeness_status") or getattr(snapshot, "completeness_status", "healthy"))
        self.output_title.setText(snapshot.scan_name)
        self.summary_label.setText(
            f"Workspace: {snapshot.workspace_name or 'Unassigned'} | State: {title_case_label(snapshot.state)} | Completeness: {title_case_label(completeness_status)} | Issues: {issue_count} | Elapsed: {format_duration(snapshot.elapsed_seconds)} | ETA: {format_duration(snapshot.eta_seconds)} | Current task: {snapshot.current_task}"
        )
        self.progress_label.setText(f"{format_progress(snapshot.completed_tasks, snapshot.total_tasks)} | {progress_percent(snapshot.completed_tasks, snapshot.total_tasks)}% complete")
        self.progress_bar.setValue(progress_percent(snapshot.completed_tasks, snapshot.total_tasks))
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
        self.findings_card.set_value(str(len(findings)), f"{len(report_rows)} staged for reporting")
        self.critical_card.set_value(str(critical_high), f"{needs_validation} still need validation")
        self.coverage_card.set_value(f"{progress_percent(snapshot.completed_tasks, snapshot.total_tasks)}%", format_progress(snapshot.completed_tasks, snapshot.total_tasks))
        health_hint = "No execution issues detected. Open Scanner > Issues for a consolidated review."
        if issue_count:
            health_hint = f"{issue_count} execution issue(s) recorded | Open Scanner > Issues"
        self.health_card.set_value(title_case_label(completeness_status), health_hint)
        self.assets_card.set_value(str(len(snapshot.assets)), summarize_target_input(snapshot.target_input))
        self.evidence_card.set_value(str(len(snapshot.evidence) + len(snapshot.artifacts)), f"{len(snapshot.screenshots)} screenshot artifacts")

        attention_items: list[str] = []
        if critical_high:
            attention_items.append(f"{critical_high} critical/high findings")
        if needs_validation:
            attention_items.append(f"{needs_validation} findings still need validation")
        if issue_count:
            attention_items.append(f"{issue_count} execution issue(s) affecting completeness")
        if self._quick_filter == "new" and self._compare_snapshot is None:
            attention_items.append("Select a comparison run to isolate new inventory")
        if attention_items:
            banner_text = "Attention required: " + " | ".join(attention_items)
            if issue_count:
                banner_text += " | Open Scanner > Issues to review"
            self.attention_banner.setText(banner_text)
            self.attention_banner.setProperty("tone", "alert")
        else:
            self.attention_banner.setText("Monitoring looks healthy. Use the focus chips to zero in on critical findings or report-ready items.")
            self.attention_banner.setProperty("tone", "ok")
        refresh_widget_style(self.attention_banner)
        self.filter_status_label.setText(
            "Showing "
            f"{len(filtered_findings)}/{len(findings)} findings, "
            f"{len(filtered_assets)}/{len(snapshot.assets)} assets, "
            f"{len(filtered_services)}/{len(snapshot.services)} services, "
            f"{len(filtered_attack_paths)}/{len(snapshot.attack_paths)} attack paths, "
            f"{len(filtered_validation_tasks)}/{len(snapshot.validation_tasks)} validation tasks, "
            f"{len(filtered_replay_requests)}/{len(snapshot.replay_requests)} replay requests, "
            f"{len(filtered_evidence)}/{len(snapshot.evidence)} evidence records, "
            f"{issue_count}/{len(execution_issues)} issues"
            + (f" | Compare: {self._compare_snapshot.scan_name}" if self._compare_snapshot else "")
        )
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
        if not self.detail_text.toPlainText():
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
            row["effective_severity"] = state.severity_override or base_severity
            row["reproduce_steps"] = state.reproduce_steps if state else ""
            rows.append(row)
        rows.sort(key=lambda row: (SEVERITY_ORDER.get(str(row.get("effective_severity") or "info").lower(), 99), str(row.get("title") or "")))
        return rows

    def _filter_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.search_edit.text().strip().lower()
        diff_only = self.diff_filter.currentText() == "New Since Compare" or self._quick_filter == "new"
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
            if self._quick_filter == "critical-high" and str(row.get("effective_severity") or "").lower() not in {"critical", "high"}:
                continue
            if self._quick_filter == "needs-validation" and str(row.get("workflow_status") or "") != "needs-validation":
                continue
            if self._quick_filter == "report-ready" and not row.get("include_in_report"):
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
        self._show_details(payload)

    def _service_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _finding_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(0)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)
        self._current_finding_id = str(row.get("finding_id") or "")
        self.finding_status_combo.setCurrentText(str(row.get("workflow_status") or "needs-validation"))
        self.finding_severity_combo.setCurrentText(str(row.get("severity_override") or ""))
        self.finding_include_checkbox.setChecked(bool(row.get("include_in_report", True)))
        self.finding_note_edit.setPlainText(str(row.get("analyst_note") or ""))
        self.finding_repro_edit.setPlainText(str(row.get("reproduce_steps") or ""))

    def _web_app_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _endpoint_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _parameter_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _form_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _login_surface_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _technology_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _site_map_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _evidence_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)
        path = str(row.get("artifact_path") or "")
        self._set_current_path(path)
        self._preview_if_possible(path)

    def _artifact_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)
        path = str(row.get("path") or "")
        self._set_current_path(path)
        self._preview_if_possible(path)

    def _screenshot_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(2)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)
        path = str(row.get("path") or "")
        self._set_current_path(path)
        self._preview_path = path
        self._render_preview()
        self.inspector_tabs.setCurrentIndex(self.preview_tab_index)

    def _hypothesis_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _surface_signal_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _attack_path_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _investigation_step_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _validation_task_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _replay_request_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _validation_result_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _coverage_gap_selected(self, index: QModelIndex) -> None:
        self.primary_tabs.setCurrentIndex(1)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row)

    def _show_details(self, row: dict[str, Any]) -> None:
        detail_keys = [title_case_label(str(key)) for key in row.keys()]
        if detail_keys:
            self.inspector_summary.setText(f"Inspecting {', '.join(detail_keys[:3])}{'...' if len(detail_keys) > 3 else ''}")
        else:
            self.inspector_summary.setText("Select an item to inspect technical details and artifacts.")
        self.detail_text.setPlainText(self._build_technical_text(row))
        self.raw_text.setPlainText(json.dumps(row, indent=2, sort_keys=True))

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
