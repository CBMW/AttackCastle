from __future__ import annotations

import json
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QCheckBox,
    QFrame,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from attackcastle.extensions.reports.exporter import (
    ReportExportError,
    ReportMergeToolUnavailableError,
    build_shortcode_values,
    convert_docx_to_pdf,
    export_report,
    render_section_preview_html,
)
from attackcastle.extensions.reports.models import ReportTemplateSection
from attackcastle.gui.common import (
    FlowButtonRow,
    PAGE_CARD_SPACING,
    PAGE_SECTION_SPACING,
    PANEL_COMPACT_PADDING,
    PersistentSplitterController,
    SURFACE_PRIMARY,
    SURFACE_SECONDARY,
    apply_form_layout_defaults,
    apply_responsive_splitter,
    build_flat_container,
    build_surface_frame,
    configure_tab_widget,
    configure_scroll_surface,
    refresh_widget_style,
    set_tooltips,
    style_button,
)
from attackcastle.gui.models import FindingState, ReportScopeItem, ReportsConfig, RunSnapshot


REPORT_TYPE_LABELS = {
    "web_application": "Web Application",
    "external": "External",
    "internal": "Internal",
}
DATE_PATTERN = re.compile(r"^\d{2}/\d{2}/\d{4}$")
REPORTS_LEFT_WIDTH = 430
REPORTS_ROW_HEIGHT = 28
REPORT_EXPORT_FORMATS = (("docx", "DOCX"), ("pdf", "PDF"))
REPORT_PREVIEW_SECTIONS = (
    ("cover_page", "Cover Page", "cover_page.docx"),
    ("toc", "ToC", "chapter2.docx"),
    ("technical_summary", "Technical Summary", "chapter1-1.docx"),
    ("management_summary", "Management Summary", "chapter1.docx"),
    ("detailed_findings", "Detailed Findings", ""),
    ("appendices", "Appendices", ""),
)


class ScopeRow(QFrame):
    def __init__(self, scope_type: str, remove_handler: Callable[["ScopeRow"], None], item: ReportScopeItem | None = None) -> None:
        super().__init__()
        self.scope_type = scope_type
        self.setObjectName("scopeRow")
        self.setMinimumHeight(REPORTS_ROW_HEIGHT)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(PAGE_CARD_SPACING)
        layout.setVerticalSpacing(0)
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText(f"{REPORT_TYPE_LABELS.get(scope_type, scope_type)} target or asset")
        self.value_edit.setMinimumHeight(REPORTS_ROW_HEIGHT)
        self.uat_checkbox = QCheckBox("UAT")
        self.uat_checkbox.setObjectName("scopeUatCheckbox")
        self.uat_checkbox.setMinimumHeight(REPORTS_ROW_HEIGHT)
        self.remove_button = QPushButton("Remove")
        self.remove_button.setObjectName("scopeRemoveButton")
        self.remove_button.setFixedWidth(72)
        style_button(self.remove_button, role="secondary", min_height=REPORTS_ROW_HEIGHT)
        self.remove_button.clicked.connect(lambda: remove_handler(self))
        layout.addWidget(self.value_edit, 0, 0)
        layout.addWidget(self.uat_checkbox, 0, 1, Qt.AlignCenter)
        layout.addWidget(self.remove_button, 0, 2)
        layout.setColumnStretch(0, 1)
        layout.setColumnMinimumWidth(1, 68)
        layout.setColumnMinimumWidth(2, 78)
        if item is not None:
            self.value_edit.setText(item.value)
            self.uat_checkbox.setChecked(item.is_uat)

    def to_item(self) -> ReportScopeItem:
        return ReportScopeItem(
            scope_type=self.scope_type,
            value=self.value_edit.text().strip(),
            is_uat=self.uat_checkbox.isChecked(),
        )


class ReportsTab(QWidget):
    def __init__(
        self,
        *,
        load_config: Callable[[], ReportsConfig],
        save_config: Callable[[ReportsConfig], None],
        current_workspace_home: Callable[[], str],
        current_client_name: Callable[[], str],
        finding_states: Callable[[], dict[str, FindingState]],
        manual_findings: Callable[[str], list[dict[str, Any]]],
        open_path: Callable[[str], None],
        current_findings: Callable[[], list[dict[str, Any]]] | None = None,
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._load_config = load_config
        self._save_config = save_config
        self._current_workspace_home = current_workspace_home
        self._current_client_name = current_client_name
        self._finding_states = finding_states
        self._manual_findings = manual_findings
        self._current_findings = current_findings
        self._open_path = open_path
        self._snapshot: RunSnapshot | None = None
        self._last_export_path = ""
        self._scope_rows: dict[str, list[ScopeRow]] = {key: [] for key in REPORT_TYPE_LABELS}
        self._preview_browsers: dict[str, QTextBrowser] = {}
        self._last_preview_keys: dict[str, str] = {}
        self._preview_temp_dir = Path(tempfile.mkdtemp(prefix="attackcastle_report_previews_"))
        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.timeout.connect(self._refresh_report_previews)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)

        self.status_label = QLabel("")
        self.status_label.setObjectName("attentionBanner")
        self.status_label.setProperty("tone", "neutral")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.splitter = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 3))
        self.splitter_controller = PersistentSplitterController(
            self.splitter,
            "reports_main_split",
            layout_loader,
            layout_saver,
            self,
        )
        root.addWidget(self.splitter, 1)

        self._build_setup_panel()
        self._build_report_sections_panel()
        self.reload_config()
        self.sync_responsive_mode(self.width())

    def _build_setup_panel(self) -> None:
        panel, layout = build_surface_frame(object_name="reportsSetupPanel", surface=SURFACE_PRIMARY)
        panel.setMinimumWidth(360)
        layout.setSpacing(PANEL_COMPACT_PADDING)
        layout.addWidget(self._build_reports_header("Report Setup"))

        self.export_path_edit = QLineEdit()
        self.export_path_edit.setPlaceholderText("C:\\Reports\\client_report.docx")
        browse_button = QPushButton("Browse")
        browse_button.setObjectName("reportsBrowseButton")
        style_button(browse_button, role="secondary")
        browse_button.clicked.connect(self._browse_export_path)
        path_row = self._build_compound_row(self.export_path_edit, browse_button)

        self.merge_tool_path_edit = QLineEdit()
        self.merge_tool_path_edit.setPlaceholderText("Optional: path to LibreOffice soffice")
        browse_merge_button = QPushButton("Browse")
        browse_merge_button.setObjectName("reportsBrowseButton")
        style_button(browse_merge_button, role="secondary")
        browse_merge_button.clicked.connect(self._browse_merge_tool_path)
        merge_tool_row = self._build_compound_row(self.merge_tool_path_edit, browse_merge_button)

        format_row = QWidget()
        format_row.setObjectName("reportsCheckGrid")
        format_layout = QHBoxLayout(format_row)
        format_layout.setContentsMargins(0, 0, 0, 0)
        format_layout.setSpacing(PANEL_COMPACT_PADDING)
        self.export_format_checkboxes: dict[str, QCheckBox] = {}
        for key, label in REPORT_EXPORT_FORMATS:
            checkbox = QCheckBox(label)
            checkbox.setMinimumHeight(REPORTS_ROW_HEIGHT)
            checkbox.toggled.connect(self._schedule_preview_refresh)
            self.export_format_checkboxes[key] = checkbox
            format_layout.addWidget(checkbox)
        format_layout.addStretch(1)

        self.title_edit = QLineEdit()
        self.client_edit = QLineEdit()
        self.report_date_edit = QLineEdit()
        self.engagement_start_edit = QLineEdit()
        self.engagement_end_edit = QLineEdit()
        for edit in (
            self.export_path_edit,
            self.merge_tool_path_edit,
            self.title_edit,
            self.client_edit,
            self.report_date_edit,
            self.engagement_start_edit,
            self.engagement_end_edit,
        ):
            edit.setMinimumHeight(REPORTS_ROW_HEIGHT)

        type_row = QWidget()
        type_row.setObjectName("reportsCheckGrid")
        type_layout = QHBoxLayout(type_row)
        type_layout.setContentsMargins(0, 0, 0, 0)
        type_layout.setSpacing(PANEL_COMPACT_PADDING)
        self.type_checkboxes: dict[str, QCheckBox] = {}
        for key, label in REPORT_TYPE_LABELS.items():
            checkbox = QCheckBox(label)
            checkbox.setMinimumHeight(REPORTS_ROW_HEIGHT)
            checkbox.toggled.connect(self._sync_scope_sections)
            checkbox.toggled.connect(self._schedule_preview_refresh)
            self.type_checkboxes[key] = checkbox
            type_layout.addWidget(checkbox)
        type_layout.addStretch(1)

        self.add_all_findings_checkbox = QCheckBox("Add all findings")
        self.add_report_only_checkbox = QCheckBox("Add Report Only Findings")
        self.add_all_findings_checkbox.setMinimumHeight(REPORTS_ROW_HEIGHT)
        self.add_report_only_checkbox.setMinimumHeight(REPORTS_ROW_HEIGHT)
        self.add_all_findings_checkbox.toggled.connect(self._sync_finding_mode_checkboxes)
        self.add_report_only_checkbox.toggled.connect(self._sync_finding_mode_checkboxes)
        self.add_all_findings_checkbox.toggled.connect(self._schedule_preview_refresh)
        self.add_report_only_checkbox.toggled.connect(self._schedule_preview_refresh)

        output_section, output_form = self._build_setup_section("Output")
        output_form.addRow("Export Path", path_row)
        output_form.addRow("Export Formats", format_row)
        output_form.addRow("Merge Tool", merge_tool_row)
        layout.addWidget(output_section)

        identity_section, identity_form = self._build_setup_section("Identity")
        identity_form.addRow("Report Title", self.title_edit)
        identity_form.addRow("Client Name", self.client_edit)
        identity_form.addRow("Report Date", self.report_date_edit)
        identity_form.addRow("Engagement Start", self.engagement_start_edit)
        identity_form.addRow("Engagement End", self.engagement_end_edit)
        layout.addWidget(identity_section)

        coverage_section, coverage_form = self._build_setup_section("Coverage")
        coverage_form.addRow("Report Type", type_row)
        coverage_form.addRow("Findings", self.add_all_findings_checkbox)
        coverage_form.addRow("", self.add_report_only_checkbox)
        layout.addWidget(coverage_section)

        layout.addWidget(self._build_scope_section())

        actions = FlowButtonRow()
        actions.setObjectName("reportsActionRow")
        self.export_button = QPushButton("Export Report")
        self.export_button.setObjectName("reportsPrimaryAction")
        self.export_button.clicked.connect(self.export_current_report)
        style_button(self.export_button, min_height=32)
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_current_config)
        style_button(self.save_button, role="secondary", min_height=32)
        self.open_folder_button = QPushButton("Open Export Folder")
        self.open_folder_button.clicked.connect(self._open_export_folder)
        self.open_folder_button.setEnabled(False)
        style_button(self.open_folder_button, role="secondary", min_height=32)
        actions.addWidget(self.export_button)
        actions.addWidget(self.save_button)
        actions.addWidget(self.open_folder_button)
        layout.addWidget(actions)
        layout.addStretch(1)
        set_tooltips(
            (
                (self.export_path_edit, "Choose the report file path or destination folder."),
                (
                    self.merge_tool_path_edit,
                    "Optional path to LibreOffice soffice/libreoffice. Used when Microsoft Word is unavailable or on Linux.",
                ),
                (self.export_format_checkboxes["docx"], "Write the editable Word report."),
                (self.export_format_checkboxes["pdf"], "Also convert the rendered Word report to PDF."),
                (self.report_date_edit, "Use Australian date format: DD/MM/YYYY."),
                (self.add_all_findings_checkbox, "Include every finding available for the selected run."),
                (self.add_report_only_checkbox, "Include only findings explicitly marked for reports exports."),
            )
        )
        for edit in (
            self.export_path_edit,
            self.merge_tool_path_edit,
            self.title_edit,
            self.client_edit,
            self.report_date_edit,
            self.engagement_start_edit,
            self.engagement_end_edit,
        ):
            edit.textChanged.connect(self._schedule_preview_refresh)
        self.splitter.addWidget(panel)

    def _build_scope_section(self) -> QFrame:
        scope_section, scope_section_layout = build_surface_frame(
            object_name="reportsSetupSection",
            surface=SURFACE_SECONDARY,
            padding=PANEL_COMPACT_PADDING,
        )
        scope_section_layout.setSpacing(PAGE_CARD_SPACING)
        title = QLabel("Web Application Scope")
        title.setObjectName("profileGroupTitle")
        scope_section_layout.addWidget(title)
        self.scope_tabs = QTabWidget()
        configure_tab_widget(self.scope_tabs, role="inspector")
        self.scope_tabs.setObjectName("reportsScopeTabs")
        self.scope_sections: dict[str, QWidget] = {}
        self.scope_row_layouts: dict[str, QVBoxLayout] = {}
        self.scope_tab_indices: dict[str, int] = {}
        for key, label in REPORT_TYPE_LABELS.items():
            section, section_layout = build_surface_frame(
                object_name="reportsScopeSection",
                surface=SURFACE_SECONDARY,
                padding=PANEL_COMPACT_PADDING,
            )
            section_layout.setSpacing(PAGE_CARD_SPACING)
            header = QHBoxLayout()
            header.setContentsMargins(0, 0, 0, 0)
            header.setSpacing(PAGE_CARD_SPACING)
            header_title = QLabel(f"{label} Scope")
            header_title.setObjectName("sectionTitle")
            header_hint = QLabel("Target")
            header_hint.setObjectName("helperText")
            add_button = QPushButton("Add Row")
            add_button.setObjectName("scopeAddButton")
            add_button.setFixedWidth(86)
            style_button(add_button, role="secondary", min_height=REPORTS_ROW_HEIGHT)
            add_button.clicked.connect(lambda _checked=False, scope_type=key: self._add_scope_row(scope_type))
            header.addWidget(header_title)
            header.addWidget(header_hint, 1)
            header.addWidget(add_button)

            column_header = QWidget()
            column_header.setObjectName("scopeColumnHeaderRow")
            column_header_layout = QGridLayout(column_header)
            column_header_layout.setContentsMargins(0, 0, 0, 0)
            column_header_layout.setHorizontalSpacing(PAGE_CARD_SPACING)
            column_header_layout.setVerticalSpacing(0)
            target_label = QLabel("Target / Asset")
            target_label.setObjectName("scopeColumnHeader")
            uat_label = QLabel("UAT")
            uat_label.setObjectName("scopeColumnHeader")
            action_label = QLabel("Action")
            action_label.setObjectName("scopeColumnHeader")
            column_header_layout.addWidget(target_label, 0, 0)
            column_header_layout.addWidget(uat_label, 0, 1, Qt.AlignCenter)
            column_header_layout.addWidget(action_label, 0, 2, Qt.AlignCenter)
            column_header_layout.setColumnStretch(0, 1)
            column_header_layout.setColumnMinimumWidth(1, 68)
            column_header_layout.setColumnMinimumWidth(2, 78)

            rows_host = QWidget()
            rows_host.setObjectName("scopeRowsHost")
            row_layout = QVBoxLayout()
            rows_host.setLayout(row_layout)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(PAGE_CARD_SPACING)
            section_layout.addLayout(header)
            section_layout.addWidget(column_header)
            section_layout.addWidget(rows_host)
            self.scope_sections[key] = section
            self.scope_row_layouts[key] = row_layout
            tab = build_flat_container()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setContentsMargins(0, 0, 0, 0)
            tab_layout.setSpacing(0)
            tab_layout.addWidget(section, 1)
            self.scope_tab_indices[key] = self.scope_tabs.addTab(tab, label)
        scope_section_layout.addWidget(self.scope_tabs, 1)
        return scope_section

    def _build_report_sections_panel(self) -> None:
        panel, layout = build_surface_frame(object_name="reportsContentPanel", surface=SURFACE_PRIMARY)
        layout.setSpacing(PANEL_COMPACT_PADDING)
        self.report_section_tabs = QTabWidget()
        self.report_section_tabs.setObjectName("reportsSectionTabs")
        configure_tab_widget(self.report_section_tabs, role="group")
        self.report_section_tabs.currentChanged.connect(self._schedule_preview_refresh)
        for section_id, label, template_filename in REPORT_PREVIEW_SECTIONS:
            tab = build_flat_container()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setContentsMargins(0, 0, 0, 0)
            tab_layout.setSpacing(PANEL_COMPACT_PADDING)
            if not template_filename:
                tab_layout.addStretch(1)
                self.report_section_tabs.addTab(tab, label)
                continue

            preview = QTextBrowser()
            preview.setObjectName("reportsDocumentPreview")
            preview.setOpenExternalLinks(False)
            preview.setReadOnly(True)
            preview.setHtml(self._empty_preview_html())
            tab_layout.addWidget(configure_scroll_surface(preview), 1)
            self._preview_browsers[section_id] = preview
            self.report_section_tabs.addTab(tab, label)
        layout.addWidget(self.report_section_tabs, 1)
        self.splitter.addWidget(panel)

    def _empty_preview_html(self) -> str:
        return (
            "<html><body style=\"margin:0;background:#eef1f5;color:#64748b;"
            "font-family:Arial, sans-serif;\"></body></html>"
        )

    def _build_reports_header(self, title: str) -> QWidget:
        header = QWidget()
        header.setObjectName("reportsPanelHeader")
        layout = QVBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        layout.addWidget(title_label)
        return header

    def _build_setup_section(self, title: str) -> tuple[QFrame, QFormLayout]:
        section, layout = build_surface_frame(
            object_name="reportsSetupSection",
            surface=SURFACE_SECONDARY,
            padding=PANEL_COMPACT_PADDING,
        )
        layout.setSpacing(PAGE_CARD_SPACING)
        label = QLabel(title)
        label.setObjectName("profileGroupTitle")
        layout.addWidget(label)
        body = QWidget()
        body.setObjectName("reportsSetupSectionBody")
        form = QFormLayout(body)
        apply_form_layout_defaults(form)
        form.setVerticalSpacing(PAGE_CARD_SPACING)
        form.setHorizontalSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(body)
        return section, form

    def _build_compound_row(self, field: QLineEdit, button: QPushButton) -> QWidget:
        row = QWidget()
        row.setObjectName("reportsPathRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(PAGE_CARD_SPACING)
        row_layout.addWidget(field, 1)
        row_layout.addWidget(button)
        return row

    def _load_into_form(self) -> None:
        config = self._load_config()
        self.export_path_edit.setText(config.export_path)
        self.merge_tool_path_edit.setText(config.merge_tool_path)
        selected_formats = set(config.export_formats or ["docx"])
        for key, checkbox in self.export_format_checkboxes.items():
            checkbox.setChecked(key in selected_formats)
        if not any(checkbox.isChecked() for checkbox in self.export_format_checkboxes.values()):
            self.export_format_checkboxes["docx"].setChecked(True)
        self.title_edit.setText(config.report_title)
        self.client_edit.setText(config.client_name or self._current_client_name())
        self.report_date_edit.setText(config.report_date or datetime.now().strftime("%d/%m/%Y"))
        self.engagement_start_edit.setText(config.engagement_start_date)
        self.engagement_end_edit.setText(config.engagement_end_date)
        self.add_all_findings_checkbox.setChecked(config.add_all_findings)
        self.add_report_only_checkbox.setChecked(config.add_report_only_findings)
        for key, checkbox in self.type_checkboxes.items():
            checkbox.setChecked(key in config.report_types)
        for item in config.scope_items:
            if item.scope_type in self._scope_rows:
                self._add_scope_row(item.scope_type, item)
        for key in REPORT_TYPE_LABELS:
            if not self._scope_rows[key]:
                self._add_scope_row(key)
        self._sync_scope_sections()
        self._set_status("Ready to export a HackLabs-style report cover page.", "neutral")
        self._schedule_preview_refresh()

    def reload_config(self) -> None:
        for rows in self._scope_rows.values():
            while rows:
                row = rows.pop()
                row.setParent(None)
                row.deleteLater()
        self._scope_rows = {key: [] for key in REPORT_TYPE_LABELS}
        self._load_into_form()

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot
        self._refresh_findings_summary()

    def sync_responsive_mode(self, width: int) -> None:
        self.splitter.setOrientation(Qt.Horizontal if width >= 1180 else Qt.Vertical)
        if width >= 1180:
            self.splitter_controller.apply([REPORTS_LEFT_WIDTH, max(width - REPORTS_LEFT_WIDTH, 680)])
        else:
            self.splitter_controller.apply([360, 520])

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())

    def closeEvent(self, event) -> None:  # noqa: N802
        self._preview_timer.stop()
        shutil.rmtree(self._preview_temp_dir, ignore_errors=True)
        super().closeEvent(event)

    def _add_scope_row(self, scope_type: str, item: ReportScopeItem | None = None) -> None:
        row = ScopeRow(scope_type, self._remove_scope_row, item)
        row.value_edit.textChanged.connect(self._schedule_preview_refresh)
        row.uat_checkbox.toggled.connect(self._schedule_preview_refresh)
        self._scope_rows.setdefault(scope_type, []).append(row)
        self.scope_row_layouts[scope_type].addWidget(row)

    def _remove_scope_row(self, row: ScopeRow) -> None:
        rows = self._scope_rows.get(row.scope_type, [])
        if row in rows:
            rows.remove(row)
        row.setParent(None)
        row.deleteLater()
        if not rows:
            self._add_scope_row(row.scope_type)
        self._schedule_preview_refresh()

    def _sync_scope_sections(self) -> None:
        for key, section in self.scope_sections.items():
            checked = self.type_checkboxes[key].isChecked()
            section.setVisible(checked)
            if hasattr(self, "scope_tabs"):
                self.scope_tabs.setTabVisible(self.scope_tab_indices[key], checked)

    def _selected_report_types(self) -> list[str]:
        return [key for key, checkbox in self.type_checkboxes.items() if checkbox.isChecked()]

    def _selected_export_formats(self) -> list[str]:
        return [key for key, checkbox in self.export_format_checkboxes.items() if checkbox.isChecked()]

    def _scope_items(self) -> list[ReportScopeItem]:
        items: list[ReportScopeItem] = []
        for scope_type, rows in self._scope_rows.items():
            for row in rows:
                item = row.to_item()
                if item.value or scope_type in self._selected_report_types():
                    items.append(item)
        return items

    def build_config(self) -> ReportsConfig:
        return ReportsConfig(
            export_path=self.export_path_edit.text().strip(),
            merge_tool_path=self.merge_tool_path_edit.text().strip(),
            export_formats=self._selected_export_formats(),
            report_title=self.title_edit.text().strip(),
            report_types=self._selected_report_types(),
            client_name=self.client_edit.text().strip(),
            report_date=self.report_date_edit.text().strip(),
            engagement_start_date=self.engagement_start_edit.text().strip(),
            engagement_end_date=self.engagement_end_edit.text().strip(),
            scope_items=self._scope_items(),
            add_all_findings=self.add_all_findings_checkbox.isChecked(),
            add_report_only_findings=self.add_report_only_checkbox.isChecked(),
        )

    def save_current_config(self) -> None:
        self._save_config(self.build_config())
        self._set_status("Report settings saved.", "ok")

    def _validation_errors(self, config: ReportsConfig) -> list[str]:
        errors: list[str] = []
        if not config.export_path:
            errors.append("Export path is required.")
        if not config.export_formats:
            errors.append("Select at least one export format.")
        if not config.report_title:
            errors.append("Report title is required.")
        if not config.client_name:
            errors.append("Client name is required.")
        if not config.report_types:
            errors.append("Select at least one report type.")
        if config.add_all_findings and config.add_report_only_findings:
            errors.append("Choose either all findings or report-only findings, not both.")
        if not DATE_PATTERN.match(config.report_date):
            errors.append("Report date must be DD/MM/YYYY.")
        for label, value in (("Engagement start", config.engagement_start_date), ("Engagement end", config.engagement_end_date)):
            if value and not DATE_PATTERN.match(value):
                errors.append(f"{label} date must be DD/MM/YYYY.")
        return errors

    def _included_findings(self, config: ReportsConfig) -> list[dict[str, Any]]:
        rows = self._available_findings()
        rows = self._rows_with_finding_state(rows)
        if config.add_all_findings:
            return rows
        if config.add_report_only_findings:
            return [
                row
                for row in rows
                if row.get("include_in_report") and row.get("report_flag_touched")
            ]
        return []

    def _available_findings(self) -> list[dict[str, Any]]:
        if self._current_findings is not None:
            rows = self._current_findings()
            if rows:
                return list(rows)
        if self._snapshot is None:
            return []
        rows = list(self._snapshot.findings)
        manual_rows = self._manual_findings(self._snapshot.run_id)
        existing_ids = {str(row.get("finding_id") or "") for row in rows}
        removed_ids = {
            str(row.get("finding_id") or "")
            for row in manual_rows
            if isinstance(row, dict) and row.get("_removed") and str(row.get("finding_id") or "")
        }
        rows = [row for row in rows if str(row.get("finding_id") or "") not in removed_ids]
        rows.extend(
            row
            for row in manual_rows
            if not row.get("_removed") and str(row.get("finding_id") or "") not in existing_ids
        )
        return rows

    def _rows_with_finding_state(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        states = self._finding_states()
        merged_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            merged = dict(row)
            state = states.get(str(merged.get("finding_id") or ""))
            base_severity = str(merged.get("severity") or "info").lower()
            merged["include_in_report"] = state.include_in_report if state else bool(merged.get("include_in_report", True))
            merged["report_flag_touched"] = state.report_flag_touched if state else bool(merged.get("report_flag_touched", False))
            merged["severity_override"] = state.severity_override if state else str(merged.get("severity_override") or "")
            merged["effective_severity"] = (state.severity_override if state else "") or str(merged.get("effective_severity") or base_severity)
            merged_rows.append(merged)
        return merged_rows

    def export_current_report(self) -> None:
        config = self.build_config()
        errors = self._validation_errors(config)
        if errors:
            self._set_status(" ".join(errors), "warning")
            return
        included_findings = self._included_findings(config)
        if config.add_report_only_findings and not included_findings:
            decision = QMessageBox.question(
                self,
                "No Report Findings",
                "No findings are explicitly marked for reporting. Export the cover page anyway?",
            )
            if decision != QMessageBox.Yes:
                return
        try:
            result, exported_paths = self._export_with_config(config, included_findings)
        except ReportMergeToolUnavailableError as exc:
            self._set_status(str(exc), "alert")
            selected = self._prompt_for_merge_tool_path(str(exc))
            if not selected:
                return
            config.merge_tool_path = selected
            self.merge_tool_path_edit.setText(selected)
            try:
                result, exported_paths = self._export_with_config(config, included_findings)
            except ReportExportError as retry_exc:
                self._set_status(str(retry_exc), "alert")
                QMessageBox.warning(self, "Report Export Failed", str(retry_exc))
                return
        except ReportExportError as exc:
            self._set_status(str(exc), "alert")
            QMessageBox.warning(self, "Report Export Failed", str(exc))
            return
        self._save_config(config)
        self._last_export_path = str(exported_paths[0] if exported_paths else result.output_path)
        self.open_folder_button.setEnabled(True)
        targets = ", ".join(str(path) for path in exported_paths)
        self._set_status(f"Exported report to {targets}", "ok")

    def _export_with_config(self, config: ReportsConfig, included_findings: list[dict[str, Any]]):
        result = export_report(
            export_path=config.export_path,
            report_title=config.report_title,
            report_type=", ".join(REPORT_TYPE_LABELS[key] for key in config.report_types),
            client_name=config.client_name,
            report_date=config.report_date,
            workspace_home=self._current_workspace_home(),
            included_findings=included_findings,
            merge_tool_path=config.merge_tool_path,
        )
        exported_paths = []
        formats = set(config.export_formats or ["docx"])
        if "docx" in formats:
            exported_paths.append(result.output_path)
        if "pdf" in formats:
            pdf_path = convert_docx_to_pdf(
                result.output_path,
                result.output_path.with_suffix(".pdf"),
                merge_tool_path=config.merge_tool_path,
            )
            exported_paths.append(pdf_path)
        if "docx" not in formats and "pdf" in formats:
            try:
                result.output_path.unlink()
            except OSError:
                pass
        return result, exported_paths

    def _prompt_for_merge_tool_path(self, message: str) -> str:
        QMessageBox.warning(
            self,
            "Report Merge Tool Required",
            (
                f"{message}\n\n"
                "Install Microsoft Word on Windows or LibreOffice on Windows/Linux. "
                "If LibreOffice is installed, select the soffice/libreoffice binary in the next dialog."
            ),
        )
        return self._browse_merge_tool_path()

    def _sync_finding_mode_checkboxes(self, checked: bool) -> None:
        if not checked:
            return
        sender = self.sender()
        if sender is self.add_all_findings_checkbox and self.add_report_only_checkbox.isChecked():
            self.add_report_only_checkbox.setChecked(False)
        elif sender is self.add_report_only_checkbox and self.add_all_findings_checkbox.isChecked():
            self.add_all_findings_checkbox.setChecked(False)

    def _browse_export_path(self) -> None:
        start = self.export_path_edit.text().strip() or self._current_workspace_home() or str(Path.home())
        selected, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            start,
            "Word Document (*.docx);;PDF Document (*.pdf);;All Files (*)",
        )
        if selected:
            self.export_path_edit.setText(selected)
            if selected.lower().endswith(".pdf") or "PDF" in selected_filter:
                self.export_format_checkboxes["pdf"].setChecked(True)
                self.export_format_checkboxes["docx"].setChecked(False)
            elif selected.lower().endswith(".docx") or "Word" in selected_filter:
                self.export_format_checkboxes["docx"].setChecked(True)

    def _browse_merge_tool_path(self) -> str:
        start = self.merge_tool_path_edit.text().strip() or str(Path.home())
        filter_text = "Executable (*.exe);;All Files (*)" if Path(start).drive or "\\" in start else "All Files (*)"
        selected, _filter = QFileDialog.getOpenFileName(self, "Locate LibreOffice soffice", start, filter_text)
        if selected:
            self.merge_tool_path_edit.setText(selected)
        return selected

    def _open_export_folder(self) -> None:
        path = Path(self._last_export_path or self.export_path_edit.text().strip())
        if path.suffix:
            path = path.parent
        if str(path):
            self._open_path(str(path))

    def _refresh_findings_summary(self) -> None:
        available = self._available_findings()
        marked = len(
            [
                state
                for state in self._finding_states().values()
                if state.include_in_report and state.report_flag_touched
            ]
        )
        self._set_status(
            f"Ready. Current context has {len(available)} finding(s), {marked} explicitly marked for reporting.",
            "neutral",
        )
        self._schedule_preview_refresh()

    def _schedule_preview_refresh(self, *_args) -> None:
        if not self._preview_browsers:
            return
        self._preview_timer.start(250)

    def _report_type_label(self, config: ReportsConfig) -> str:
        return ", ".join(REPORT_TYPE_LABELS[key] for key in config.report_types if key in REPORT_TYPE_LABELS)

    def _refresh_report_previews(self) -> None:
        section_id, label, template_filename = self._active_preview_section()
        if not section_id or not template_filename:
            return
        config = self.build_config()
        included_findings = self._included_findings(config)
        preview_key = self._preview_key(section_id, config, included_findings)
        if preview_key == self._last_preview_keys.get(section_id):
            return
        shortcode_values = build_shortcode_values(
            report_title=config.report_title,
            report_type=self._report_type_label(config),
            client_name=config.client_name,
            report_date=config.report_date,
            included_findings=included_findings,
        )
        try:
            html = render_section_preview_html(
                ReportTemplateSection(section_id=section_id, template_filename=template_filename),
                shortcode_values,
                included_findings=included_findings,
                asset_dir=self._preview_temp_dir / section_id,
                merge_tool_path=config.merge_tool_path,
            )
            browser = self._preview_browsers.get(section_id)
            if browser is not None:
                browser.setHtml(html)
            self._last_preview_keys[section_id] = preview_key
        except ReportExportError as exc:
            browser = self._preview_browsers.get(section_id)
            if browser is not None:
                browser.setPlainText(f"{label} preview is not available yet.\n\n{exc}")

    def _active_preview_section(self) -> tuple[str, str, str]:
        index = self.report_section_tabs.currentIndex()
        if index < 0 or index >= len(REPORT_PREVIEW_SECTIONS):
            return "", "", ""
        return REPORT_PREVIEW_SECTIONS[index]

    def _preview_key(self, section_id: str, config: ReportsConfig, included_findings: list[dict[str, Any]]) -> str:
        finding_rows = [
            {
                "finding_id": row.get("finding_id"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "severity_override": row.get("severity_override"),
                "effective_severity": row.get("effective_severity"),
            }
            for row in included_findings
            if isinstance(row, dict)
        ]
        payload = {
            "renderer": "native-docx-html-v3",
            "section_id": section_id,
            "title": config.report_title,
            "types": config.report_types,
            "client": config.client_name,
            "date": config.report_date,
            "merge_tool": config.merge_tool_path,
            "findings": finding_rows,
        }
        return json.dumps(payload, sort_keys=True)

    def _set_status(self, message: str, tone: str) -> None:
        self.status_label.setText(message)
        self.status_label.setProperty("tone", tone)
        refresh_widget_style(self.status_label)
