from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QProcess, QRect, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    Card,
    FlowButtonRow,
    MappingTableModel,
    PAGE_CARD_SPACING,
    PAGE_SECTION_SPACING,
    PANEL_CONTENT_PADDING,
    PersistentSplitterController,
    RUN_STATE_ORDER,
    SURFACE_FLAT,
    SURFACE_PRIMARY,
    SURFACE_SECONDARY,
    apply_form_layout_defaults,
    apply_responsive_splitter,
    build_flat_container,
    build_inspector_panel,
    build_section_header,
    build_surface_frame,
    build_table_section,
    build_workstation_stylesheet,
    configure_tab_widget,
    configure_scroll_surface,
    ensure_table_defaults,
    format_duration,
    format_progress,
    refresh_widget_style,
    style_button,
    set_tooltip,
    set_tooltips,
    summarize_target_input,
    table_height_for_rows,
    title_case_label,
)
from attackcastle.gui.asset_inventory import build_workspace_inventory_snapshot
from attackcastle.gui.attacker_tab import AttackerTab, WORKSPACE_TYPES
from attackcastle.gui.assets_tab import AssetsTab
from attackcastle.gui.configuration_tab import ConfigurationTab
from attackcastle.gui.dialogs import (
    DebugLogDialog,
    StartScanDialog,
    WorkspaceChooserDialog,
    WorkspaceDialog,
    WorkspaceMigrationDialog,
)
from attackcastle.gui.extensions import REPORTS_EXTENSION_ID
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.extensions_tab import ExtensionsTab
from attackcastle.gui.models import (
    AttackWorkspace,
    AuditEntry,
    EntityNote,
    FindingState,
    GuiProfile,
    GuiProxySettings,
    MigrationState,
    OverviewChecklistItem,
    ReportsConfig,
    RunRegistryEntry,
    RunSnapshot,
    ScanRequest,
    Workspace,
    WorkspaceOverviewState,
    now_iso,
)
from attackcastle.gui.overview_general import GeneralOverviewData, OverviewGeneralPanel
from attackcastle.gui.overview_checklist import OverviewChecklistPanel
from attackcastle.gui.output_tab import OutputTab
from attackcastle.gui.performance import (
    PerformanceGuardSettings,
    ProcessTreeUsageSampler,
    load_performance_guard_settings,
    save_performance_guard_settings,
)
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.reports_tab import ReportsTab
from attackcastle.gui.runtime import build_run_debug_bundle, load_run_snapshot
from attackcastle.gui.scanner_panel import ScannerPanel
from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.gui.worker_protocol import WorkerEvent
from attackcastle.gui.workspace_store import NO_WORKSPACE_SCOPE_ID, WorkspaceStore, ad_hoc_output_home
from attackcastle.storage.run_store import RunStore

class MainWindow(QMainWindow):
    def __init__(
        self,
        store: GuiProfileStore | None = None,
        workspace_store: WorkspaceStore | None = None,
        extension_store: GuiExtensionStore | None = None,
        active_workspace: Workspace | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("AttackCastle")
        self.store = store or GuiProfileStore()
        self.workspace_store = workspace_store or WorkspaceStore()
        self.extension_store = extension_store or GuiExtensionStore()
        self._profiles = self.store.load()
        self._workspaces = self.workspace_store.load_workspaces()
        self._engagements = self._workspaces
        self._active_workspace_id = (
            active_workspace.workspace_id
            if active_workspace is not None
            else self.workspace_store.get_active_workspace_id()
        )
        self._selected_workspace_id = self._active_workspace_id or (self._workspaces[0].workspace_id if self._workspaces else "")
        self._selected_engagement_id = self._selected_workspace_id
        self._finding_states_by_run: dict[str, dict[str, FindingState]] = {}
        self._audit_entries: list[AuditEntry] = []
        self._run_registry: list[RunRegistryEntry] = []
        self._process_buffers: dict[QProcess, str] = {}
        self._job_files: dict[QProcess, Path] = {}
        self._process_run_ids: dict[QProcess, str] = {}
        self._run_processes: dict[str, QProcess] = {}
        self._run_snapshots: dict[str, RunSnapshot] = {}
        self._debug_dialogs: list[DebugLogDialog] = []
        self._selected_run_id: str | None = None
        self._overview_state = WorkspaceOverviewState()
        self._applying_overview_state = False
        self._geometry_synced_to_screen = False
        self._nav_order = ["workspaces", "runs", "assets", "attacker", "findings", "extensions", "settings"]
        self._page_indices: dict[str, int] = {}
        self.reports_tab: ReportsTab | None = None
        self._splitter_controllers: dict[str, PersistentSplitterController] = {}
        self._switch_in_progress = False
        self.performance_guard_settings = load_performance_guard_settings()
        self.proxy_settings = self.workspace_store.load_proxy_settings()
        self._applying_proxy_settings = False
        self._system_usage_sampler = ProcessTreeUsageSampler()
        self._resource_pressure_active = False
        self._last_resource_action = "No resource action yet."
        self._resource_unmet_alerts: dict[str, float] = {}
        self._init_ui()
        self._apply_initial_geometry()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(1000)
        self._refresh_timer.timeout.connect(self._refresh_runs)
        self._refresh_timer.start()
        self._overview_notes_timer = QTimer(self)
        self._overview_notes_timer.setSingleShot(True)
        self._overview_notes_timer.setInterval(300)
        self._overview_notes_timer.timeout.connect(self._persist_overview_state)
        self._performance_timer = QTimer(self)
        self._performance_timer.setInterval(max(1000, int(self.performance_guard_settings.sample_interval_seconds) * 1000))
        self._performance_timer.timeout.connect(self._check_performance_guard)
        self._performance_timer.start()
        self._apply_styles()
        self._setup_shortcuts()
        self._sync_workspace_list()
        self._load_workspace_state(self._active_workspace_id)
        self._update_run_action_state()
        self._refresh_settings_page()
        self._navigate_to("workspaces")

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        if not self._geometry_synced_to_screen:
            self._apply_initial_geometry()
            self._geometry_synced_to_screen = True
        self._sync_responsive_layouts()

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._sync_responsive_layouts()

    def _sync_responsive_layouts(self) -> None:
        width = max(self.width(), 1)
        if width >= 1480:
            mode = "desktop"
        elif width >= 1280:
            mode = "compact"
        else:
            mode = "stacked"

        if mode == "stacked":
            self.workspace_content_split.setOrientation(Qt.Vertical)
            self._apply_splitter_layout(
                "workspace_overview_split",
                [
                    max(int(self.height() * 0.26), 220),
                    max(int(self.height() * 0.42), 320),
                    max(int(self.height() * 0.32), 260),
                ],
            )
        else:
            self.workspace_content_split.setOrientation(Qt.Horizontal)
            self._apply_splitter_layout(
                "workspace_overview_split",
                [max(int(width * 0.25), 260), max(int(width * 0.50), 520), max(int(width * 0.25), 280)],
            )
        if hasattr(self, "workspace_center_split"):
            self.workspace_center_split.setOrientation(Qt.Vertical)
            self._apply_splitter_layout(
                "workspace_center_split",
                [max(int(self.height() * 0.34), 240), max(int(self.height() * 0.34), 240)],
            )
        if hasattr(self, "workspace_inspector_split"):
            self.workspace_inspector_split.setOrientation(Qt.Vertical)
            self._apply_splitter_layout(
                "workspace_inspector_split",
                [max(int(self.height() * 0.34), 240), max(int(self.height() * 0.34), 240)],
            )
        self._arrange_run_filters(width)
        if hasattr(self, "runs_body_split"):
            if width >= 1240:
                self.runs_body_split.setOrientation(Qt.Horizontal)
                content_width = max(int(width * 0.96), 960)
                self._apply_splitter_layout(
                    "runs_body_split",
                    [max(int(content_width * 0.62), 620), max(int(content_width * 0.38), 360)],
                )
            else:
                self.runs_body_split.setOrientation(Qt.Vertical)
                self._apply_splitter_layout(
                    "runs_body_split",
                    [max(int(self.height() * 0.42), 300), max(int(self.height() * 0.42), 320)],
                )
        if hasattr(self, "settings_split"):
            if width >= 1040:
                self.settings_split.setOrientation(Qt.Horizontal)
                self._apply_splitter_layout(
                    "settings_split",
                    [max(int(width * 0.22), 260), max(int(width * 0.78), 780)],
                )
            else:
                self.settings_split.setOrientation(Qt.Vertical)
                self._apply_splitter_layout(
                    "settings_split",
                    [max(int(self.height() * 0.24), 180), max(int(self.height() * 0.76), 520)],
                )
        self.output_tab.sync_responsive_mode(width)
        if self.reports_tab is not None:
            self.reports_tab.sync_responsive_mode(width)
        self.attacker_tab.sync_responsive_mode(width)
        self.scanner_panel.sync_responsive_mode(width)
        self.configuration_tab.sync_profile_form_width(width)

    def _arrange_run_filters(self, width: int) -> None:
        while self.run_filter_grid.count():
            self.run_filter_grid.takeAt(0)
        if width >= 1480:
            column = 0
            for label, widget in self.run_filter_controls:
                self.run_filter_grid.addWidget(label, 0, column)
                self.run_filter_grid.addWidget(widget, 0, column + 1)
                column += 2
            self.run_filter_grid.addWidget(self.run_results_label, 1, 0, 1, max(column - 1, 1))
            self.run_filter_grid.addWidget(self.start_scan_button, 1, max(column - 1, 1), Qt.AlignRight)
        else:
            for row, (label, widget) in enumerate(self.run_filter_controls):
                self.run_filter_grid.addWidget(label, row, 0)
                self.run_filter_grid.addWidget(widget, row, 1)
            row = len(self.run_filter_controls)
            self.run_filter_grid.addWidget(self.run_results_label, row, 0)
            self.run_filter_grid.addWidget(self.start_scan_button, row, 1, Qt.AlignRight)

    def _load_ui_layout(self, layout_key: str, orientation: str) -> list[int] | None:
        sizes = self.workspace_store.load_ui_layout(layout_key, orientation)
        return list(sizes) if isinstance(sizes, list) else None

    def _save_ui_layout(self, layout_key: str, orientation: str, sizes: list[int]) -> None:
        self.workspace_store.save_ui_layout(layout_key, orientation, sizes)

    def _register_splitter(self, splitter: QSplitter, layout_key: str) -> PersistentSplitterController:
        controller = PersistentSplitterController(
            splitter,
            layout_key,
            self._load_ui_layout,
            self._save_ui_layout,
            self,
        )
        self._splitter_controllers[layout_key] = controller
        return controller

    def _apply_splitter_layout(self, layout_key: str, fallback_sizes: list[int]) -> None:
        controller = self._splitter_controllers.get(layout_key)
        if controller is not None:
            controller.apply(fallback_sizes)

    def _init_ui(self) -> None:
        self.setMinimumSize(720, 520)
        central = QWidget()
        central.setObjectName("appRoot")
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(0)

        self.general_status = QLabel("Ready")
        self.general_status_detail = QLabel("Project, run actions, and findings stay in sync across every section.")

        self.workflow_tabs = QTabWidget()
        configure_tab_widget(self.workflow_tabs, role="master")
        self.workflow_tabs.setUsesScrollButtons(True)
        self.workflow_tabs.setElideMode(Qt.ElideRight)
        self.workflow_tabs.currentChanged.connect(self._workflow_tab_changed)
        self.workflow_tabs.tabBar().setExpanding(True)
        self.workflow_tabs.tabBar().setUsesScrollButtons(True)
        self.workflow_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        self.workflow_tabs.setMinimumHeight(0)
        set_tooltip(self.workflow_tabs, "Switch between the main workflow areas of the GUI. Ctrl+1..7 switches sections.")
        set_tooltip(self.workflow_tabs.tabBar(), "Switch between the main workflow areas of the GUI. Ctrl+1..7 switches sections.")
        self.workspace_page = self._build_workspace_page()
        self.runs_page = self._build_runs_page()
        self.assets_tab = AssetsTab(
            self._start_scan_for_target,
            self._load_entity_notes,
            self._save_entity_note,
            send_to_attacker=self._send_asset_to_attacker,
            attacker_action_types=self._attacker_action_types,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
        self.assets_tab.setMinimumHeight(0)
        self.attacker_page = self._build_attacker_page()
        self.attacker_page.setMinimumHeight(0)
        self.output_tab = OutputTab(
            self._save_finding_state,
            self._open_local_path,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
            load_manual_findings=self._load_manual_findings,
            save_manual_findings=self._save_manual_findings,
            report_exports_enabled=self._reports_extension_enabled(),
        )
        self.output_tab.setMinimumHeight(0)
        self.configuration_tab = ConfigurationTab(
            self.store,
            self._profiles_changed,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
        self.configuration_tab.setMinimumHeight(0)
        self.extensions_tab = ExtensionsTab(
            self.extension_store,
            self._apply_theme_manifest,
            self._open_local_path,
            on_extensions_changed=self._sync_extension_tabs,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
        self.extensions_tab.setMinimumHeight(0)
        self.settings_page = self._build_settings_page()
        for key, page in (
            ("workspaces", self.workspace_page),
            ("runs", self.runs_page),
            ("assets", self.assets_tab),
            ("attacker", self.attacker_page),
            ("findings", self.output_tab),
            ("extensions", self.extensions_tab),
            ("settings", self.settings_page),
        ):
            self._page_indices[key] = self.workflow_tabs.addTab(page, self._workflow_label_for_key(key))
        self._sync_extension_tabs()
        root.addWidget(self.workflow_tabs, 1)
        self.setCentralWidget(central)

    def _build_workspace_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        content_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (1, 2, 1))
        self.workspace_content_split = content_split
        self.workspace_overview_split = content_split
        self._register_splitter(self.workspace_content_split, "workspace_overview_split")
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(PAGE_SECTION_SPACING)
        left_top_panel = QWidget()
        left_top_layout = QVBoxLayout(left_top_panel)
        left_top_layout.setContentsMargins(0, 0, 0, 0)
        left_top_layout.setSpacing(PAGE_SECTION_SPACING)
        self.workspace_list = configure_scroll_surface(QListWidget(left_panel))
        self.workspace_list.setObjectName("sidebarList")
        self.workspace_list.currentRowChanged.connect(self._workspace_selected)
        self.engagement_list = self.workspace_list
        self.workspace_list.setEnabled(False)
        self.workspace_list.hide()
        set_tooltip(self.workspace_list, "Shows the active project for this session. Switch active project from Settings.")
        engagement_buttons = FlowButtonRow()
        self.new_workspace_button = QPushButton("New Project")
        self.new_workspace_button.clicked.connect(self._new_workspace)
        self.edit_workspace_button = QPushButton("Edit")
        self.edit_workspace_button.clicked.connect(self._edit_selected_workspace)
        self.open_workspace_button = QPushButton("Open")
        self.open_workspace_button.clicked.connect(self._switch_to_selected_workspace)
        self.no_workspace_button = QPushButton("Ad-Hoc")
        self.no_workspace_button.clicked.connect(self._switch_to_no_workspace)
        self.delete_workspace_button = QPushButton("Delete")
        self.delete_workspace_button.clicked.connect(self._delete_selected_workspace)
        self.new_engagement_button = self.new_workspace_button
        self.edit_engagement_button = self.edit_workspace_button
        self.delete_engagement_button = self.delete_workspace_button
        style_button(self.new_workspace_button)
        style_button(self.edit_workspace_button, role="secondary")
        style_button(self.open_workspace_button, role="secondary")
        style_button(self.no_workspace_button, role="secondary")
        style_button(self.delete_workspace_button, role="secondary")
        engagement_buttons.addWidget(self.new_workspace_button)
        engagement_buttons.addWidget(self.edit_workspace_button)
        engagement_buttons.addWidget(self.open_workspace_button)
        engagement_buttons.addWidget(self.no_workspace_button)
        engagement_buttons.addWidget(self.delete_workspace_button)
        engagement_buttons.setVisible(False)
        for button in (
            self.new_workspace_button,
            self.edit_workspace_button,
            self.open_workspace_button,
            self.no_workspace_button,
            self.delete_workspace_button,
        ):
            button.setEnabled(False)
        left_top_layout.addWidget(engagement_buttons)
        self.workspace_summary = configure_scroll_surface(QTextEdit())
        self.workspace_summary.setObjectName("richBrief")
        self.workspace_summary.setReadOnly(True)
        self.workspace_summary.setMinimumHeight(280)
        self.engagement_summary = self.workspace_summary
        set_tooltip(self.workspace_summary, "Read-only project details for the selected saved project.")
        workspace_summary_panel, _workspace_summary_title, _workspace_summary_summary = build_inspector_panel(
            "Project Details",
            self.workspace_summary,
        )
        left_layout.addWidget(left_top_panel)
        left_layout.addWidget(workspace_summary_panel, 1)
        content_split.addWidget(left_panel)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(PAGE_SECTION_SPACING)
        self.workspace_center_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (1, 1))
        self._register_splitter(self.workspace_center_split, "workspace_center_split")
        self.overview_general_panel = OverviewGeneralPanel()
        general_panel, _general_title, _general_summary = build_inspector_panel(
            "General",
            self.overview_general_panel,
            surface=SURFACE_PRIMARY,
        )
        workspace_runs = QWidget()
        workspace_runs_layout = QVBoxLayout(workspace_runs)
        workspace_runs_layout.setContentsMargins(0, 0, 0, 0)
        workspace_runs_layout.setSpacing(PAGE_SECTION_SPACING)
        self.workspace_run_model = MappingTableModel(
            [("Scan Name", "scan_name"), ("State", "state"), ("Current Task", "current_task"), ("Progress", lambda row: row.get("progress") or "--")]
        )
        self.workspace_run_table = configure_scroll_surface(QTableView())
        self.workspace_run_table.setObjectName("dataGrid")
        self.workspace_run_table.setModel(self.workspace_run_model)
        ensure_table_defaults(
            self.workspace_run_table,
            column_policies=(
                {"mode": "stretch", "min": 220},
                {"mode": "content", "min": 110, "max": 150},
                {"mode": "stretch", "min": 280},
                {"mode": "mixed", "min": 170, "width": 190},
            ),
            minimum_rows=11,
        )
        self.workspace_run_table.clicked.connect(self._workspace_run_selected)
        self.workspace_run_table.doubleClicked.connect(self._focus_output_tab)
        self.workspace_run_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.workspace_run_table.customContextMenuRequested.connect(
            lambda point, view=self.workspace_run_table: self._open_run_context_menu(view, point)
        )
        set_tooltip(self.workspace_run_table, "Select a run to inspect it, or double-click to jump into Findings.")
        workspace_runs_layout.addWidget(self.workspace_run_table, 1)
        runs_panel, _runs_title, _runs_summary = build_table_section(
            "Scans Overview",
            workspace_runs,
            surface=SURFACE_PRIMARY,
        )
        self.workspace_center_split.addWidget(general_panel)
        self.workspace_center_split.addWidget(runs_panel)
        center_layout.addWidget(self.workspace_center_split, 1)
        content_split.addWidget(center_panel)

        self.overview_checklist_panel = OverviewChecklistPanel()
        self.overview_checklist_panel.add_requested.connect(self._add_overview_checklist_item)
        self.overview_checklist_panel.toggled.connect(self._toggle_overview_checklist_item)
        self.overview_checklist_panel.delete_requested.connect(self._delete_overview_checklist_item)

        notes_panel, notes_layout = build_surface_frame(
            object_name="sectionPanel",
            surface=SURFACE_SECONDARY,
            padding=PANEL_CONTENT_PADDING,
            spacing=PAGE_SECTION_SPACING,
        )
        notes_header = QLabel("Notes")
        notes_header.setObjectName("sectionTitle")
        self.overview_notes_edit = configure_scroll_surface(QPlainTextEdit())
        self.overview_notes_edit.setObjectName("consoleText")
        self.overview_notes_edit.setPlaceholderText("Operator notes for this engagement...")
        self.overview_notes_edit.textChanged.connect(self._handle_overview_notes_changed)
        notes_layout.addWidget(notes_header)
        notes_layout.addWidget(self.overview_notes_edit, 1)

        self.workspace_inspector_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (1, 1))
        self._register_splitter(self.workspace_inspector_split, "workspace_inspector_split")
        self.workspace_inspector_split.addWidget(self.overview_checklist_panel)
        self.workspace_inspector_split.addWidget(notes_panel)

        content_split.addWidget(self.workspace_inspector_split)
        layout.addWidget(content_split, 1)
        return page

    def _build_runs_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("scannerPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        self.run_filter_grid = QGridLayout()
        self.run_filter_grid.setHorizontalSpacing(PAGE_SECTION_SPACING)
        self.run_filter_grid.setVerticalSpacing(PAGE_SECTION_SPACING)
        self.run_search_edit = QLineEdit()
        self.run_search_edit.setPlaceholderText("Search runs, targets, or current task")
        self.run_search_edit.textChanged.connect(self._sync_run_table)
        self.run_state_filter = QComboBox()
        self.run_state_filter.addItems(["All States", "running", "failed", "blocked", "paused", "completed", "cancelled"])
        self.run_state_filter.currentTextChanged.connect(self._sync_run_table)
        self.start_scan_button = QPushButton("+")
        self.start_scan_button.setObjectName("scannerStartButton")
        self.start_scan_button.clicked.connect(self._start_scan)
        self.start_scan_button.setToolTip("Start a new scan in the active project or ad-hoc session. Shortcut: Ctrl+N.")
        self.start_scan_button.setAccessibleName("Launch New Scan")
        self.start_scan_button.setMinimumSize(24, 24)
        self.start_scan_button.setMaximumSize(28, 28)
        self.start_scan_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        set_tooltips(
            (
                (self.run_search_edit, "Filter the scan queue by scan name, targets, or current task."),
                (self.run_state_filter, "Show only runs in the selected state."),
            )
        )
        self.run_filter_controls: list[tuple[QLabel, QWidget]] = [
            (QLabel("Search"), self.run_search_edit),
            (QLabel("State"), self.run_state_filter),
        ]
        run_toolbar, run_toolbar_layout = build_surface_frame(
            surface=SURFACE_FLAT,
            padding=0,
            spacing=PAGE_CARD_SPACING,
        )
        run_toolbar.setObjectName("toolbarStrip")
        run_toolbar_layout.setContentsMargins(0, 0, 0, 0)
        run_toolbar_layout.addLayout(self.run_filter_grid)
        self.run_results_label = QLabel("Showing 0/0 runs")
        self.run_results_label.setObjectName("helperText")
        self.run_results_label.setWordWrap(True)
        self._arrange_run_filters(self.width())
        self.run_model = MappingTableModel(
            [
                ("Scan Name", "scan_name"),
                ("State", "state"),
                ("Elapsed", lambda row: format_duration(row.get("elapsed_seconds"))),
                ("ETA", lambda row: format_duration(row.get("eta_seconds"))),
                ("Current Task", "current_task"),
                ("Target Summary", lambda row: row.get("target_summary") or ""),
                ("Findings", "finding_count"),
            ]
        )
        self.run_table = configure_scroll_surface(QTableView())
        self.run_table.setObjectName("dataGrid")
        self.run_table.setModel(self.run_model)
        ensure_table_defaults(
            self.run_table,
            column_policies=(
                {"mode": "stretch", "min": 220},
                {"mode": "content", "min": 110, "max": 150},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "content", "min": 90, "max": 110},
                {"mode": "stretch", "min": 240},
                {"mode": "stretch", "min": 240},
                {"mode": "content", "min": 90, "max": 110},
            ),
            minimum_rows=10,
        )
        self.run_table.clicked.connect(self._run_selected)
        self.run_table.doubleClicked.connect(self._focus_output_tab)
        self.run_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.run_table.customContextMenuRequested.connect(
            lambda point, view=self.run_table: self._open_run_context_menu(view, point)
        )
        set_tooltip(self.run_table, "Select a scan to inspect it, right-click for controls, or double-click to open it in Findings.")
        self.scanner_panel = ScannerPanel(layout_loader=self._load_ui_layout, layout_saver=self._save_ui_layout)
        self.scanner_panel.set_context_menu_handler(self._handle_scanner_context_menu)
        self.runs_body_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (3, 4))
        self._register_splitter(self.runs_body_split, "runs_body_split")
        run_queue_panel, _queue_title, _queue_summary = build_table_section(
            "Scan Queue",
            self.run_table,
            summary_text="",
            surface=SURFACE_PRIMARY,
            toolbar=run_toolbar,
        )
        scanner_detail_panel, _scanner_title, _scanner_summary = build_inspector_panel(
            "Scanner Detail",
            self.scanner_panel,
            summary_text="",
            surface=SURFACE_PRIMARY,
        )
        self.runs_body_split.addWidget(run_queue_panel)
        self.runs_body_split.addWidget(scanner_detail_panel)
        layout.addWidget(self.runs_body_split, 1)
        return page

    def _build_attacker_page(self) -> QWidget:
        self.attacker_tab = AttackerTab(
            self._load_attack_workspaces,
            self._save_attack_workspaces,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
        self.attacker_tab.set_proxy_url(self.proxy_settings.effective_attacker_proxy_url())
        return self.attacker_tab

    def _build_performance_slider_row(
        self,
        label: str,
        slider: QSlider,
        value_label: QLabel,
        tooltip: str,
    ) -> QWidget:
        row = QFrame()
        row.setObjectName("settingsControlGroup")
        row_layout = QVBoxLayout(row)
        row_layout.setContentsMargins(12, 10, 12, 10)
        row_layout.setSpacing(8)
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        name = QLabel(label)
        name.setObjectName("settingsFieldLabel")
        slider.setOrientation(Qt.Horizontal)
        slider.setToolTip(tooltip)
        slider.setMinimumHeight(28)
        value_label.setMinimumWidth(72)
        value_label.setObjectName("monoLabel")
        header_layout.addWidget(name)
        header_layout.addStretch(1)
        header_layout.addWidget(value_label)
        helper = QLabel(tooltip)
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        row_layout.addWidget(header)
        row_layout.addWidget(helper)
        row_layout.addWidget(slider)
        return row

    def _build_settings_card(
        self,
        title: str,
        *,
        summary: str = "",
        danger: bool = False,
    ) -> tuple[Card, QVBoxLayout]:
        card = Card(
            title,
            summary=summary,
            object_name="settingsDangerCard" if danger else "settingsCard",
            padding=18,
            spacing=12,
        )
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        return card, card.content_layout

    def _build_settings_divider(self) -> QFrame:
        divider = QFrame()
        divider.setObjectName("settingsDivider")
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Plain)
        return divider

    def _show_settings_row(self, row: int) -> None:
        if row < 0:
            return
        if not hasattr(self, "settings_page_stack"):
            return
        if row >= self.settings_page_stack.count():
            return
        self.settings_page_stack.setCurrentIndex(row)

    def _show_settings_section(self, key: str) -> None:
        if not hasattr(self, "settings_nav_list"):
            return
        row = getattr(self, "_settings_page_indices", {}).get(key, -1)
        if row < 0:
            return
        if self.settings_nav_list.currentRow() == row:
            self._show_settings_row(row)
            return
        self.settings_nav_list.blockSignals(True)
        self.settings_nav_list.setCurrentRow(row)
        self.settings_nav_list.blockSignals(False)
        self._show_settings_row(row)

    def _build_settings_content_page(self, *widgets: QWidget) -> QScrollArea:
        scroll = configure_scroll_surface(QScrollArea())
        scroll.setObjectName("settingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        content.setObjectName("settingsContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, PAGE_CARD_SPACING, 0)
        content_layout.setSpacing(18)
        for widget in widgets:
            content_layout.addWidget(widget)
        content_layout.addStretch(1)
        scroll.setWidget(content)
        return scroll

    def _add_settings_page(self, key: str, title: str, page: QWidget) -> None:
        self.settings_nav_list.addItem(QListWidgetItem(title))
        self._settings_page_indices[key] = self.settings_page_stack.addWidget(page)

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.settings_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (1, 4))
        self._register_splitter(self.settings_split, "settings_split")

        rail = QFrame()
        rail.setObjectName("sidebarPanel")
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        rail_layout.setSpacing(PAGE_SECTION_SPACING)
        rail_title = QLabel("Settings")
        rail_title.setObjectName("sectionTitle")
        self.settings_nav_list = QListWidget()
        self.settings_nav_list.setObjectName("sidebarList")
        self.settings_nav_list.currentRowChanged.connect(self._show_settings_row)
        rail_layout.addWidget(rail_title)
        rail_layout.addWidget(self.settings_nav_list, 1)
        self.settings_split.addWidget(rail)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        self.settings_page_stack = QStackedWidget()
        self.settings_page_stack.setObjectName("settingsPageStack")
        self._settings_page_indices: dict[str, int] = {}

        self._settings_section_widgets: list[QWidget] = []

        performance_panel, performance_layout = self._build_settings_card(
            "Resource Limits",
            summary="Keep worker processes inside the CPU and memory envelope you choose.",
        )
        performance_panel.setObjectName("settingsPrimaryCard")
        self._settings_section_widgets.append(performance_panel)
        self.performance_guard_enabled_checkbox = QCheckBox("Limit AttackCastle CPU and memory usage")
        self.performance_guard_enabled_checkbox.setChecked(self.performance_guard_settings.enabled)
        self.performance_guard_enabled_checkbox.toggled.connect(lambda _checked: self._persist_performance_guard_settings())
        self.performance_guard_status_label = QLabel(
            "Defaults are max. Lower a limit to have AttackCastle throttle, pause queued work, and gracefully cancel one running task if pressure persists."
        )
        self.performance_guard_status_label.setObjectName("infoBanner")
        self.performance_guard_status_label.setWordWrap(True)
        self.performance_cpu_slider = QSlider(Qt.Horizontal)
        self.performance_cpu_slider.setRange(1, 100)
        self.performance_cpu_slider.setValue(int(self.performance_guard_settings.cpu_limit_percent))
        self.performance_cpu_value_label = QLabel("")
        self.performance_cpu_slider.valueChanged.connect(lambda _value: self._persist_performance_guard_settings())
        self.performance_memory_slider = QSlider(Qt.Horizontal)
        self.performance_memory_slider.setRange(1, 100)
        self.performance_memory_slider.setValue(int(self.performance_guard_settings.memory_limit_percent))
        self.performance_memory_value_label = QLabel("")
        self.performance_memory_slider.valueChanged.connect(lambda _value: self._persist_performance_guard_settings())
        self.performance_test_throttle_button = QPushButton("Apply Limits To Running Scans")
        style_button(self.performance_test_throttle_button)
        self.performance_test_throttle_button.clicked.connect(lambda: self._throttle_live_runs("operator_requested"))
        set_tooltips(
            (
                (
                    self.performance_guard_enabled_checkbox,
                    "Enable process-scoped CPU and memory limits for AttackCastle worker and tool processes.",
                ),
                (
                    self.performance_test_throttle_button,
                    "Immediately send the current resource limits to all live running scans.",
                ),
            )
        )
        performance_layout.addWidget(self.performance_guard_enabled_checkbox)
        performance_layout.addWidget(self.performance_guard_status_label)
        performance_layout.addWidget(self._build_settings_divider())
        performance_layout.addWidget(
            self._build_performance_slider_row(
                "CPU limit",
                self.performance_cpu_slider,
                self.performance_cpu_value_label,
                "Maximum percentage of total system CPU capacity AttackCastle should use.",
            )
        )
        performance_layout.addWidget(
            self._build_performance_slider_row(
                "Memory limit",
                self.performance_memory_slider,
                self.performance_memory_value_label,
                "Maximum percentage of total system RAM AttackCastle should use.",
            )
        )
        performance_layout.addWidget(self._build_settings_divider())
        performance_layout.addWidget(self.performance_test_throttle_button)
        self._add_settings_page("resources", "Resource Limits", self._build_settings_content_page(performance_panel))
        self._add_settings_page("profiles", "Profiles", self.configuration_tab)

        proxy_panel, proxy_layout = self._build_settings_card(
            "Proxy",
            summary="Route Scanner and Attacker HTTP traffic through a shared or function-specific proxy.",
        )
        self._settings_section_widgets.append(proxy_panel)
        self.proxy_all_traffic_checkbox = QCheckBox("Proxy All AttackCastle Traffic")
        self.proxy_global_url_edit = QLineEdit()
        self.proxy_global_url_edit.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_scanner_enabled_checkbox = QCheckBox("Use scanner-specific proxy")
        self.proxy_scanner_url_edit = QLineEdit()
        self.proxy_scanner_url_edit.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_attacker_enabled_checkbox = QCheckBox("Use attacker-specific proxy")
        self.proxy_attacker_url_edit = QLineEdit()
        self.proxy_attacker_url_edit.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_settings_status_label = QLabel("")
        self.proxy_settings_status_label.setObjectName("helperText")
        self.proxy_settings_status_label.setWordWrap(True)
        for edit in (
            self.proxy_global_url_edit,
            self.proxy_scanner_url_edit,
            self.proxy_attacker_url_edit,
        ):
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        set_tooltips(
            (
                (self.proxy_all_traffic_checkbox, "Use the global proxy URL for both Scanner launches and Attacker HTTP replay."),
                (self.proxy_global_url_edit, "Shared HTTP(S) proxy URL, for example a Burp listener."),
                (self.proxy_scanner_enabled_checkbox, "Use a Scanner-specific proxy when the global all-traffic proxy is off."),
                (self.proxy_scanner_url_edit, "Proxy URL applied to newly launched, resumed, and retried Scanner work."),
                (self.proxy_attacker_enabled_checkbox, "Use an Attacker-specific proxy when the global all-traffic proxy is off."),
                (self.proxy_attacker_url_edit, "Proxy URL applied to Attacker HTTP replay requests."),
            )
        )
        proxy_form = QWidget()
        proxy_form_layout = QFormLayout(proxy_form)
        apply_form_layout_defaults(proxy_form_layout)
        proxy_form_layout.addRow(self.proxy_all_traffic_checkbox)
        proxy_form_layout.addRow("Global proxy URL", self.proxy_global_url_edit)
        proxy_form_layout.addRow(self._build_settings_divider())
        proxy_form_layout.addRow(self.proxy_scanner_enabled_checkbox)
        proxy_form_layout.addRow("Scanner proxy URL", self.proxy_scanner_url_edit)
        proxy_form_layout.addRow(self._build_settings_divider())
        proxy_form_layout.addRow(self.proxy_attacker_enabled_checkbox)
        proxy_form_layout.addRow("Attacker proxy URL", self.proxy_attacker_url_edit)
        proxy_layout.addWidget(proxy_form)
        proxy_layout.addWidget(self.proxy_settings_status_label)
        for signal in (
            self.proxy_all_traffic_checkbox.toggled,
            self.proxy_global_url_edit.textChanged,
            self.proxy_scanner_enabled_checkbox.toggled,
            self.proxy_scanner_url_edit.textChanged,
            self.proxy_attacker_enabled_checkbox.toggled,
            self.proxy_attacker_url_edit.textChanged,
        ):
            signal.connect(lambda *_args: self._persist_proxy_settings())
        self._add_settings_page("proxy", "Proxy", self._build_settings_content_page(proxy_panel))

        paths_panel, paths_layout = self._build_settings_card(
            "Metadata Paths",
            summary="Local files used for profiles, project metadata, audit state, and run registry data.",
        )
        self._settings_section_widgets.append(paths_panel)
        self.profile_store_path_label = QLabel("")
        self.profile_store_path_label.setObjectName("monoLabel")
        self.profile_store_path_label.setProperty("variant", "path")
        self.profile_store_path_label.setWordWrap(True)
        open_profiles = QPushButton("Open Profile Store Folder")
        style_button(open_profiles, role="secondary")
        open_profiles.clicked.connect(lambda: self._open_local_path(str(self.store.path.parent)))
        self.workspace_store_path_label = QLabel("")
        self.workspace_store_path_label.setObjectName("monoLabel")
        self.workspace_store_path_label.setProperty("variant", "path")
        self.workspace_store_path_label.setWordWrap(True)
        open_workspace = QPushButton("Open Project Store Folder")
        style_button(open_workspace, role="secondary")
        open_workspace.clicked.connect(lambda: self._open_local_path(str(self.workspace_store.path.parent)))
        about_button = QPushButton("About AttackCastle")
        style_button(about_button, role="secondary")
        about_button.clicked.connect(self._show_about)
        set_tooltips(
            (
                (open_profiles, "Open the folder that stores saved GUI profiles."),
                (open_workspace, "Open the folder that stores project metadata, audit, and run registry state."),
                (about_button, "Show a short description of the GUI."),
            )
        )
        profile_label = QLabel("Profile store path")
        profile_label.setObjectName("settingsFieldLabel")
        workspace_store_label = QLabel("Project store path")
        workspace_store_label.setObjectName("settingsFieldLabel")
        paths_layout.addWidget(profile_label)
        paths_layout.addWidget(self.profile_store_path_label)
        paths_layout.addWidget(open_profiles)
        paths_layout.addWidget(self._build_settings_divider())
        paths_layout.addWidget(workspace_store_label)
        paths_layout.addWidget(self.workspace_store_path_label)
        paths_layout.addWidget(open_workspace)
        self._add_settings_page("paths", "Metadata Paths", self._build_settings_content_page(paths_panel))

        store_panel, store_layout = self._build_settings_card(
            "Storage & Utilities",
            summary="Application shortcuts and supporting actions.",
        )
        self._settings_section_widgets.append(store_panel)
        self.shortcut_summary_label = QLabel(
            "Shortcuts: Ctrl+1..7 navigate workflow areas, Ctrl+N new scan, / focus search, Ctrl+F findings search, Ctrl+P pause/resume, Ctrl+R retry, Ctrl+O open artifact or run folder."
        )
        self.shortcut_summary_label.setObjectName("infoBanner")
        self.shortcut_summary_label.setWordWrap(True)
        store_layout.addWidget(self.shortcut_summary_label)
        store_layout.addWidget(about_button)
        self._add_settings_page("storage", "Storage & Utilities", self._build_settings_content_page(store_panel))

        danger_panel, danger_layout = self._build_settings_card(
            "Danger Zone",
            summary="Destructive project cleanup actions live here deliberately.",
            danger=True,
        )
        self._settings_section_widgets.append(danger_panel)
        self.danger_zone_status_label = QLabel("No project deletion is currently armed.")
        self.danger_zone_status_label.setObjectName("attentionBanner")
        self.danger_zone_status_label.setProperty("tone", "alert")
        self.danger_zone_status_label.setWordWrap(True)
        self.delete_active_workspace_data_button = QPushButton("Delete This Project (and All Its Data)")
        self.delete_active_workspace_data_button.clicked.connect(self._delete_active_workspace_and_data)
        self.delete_all_workspaces_data_button = QPushButton("Delete All Projects (and All Data)")
        self.delete_all_workspaces_data_button.clicked.connect(self._delete_all_workspaces_and_data)
        style_button(self.delete_active_workspace_data_button, role="danger")
        style_button(self.delete_all_workspaces_data_button, role="danger")
        set_tooltips(
            (
                (
                    self.delete_active_workspace_data_button,
                    "Permanently delete the active project, its tracked runs, and the project home directory after confirmation.",
                ),
                (
                    self.delete_all_workspaces_data_button,
                    "Permanently delete every saved project, tracked run directory, and project-scoped GUI data after confirmation.",
                ),
            )
        )
        danger_actions = FlowButtonRow()
        danger_actions.addWidget(self.delete_active_workspace_data_button)
        danger_actions.addWidget(self.delete_all_workspaces_data_button)
        danger_layout.addWidget(self.danger_zone_status_label)
        danger_layout.addWidget(danger_actions)
        self._add_settings_page("danger", "Danger Zone", self._build_settings_content_page(danger_panel))

        right_layout.addWidget(self.settings_page_stack, 1)
        self.settings_split.addWidget(right)
        self.settings_nav_list.setCurrentRow(0)
        layout.addWidget(self.settings_split, 1)
        return page

    def _setup_shortcuts(self) -> None:
        for idx, key in enumerate(self._nav_order, start=1):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{idx}"), self)
            shortcut.activated.connect(lambda selected=key: self._navigate_to(selected))
        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self._start_scan)
        QShortcut(QKeySequence("/"), self).activated.connect(self._focus_active_search)
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self._focus_findings_search)
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self._retry_selected_run)
        QShortcut(QKeySequence("Ctrl+P"), self).activated.connect(self._toggle_pause_resume)
        QShortcut(QKeySequence("Ctrl+O"), self).activated.connect(self._open_context_path)

    def _workflow_label_for_key(self, key: str) -> str:
        labels = {
            "workspaces": "Overview",
            "runs": "Scanner",
            "assets": "Assets",
            "attacker": "Attacker",
            "findings": "Findings",
            "reports": "Reports",
            "profiles": "Profiles",
            "extensions": "Extensions",
            "settings": "Settings",
        }
        return labels.get(key, title_case_label(key))

    def _workflow_tab_changed(self, row: int) -> None:
        if 0 <= row < len(self._nav_order):
            return

    def _navigate_to(self, key: str) -> None:
        if key == "profiles":
            key = "settings"
            self._show_settings_section("profiles")
        if key not in self._page_indices:
            return
        self.workflow_tabs.setCurrentIndex(self._page_indices[key])

    def _sync_page_indices(self) -> None:
        self._page_indices = {}
        ordered: list[str] = []
        for index in range(self.workflow_tabs.count()):
            widget = self.workflow_tabs.widget(index)
            for key, page in (
                ("workspaces", self.workspace_page),
                ("runs", self.runs_page),
                ("assets", self.assets_tab),
                ("attacker", self.attacker_page),
                ("findings", self.output_tab),
                ("reports", self.reports_tab),
                ("extensions", self.extensions_tab),
                ("settings", self.settings_page),
            ):
                if page is not None and widget is page:
                    self._page_indices[key] = index
                    ordered.append(key)
                    break
        self._nav_order = ordered

    def _reports_extension_enabled(self) -> bool:
        record = self.extension_store.get_record(REPORTS_EXTENSION_ID)
        return bool(record is not None and record.is_valid and record.enabled and record.manifest is not None and "report" in record.capabilities)

    def _sync_extension_tabs(self) -> None:
        enabled = self._reports_extension_enabled()
        self.output_tab.set_report_exports_enabled(enabled)
        if enabled and self.reports_tab is None:
            self.reports_tab = ReportsTab(
                load_config=self._load_reports_config,
                save_config=self._save_reports_config,
                current_workspace_home=self._current_workspace_home,
                current_client_name=self._current_client_name,
                finding_states=self._current_finding_states,
                manual_findings=self._load_manual_findings,
                open_path=self._open_local_path,
                current_findings=self.output_tab.report_findings,
                layout_loader=self._load_ui_layout,
                layout_saver=self._save_ui_layout,
            )
            self.reports_tab.setMinimumHeight(0)
            insert_at = self._page_indices.get("extensions", self.workflow_tabs.count())
            self.workflow_tabs.insertTab(insert_at, self.reports_tab, self._workflow_label_for_key("reports"))
        elif not enabled and self.reports_tab is not None:
            index = self.workflow_tabs.indexOf(self.reports_tab)
            if index >= 0:
                self.workflow_tabs.removeTab(index)
            self.reports_tab.deleteLater()
            self.reports_tab = None
        self._sync_page_indices()
        if self.reports_tab is not None:
            self.reports_tab.set_snapshot(self._selected_snapshot())

    def _workspace_run_selected(self, index: QModelIndex) -> None:
        self._run_selected(index)

    def _sync_workspace_run_table(self) -> None:
        rows = []
        total = 0
        for snapshot in sorted(self._run_snapshots.values(), key=lambda item: (RUN_STATE_ORDER.get(item.state, 99), item.scan_name.lower())):
            row = {
                "run_id": snapshot.run_id,
                "scan_name": snapshot.scan_name,
                "state": snapshot.state,
                "current_task": snapshot.current_task,
                "progress": format_progress(snapshot.completed_tasks, snapshot.total_tasks),
            }
            rows.append(row)
        self.workspace_run_model.set_rows(rows)

    def _sync_general_overview(self) -> None:
        if not hasattr(self, "overview_general_panel"):
            return
        self.overview_general_panel.set_data(self._build_general_overview_data())

    def _build_general_overview_data(self) -> GeneralOverviewData:
        inventory_snapshot = self._workspace_inventory_snapshot(preferred_run_id=self._selected_run_id)
        findings = self._workspace_overview_findings()
        severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
        root_cause_counts: dict[str, int] = {}
        for row in findings:
            severity = str(row.get("effective_severity") or row.get("severity") or "info").strip().lower()
            if severity not in severity_counts:
                severity = "info"
            severity_counts[severity] += 1

            root_cause = str(row.get("root_cause") or row.get("category") or "Uncategorized").strip()
            root_cause = root_cause or "Uncategorized"
            root_cause_counts[root_cause] = root_cause_counts.get(root_cause, 0) + 1

        task_totals = self._workspace_task_counts()
        return GeneralOverviewData(
            total_assets=len(inventory_snapshot.assets) if inventory_snapshot is not None else 0,
            total_services=len(inventory_snapshot.services) if inventory_snapshot is not None else 0,
            total_endpoints=len(inventory_snapshot.endpoints) if inventory_snapshot is not None else 0,
            total_findings=len(findings),
            tasks_in_progress=task_totals[0],
            tasks_completed=task_totals[1],
            severity_counts=severity_counts,
            root_cause_counts=root_cause_counts,
        )

    def _workspace_overview_findings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        raw_manual_findings = self.workspace_store.load_manual_findings(self._active_workspace_id)
        manual_findings_by_run = raw_manual_findings if isinstance(raw_manual_findings, dict) else {}
        seen_run_ids: set[str] = set()
        for snapshot in self._run_snapshots.values():
            seen_run_ids.add(snapshot.run_id)
            merged_by_id: dict[str, dict[str, Any]] = {}
            anonymous_index = 0
            for finding in snapshot.findings:
                if not isinstance(finding, dict):
                    continue
                finding_id = str(finding.get("finding_id") or "").strip()
                key = finding_id or f"__snapshot_{snapshot.run_id}_{anonymous_index}"
                anonymous_index += 1
                merged_by_id[key] = dict(finding)
            for finding in manual_findings_by_run.get(snapshot.run_id, []):
                if not isinstance(finding, dict):
                    continue
                finding_id = str(finding.get("finding_id") or "").strip()
                if finding_id and finding.get("_removed"):
                    merged_by_id.pop(finding_id, None)
                elif finding_id:
                    merged_by_id[finding_id] = dict(finding)
            states = self._finding_states_by_run.get(snapshot.run_id, {})
            for finding in merged_by_id.values():
                row = dict(finding)
                finding_id = str(row.get("finding_id") or "").strip()
                state = states.get(finding_id)
                base_severity = str(row.get("severity") or "info").lower()
                row["effective_severity"] = (state.severity_override if state else "") or base_severity
                rows.append(row)
        for run_id, manual_findings in manual_findings_by_run.items():
            if run_id in seen_run_ids or not isinstance(manual_findings, list):
                continue
            states = self._finding_states_by_run.get(str(run_id), {})
            for finding in manual_findings:
                if not isinstance(finding, dict):
                    continue
                if finding.get("_removed"):
                    continue
                row = dict(finding)
                finding_id = str(row.get("finding_id") or "").strip()
                state = states.get(finding_id)
                base_severity = str(row.get("severity") or "info").lower()
                row["effective_severity"] = (state.severity_override if state else "") or base_severity
                rows.append(row)
        return rows

    def _workspace_task_counts(self) -> tuple[int, int]:
        in_progress_statuses = {"running", "in_progress", "started", "active"}
        completed_statuses = {"completed", "complete", "succeeded", "success", "done"}
        in_progress = 0
        completed = 0
        for snapshot in self._run_snapshots.values():
            task_rows = [row for row in snapshot.tasks if isinstance(row, dict)]
            if task_rows:
                for row in task_rows:
                    status = str(row.get("status") or row.get("state") or "").strip().lower()
                    if status in in_progress_statuses:
                        in_progress += 1
                    elif status in completed_statuses:
                        completed += 1
                continue
            completed += max(int(snapshot.completed_tasks or 0), 0)
            if str(snapshot.state or "").lower() == "running":
                in_progress += 1
        return in_progress, completed

    def _focus_active_search(self) -> None:
        current_index = self.workflow_tabs.currentIndex()
        current_key = self._nav_order[current_index] if 0 <= current_index < len(self._nav_order) else "workspaces"
        if current_key == "findings":
            self.output_tab.focus_search()
        elif current_key == "assets":
            self.assets_tab.focus_search()
        elif current_key == "runs":
            self.run_search_edit.setFocus()
            self.run_search_edit.selectAll()
        elif current_key == "workspaces":
            self.workspace_run_table.setFocus()

    def _focus_findings_search(self) -> None:
        self._navigate_to("findings")
        self.output_tab.focus_search()

    def _toggle_pause_resume(self) -> None:
        snapshot = self._selected_snapshot()
        if snapshot is None:
            return
        if snapshot.state == "paused":
            self._send_control_action("resume")
        else:
            self._send_control_action("pause")

    def _open_context_path(self) -> None:
        if self.workflow_tabs.currentWidget() is self.output_tab and self.output_tab.has_current_artifact():
            self.output_tab.open_current_artifact()
            return
        self._open_selected_run_folder()

    def _apply_initial_geometry(self, available_geometry: QRect | None = None) -> None:
        geometry = available_geometry
        if geometry is None:
            screen = self.screen() or QApplication.primaryScreen()
            geometry = screen.availableGeometry() if screen is not None else QRect()
        if geometry.isNull():
            self.resize(1560, 980)
            return
        width = self._fit_dimension(1560, geometry.width(), 0.96)
        height = self._fit_dimension(980, geometry.height(), 0.92)
        self.resize(width, height)
        frame = self.frameGeometry()
        frame.moveCenter(geometry.center())
        self.move(frame.topLeft())

    def _apply_restore_geometry(self, available_geometry: QRect | None = None) -> None:
        geometry = available_geometry
        if geometry is None:
            screen = self.screen() or QApplication.primaryScreen()
            geometry = screen.availableGeometry() if screen is not None else QRect()
        if geometry.isNull():
            self.resize(1440, 900)
            return
        width = self._fit_restore_dimension(1440, geometry.width(), 0.82, 820)
        height = self._fit_restore_dimension(900, geometry.height(), 0.82, 620)
        self.resize(width, height)
        frame = self.frameGeometry()
        frame.moveCenter(geometry.center())
        self.move(frame.topLeft())

    @staticmethod
    def _fit_dimension(default_value: int, available_value: int, ratio: float) -> int:
        if available_value <= 0:
            return default_value
        padded = max(int(available_value * ratio), available_value - 96)
        return max(1, min(default_value, padded))

    @staticmethod
    def _fit_restore_dimension(default_value: int, available_value: int, ratio: float, minimum_value: int) -> int:
        if available_value <= 0:
            return default_value
        return max(1, min(available_value, max(minimum_value, min(default_value, int(available_value * ratio)))))

    def _wrap_group(self, title: str, widget: QWidget) -> QWidget:
        group = QGroupBox(title)
        group.setObjectName("panelGroup" if title else "panelGroupUntitled")
        group_layout = QVBoxLayout(group)
        if title:
            group_layout.setContentsMargins(8, 10, 8, 8)
        else:
            group_layout.setContentsMargins(8, 8, 8, 8)
        group_layout.setSpacing(0)
        group_layout.addWidget(widget)
        return group

    def _apply_styles(self) -> None:
        self._apply_theme_manifest(self.extension_store.get_active_theme_manifest())

    def _apply_theme_manifest(self, manifest) -> None:
        tokens = manifest.theme.tokens if manifest is not None and manifest.theme is not None else None
        qss_append = manifest.theme.qss_append if manifest is not None and manifest.theme is not None else ""
        self.setStyleSheet(build_workstation_stylesheet(tokens=tokens, qss_append=qss_append))
        if hasattr(self, "assets_tab"):
            self.assets_tab.apply_theme(tokens)
        if hasattr(self, "header_status_badge"):
            refresh_widget_style(self.header_status_badge)
    def _profiles_changed(self, profiles: list[GuiProfile]) -> None:
        self._profiles = profiles
        if hasattr(self, "profile_store_path_label"):
            self._refresh_settings_page()

    def _show_message(self, title: str, message: str) -> None:
        QMessageBox.information(self, title, message)

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "About AttackCastle GUI",
            "AttackCastle GUI\n\nKali-native PySide6 operator project for launching, monitoring, comparing, and staging external assessment findings without changing CLI behavior.",
        )

    def _refresh_settings_page(self) -> None:
        if not hasattr(self, "profile_store_path_label"):
            return
        self.profile_store_path_label.setText(str(self.store.path))
        self.workspace_store_path_label.setText(str(self.workspace_store.path))
        self._sync_performance_guard_controls()
        self._sync_proxy_settings_controls()
        self._update_danger_zone_state()

    def _sync_proxy_settings_controls(self) -> None:
        if not hasattr(self, "proxy_all_traffic_checkbox"):
            return
        self._applying_proxy_settings = True
        try:
            self.proxy_all_traffic_checkbox.setChecked(self.proxy_settings.proxy_all_traffic)
            self.proxy_global_url_edit.setText(self.proxy_settings.global_proxy_url)
            self.proxy_scanner_enabled_checkbox.setChecked(self.proxy_settings.scanner_proxy_enabled)
            self.proxy_scanner_url_edit.setText(self.proxy_settings.scanner_proxy_url)
            self.proxy_attacker_enabled_checkbox.setChecked(self.proxy_settings.attacker_proxy_enabled)
            self.proxy_attacker_url_edit.setText(self.proxy_settings.attacker_proxy_url)
        finally:
            self._applying_proxy_settings = False
        self._sync_proxy_settings_state()

    def _proxy_settings_from_controls(self) -> GuiProxySettings:
        if not hasattr(self, "proxy_all_traffic_checkbox"):
            return self.proxy_settings
        return GuiProxySettings(
            proxy_all_traffic=self.proxy_all_traffic_checkbox.isChecked(),
            global_proxy_url=self.proxy_global_url_edit.text().strip(),
            scanner_proxy_enabled=self.proxy_scanner_enabled_checkbox.isChecked(),
            scanner_proxy_url=self.proxy_scanner_url_edit.text().strip(),
            attacker_proxy_enabled=self.proxy_attacker_enabled_checkbox.isChecked(),
            attacker_proxy_url=self.proxy_attacker_url_edit.text().strip(),
        )

    def _sync_proxy_settings_state(self) -> None:
        if not hasattr(self, "proxy_all_traffic_checkbox"):
            return
        proxy_all = self.proxy_all_traffic_checkbox.isChecked()
        self.proxy_scanner_enabled_checkbox.setEnabled(not proxy_all)
        self.proxy_scanner_url_edit.setEnabled(not proxy_all and self.proxy_scanner_enabled_checkbox.isChecked())
        self.proxy_attacker_enabled_checkbox.setEnabled(not proxy_all)
        self.proxy_attacker_url_edit.setEnabled(not proxy_all and self.proxy_attacker_enabled_checkbox.isChecked())
        scanner_proxy = self.proxy_settings.effective_scanner_proxy_url()
        attacker_proxy = self.proxy_settings.effective_attacker_proxy_url()
        scanner_text = scanner_proxy or "direct"
        attacker_text = attacker_proxy or "direct"
        self.proxy_settings_status_label.setText(
            f"Scanner traffic: {scanner_text} | Attacker traffic: {attacker_text}"
        )

    def _persist_proxy_settings(self) -> None:
        if self._applying_proxy_settings or not hasattr(self, "proxy_all_traffic_checkbox"):
            return
        self.proxy_settings = self._proxy_settings_from_controls()
        self.workspace_store.save_proxy_settings(self.proxy_settings)
        self._sync_proxy_settings_state()
        if hasattr(self, "attacker_tab"):
            self.attacker_tab.set_proxy_url(self.proxy_settings.effective_attacker_proxy_url())

    def _apply_proxy_settings_to_request(self, request: ScanRequest) -> None:
        proxy_url = self.proxy_settings.effective_scanner_proxy_url()
        request.profile.proxy_enabled = bool(proxy_url)
        request.profile.proxy_url = proxy_url

    def _performance_guard_from_controls(self) -> PerformanceGuardSettings:
        if not hasattr(self, "performance_guard_enabled_checkbox"):
            return self.performance_guard_settings
        return PerformanceGuardSettings.from_dict(
            {
                **self.performance_guard_settings.to_dict(),
                "enabled": self.performance_guard_enabled_checkbox.isChecked(),
                "cpu_limit_percent": self.performance_cpu_slider.value(),
                "memory_limit_percent": self.performance_memory_slider.value(),
            }
        )

    def _sync_performance_guard_controls(self) -> None:
        if not hasattr(self, "performance_cpu_value_label"):
            return
        self.performance_cpu_value_label.setText(f"{self.performance_cpu_slider.value()}%")
        self.performance_memory_value_label.setText(f"{self.performance_memory_slider.value()}%")
        self.performance_test_throttle_button.setEnabled(bool(self._live_running_snapshots()))
        self._performance_timer.setInterval(max(1000, int(self.performance_guard_settings.sample_interval_seconds) * 1000))

    def _persist_performance_guard_settings(self) -> None:
        self.performance_guard_settings = self._performance_guard_from_controls()
        save_performance_guard_settings(self.performance_guard_settings)
        self._sync_performance_guard_controls()
        self._send_resource_limit_update_to_live_runs()

    def _live_running_snapshots(self) -> list[RunSnapshot]:
        terminal_states = {"completed", "failed", "cancelled", "blocked"}
        rows: list[RunSnapshot] = []
        for snapshot in self._run_snapshots.values():
            process = self._run_processes.get(snapshot.run_id)
            if process is None or process.state() == QProcess.NotRunning:
                continue
            if str(snapshot.state or "").lower() in terminal_states:
                continue
            rows.append(snapshot)
        return rows

    def _check_performance_guard(self) -> None:
        settings = self.performance_guard_settings
        if not settings.enabled:
            return
        live_runs = self._live_running_snapshots()
        if not live_runs:
            self._resource_pressure_active = False
            return
        sample = self._system_usage_sampler.sample(self._live_running_process_ids())
        cpu_high = sample.cpu_percent is not None and sample.cpu_percent > settings.cpu_limit_percent
        memory_high = (
            sample.memory_used_percent is not None
            and sample.memory_used_percent > settings.memory_limit_percent
        )
        if not cpu_high and not memory_high:
            self.performance_guard_status_label.setText(
                self._resource_status_text(sample, "Within configured limits.")
            )
            if self._resource_pressure_active:
                self._resource_pressure_active = False
                self._send_resource_relief_to_live_runs(sample)
            return

        reasons: list[str] = []
        if cpu_high and sample.cpu_percent is not None:
            reasons.append(f"CPU {sample.cpu_percent:.1f}% > {settings.cpu_limit_percent}%")
        if memory_high and sample.memory_used_percent is not None:
            reasons.append(f"RAM {sample.memory_used_percent:.1f}% > {settings.memory_limit_percent}%")
        reason = ", ".join(reasons) or "resource_pressure"
        self._resource_pressure_active = True
        self._last_resource_action = f"Pressure detected: {reason}"
        self.performance_guard_status_label.setText(self._resource_status_text(sample, self._last_resource_action))
        self._send_resource_pressure_to_live_runs(sample, reason)

    def _resource_status_text(self, sample, action: str) -> str:  # noqa: ANN001
        cpu_text = "--" if sample.cpu_percent is None else f"{sample.cpu_percent:.1f}%"
        memory_text = "--" if sample.memory_used_percent is None else f"{sample.memory_used_percent:.1f}%"
        return (
            f"AttackCastle usage: CPU {cpu_text}, RAM {memory_text}, processes {sample.process_count}. "
            f"Limits: CPU {self.performance_guard_settings.cpu_limit_percent}%, RAM {self.performance_guard_settings.memory_limit_percent}%. "
            f"{action}"
        )

    def _live_running_process_ids(self) -> list[int]:
        pids: list[int] = []
        for snapshot in self._live_running_snapshots():
            process = self._run_processes.get(snapshot.run_id)
            if process is None or process.state() == QProcess.NotRunning:
                continue
            pid = int(process.processId() or 0)
            if pid > 0:
                pids.append(pid)
        return pids

    def _throttle_live_runs(self, reason: str = "operator_requested") -> None:
        settings = self.performance_guard_settings
        payload = settings.throttle_payload()
        payload["sample"] = {}
        live_runs = self._live_running_snapshots()
        if not live_runs:
            self.general_status.setText("No running scans to update.")
            self._sync_performance_guard_controls()
            return
        updated = self._write_resource_control_to_live_runs(
            "resource_limit_update",
            {"reason": reason, "limits": settings.to_dict(), "throttle": payload, "timestamp_monotonic": monotonic()},
            audit_action="control.resource_limits_updated",
            audit_summary="Resource limits updated",
        )
        if updated:
            self.general_status.setText(f"Resource limits sent to {updated} running scan(s).")
        self._sync_performance_guard_controls()

    def _send_resource_limit_update_to_live_runs(self) -> None:
        if not self._live_running_snapshots():
            return
        payload = {
            "reason": "settings_changed",
            "limits": self.performance_guard_settings.to_dict(),
            "throttle": self.performance_guard_settings.throttle_payload(),
            "timestamp_monotonic": monotonic(),
        }
        self._write_resource_control_to_live_runs(
            "resource_limit_update",
            payload,
            audit_action="control.resource_limits_updated",
            audit_summary="Resource limits updated",
            show_errors=False,
        )

    def _send_resource_pressure_to_live_runs(self, sample, reason: str) -> None:  # noqa: ANN001
        payload = {
            "reason": reason,
            "limits": self.performance_guard_settings.to_dict(),
            "throttle": self.performance_guard_settings.throttle_payload(),
            "sample": sample.as_dict(),
            "timestamp_monotonic": monotonic(),
        }
        updated = self._write_resource_control_to_live_runs(
            "resource_pressure",
            payload,
            audit_action="control.resource_pressure",
            audit_summary="Resource pressure detected",
            show_errors=False,
        )
        if updated:
            self.general_status.setText(f"Resource pressure sent to {updated} running scan(s).")

    def _send_resource_relief_to_live_runs(self, sample) -> None:  # noqa: ANN001
        payload = {
            "reason": "usage_below_limits",
            "limits": self.performance_guard_settings.to_dict(),
            "sample": sample.as_dict(),
            "timestamp_monotonic": monotonic(),
        }
        updated = self._write_resource_control_to_live_runs(
            "resource_relief",
            payload,
            audit_action="control.resource_relief",
            audit_summary="Resource pressure relieved",
            show_errors=False,
        )
        if updated:
            self.general_status.setText(f"Resource limits healthy for {updated} running scan(s).")

    def _write_resource_control_to_live_runs(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        audit_action: str,
        audit_summary: str,
        show_errors: bool = True,
    ) -> int:
        updated = 0
        for snapshot in self._live_running_snapshots():
            run_dir_text = str(snapshot.run_dir or "").strip()
            if not run_dir_text:
                continue
            try:
                RunStore.from_existing(Path(run_dir_text)).write_control(action, payload)
                updated += 1
                self._append_audit(
                    audit_action,
                    f"{audit_summary} for {snapshot.scan_name}",
                    run_id=snapshot.run_id,
                    workspace_id=snapshot.workspace_id,
                    details=payload,
                )
            except Exception as exc:  # noqa: BLE001
                if show_errors:
                    QMessageBox.warning(
                        self,
                        "Resource Limit Update Failed",
                        f"Could not update {snapshot.scan_name}.\n\n{exc}",
                    )
        return updated

    def _show_resource_limit_unmet_alert(self, key: str, scan_name: str, payload: dict[str, Any]) -> None:
        now = monotonic()
        last_alert = self._resource_unmet_alerts.get(key, 0.0)
        cooldown = float(self.performance_guard_settings.cooldown_seconds)
        if now - last_alert < cooldown:
            return
        self._resource_unmet_alerts[key] = now
        sample = payload.get("sample", {}) if isinstance(payload.get("sample"), dict) else {}
        limits = payload.get("limits", {}) if isinstance(payload.get("limits"), dict) else {}
        running_tasks = payload.get("running_tasks", [])
        cpu_text = sample.get("cpu_percent", "--")
        memory_text = sample.get("memory_used_percent", "--")
        cpu_limit = limits.get("cpu_limit_percent", self.performance_guard_settings.cpu_limit_percent)
        memory_limit = limits.get("memory_limit_percent", self.performance_guard_settings.memory_limit_percent)
        if isinstance(running_tasks, list) and running_tasks:
            task_text = ", ".join(str(item) for item in running_tasks[:4])
        else:
            task_text = "No cancellable running task was reported."
        QMessageBox.warning(
            self,
            "Resource Limit Still Exceeded",
            (
                "AttackCastle is still above your CPU/RAM limit after pausing all safe work.\n\n"
                f"Run: {scan_name}\n"
                f"Current CPU/RAM: {cpu_text}% / {memory_text}%\n"
                f"Configured limits: {cpu_limit}% CPU / {memory_limit}% RAM\n"
                f"Running work: {task_text}"
            ),
        )

    def _update_danger_zone_state(self) -> None:
        if not hasattr(self, "danger_zone_status_label"):
            return
        active_workspace = self._active_workspace()
        if active_workspace is None:
            self.danger_zone_status_label.setText(
                "No active project is selected. Switch into a project to enable single-project deletion, or delete all saved projects at once."
            )
        else:
            run_count = len(self.workspace_store.load_run_registry(active_workspace.workspace_id))
            self.danger_zone_status_label.setText(
                f"Active project '{active_workspace.name}' will remove {run_count} tracked run(s) and delete data rooted at {active_workspace.home_dir}."
            )
        self.delete_active_workspace_data_button.setEnabled(
            not self._switch_in_progress and active_workspace is not None
        )
        self.delete_all_workspaces_data_button.setEnabled(
            not self._switch_in_progress and bool(self._workspaces)
        )

    def _focus_health_panel(self, *_args: Any) -> None:
        self._navigate_to("runs")
        self.scanner_panel.focus_health()

    def _start_scan(self) -> None:
        workspace = self._active_workspace()
        if self._switch_in_progress:
            return
        dialog = StartScanDialog(
            self._profiles,
            workspace,
            available_extensions=self.extension_store.list_command_hook_extensions(),
            parent=self,
        )
        if dialog.exec() != QDialog.Accepted:
            return

        request = dialog.build_request()
        self.store.save_profile(request.profile)
        self._profiles = self.store.load()
        self.configuration_tab.reload_profiles(preferred_profile_name=request.profile.name)
        self._launch_request(request)
        self._append_audit(
            "scan.started",
            f"Launch requested for {request.scan_name}",
            workspace_id=request.workspace_id,
            details={"target_summary": summarize_target_input(request.target_input), "profile": request.profile.name},
        )
        self._refresh_dashboard()

    def _launch_request(self, request: ScanRequest) -> None:
        request.performance_guard = self.performance_guard_settings.to_dict()
        self._apply_proxy_settings_to_request(request)
        job_handle = tempfile.NamedTemporaryFile(prefix="attackcastle-gui-job-", suffix=".json", delete=False)
        job_file = Path(job_handle.name)
        job_handle.close()
        job_file.write_text(json.dumps(request.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        process = QProcess(self)
        process.setProgram(sys.executable)
        process.setArguments(["-m", "attackcastle.gui.worker_main", str(job_file)])
        process.readyReadStandardOutput.connect(lambda p=process: self._read_worker_stdout(p))
        process.readyReadStandardError.connect(lambda p=process: self._read_worker_stderr(p))
        process.finished.connect(lambda code, status, p=process: self._worker_finished(p, code, status))
        process.setProperty("workspace_id", request.workspace_id)
        self._process_buffers[process] = ""
        self._job_files[process] = job_file
        process.start()
        self.general_status.setText(f"Launching: {request.scan_name}")

    def _read_worker_stdout(self, process: QProcess) -> None:
        buffer = self._process_buffers.get(process, "")
        chunk = bytes(process.readAllStandardOutput()).decode("utf-8", errors="ignore")
        buffer += chunk
        lines = buffer.splitlines(keepends=False)
        if buffer and not buffer.endswith("\n"):
            self._process_buffers[process] = lines.pop() if lines else buffer
        else:
            self._process_buffers[process] = ""
        for line in lines:
            event = WorkerEvent.from_line(line)
            if event is not None:
                self._handle_worker_event(process, event)

    def _read_worker_stderr(self, process: QProcess) -> None:
        message = bytes(process.readAllStandardError()).decode("utf-8", errors="ignore").strip()
        if message:
            self.general_status.setText(message)

    def _handle_worker_event(self, process: QProcess, event: WorkerEvent) -> None:
        payload = event.payload
        if event.event == "worker.ready":
            run_dir = payload.get("run_dir")
            if isinstance(run_dir, str):
                snapshot = load_run_snapshot(Path(run_dir))
                snapshot.live_process = True
                self._run_snapshots[snapshot.run_id] = snapshot
                self._process_run_ids[process] = snapshot.run_id
                self._run_processes[snapshot.run_id] = process
                self._sync_run_registry_for_snapshot(snapshot)
                self._selected_run_id = snapshot.run_id
                self._sync_run_table()
                self._update_output_snapshot(snapshot.run_id)
                self._navigate_to("runs")
                self.scanner_panel.focus_tasks()
                self.general_status.setText(f"Running: {snapshot.scan_name}")
                self._append_audit("worker.ready", f"Worker ready for {snapshot.scan_name}", run_id=snapshot.run_id, workspace_id=snapshot.workspace_id)
        elif event.event == "worker.completed":
            self.general_status.setText(f"Completed: {payload.get('scan_name', 'scan')}")
            run_dir = payload.get("run_dir")
            if isinstance(run_dir, str):
                snapshot = load_run_snapshot(Path(run_dir))
                snapshot.live_process = False
                self._run_snapshots[snapshot.run_id] = snapshot
                self._sync_run_registry_for_snapshot(snapshot)
                self._selected_run_id = snapshot.run_id
                self._sync_run_table()
                self._update_output_snapshot(snapshot.run_id)
                self._append_audit("worker.completed", f"Completed {snapshot.scan_name}", run_id=snapshot.run_id, workspace_id=snapshot.workspace_id)
        elif event.event == "worker.paused":
            run_id = self._process_run_ids.get(process)
            if run_id and run_id in self._run_snapshots:
                snapshot = self._run_snapshots[run_id]
                snapshot.state = "paused"
                snapshot.pause_requested = True
                snapshot.resume_required = True
                snapshot.live_process = True
                self._sync_run_registry_for_snapshot(snapshot)
                self.general_status.setText(f"Paused: {snapshot.scan_name}")
                self._append_audit("worker.paused", f"Paused {snapshot.scan_name}", run_id=run_id, workspace_id=snapshot.workspace_id)
        elif event.event == "worker.resumed":
            run_id = self._process_run_ids.get(process)
            if run_id and run_id in self._run_snapshots:
                snapshot = self._run_snapshots[run_id]
                snapshot.state = "running"
                snapshot.pause_requested = False
                snapshot.resume_required = False
                snapshot.live_process = True
                self._sync_run_registry_for_snapshot(snapshot)
                self.general_status.setText(f"Running: {snapshot.scan_name}")
                self._append_audit("worker.resumed", f"Resumed {snapshot.scan_name}", run_id=run_id, workspace_id=snapshot.workspace_id)
        elif event.event == "worker.throttled":
            run_id = self._process_run_ids.get(process) or str(payload.get("run_id") or "")
            if run_id and run_id in self._run_snapshots:
                snapshot = self._run_snapshots[run_id]
                snapshot.state = "running"
                snapshot.live_process = True
                self._sync_run_registry_for_snapshot(snapshot)
                self.general_status.setText(f"Throttling active: {snapshot.scan_name}")
                self._append_audit(
                    "worker.throttled",
                    f"Throttling active for {snapshot.scan_name}",
                    run_id=run_id,
                    workspace_id=snapshot.workspace_id,
                    details=payload,
                )
        elif event.event == "worker.resource_pressure":
            run_id = self._process_run_ids.get(process) or str(payload.get("run_id") or "")
            if run_id and run_id in self._run_snapshots:
                snapshot = self._run_snapshots[run_id]
                snapshot.state = "running"
                snapshot.live_process = True
                self._sync_run_registry_for_snapshot(snapshot)
                reason = str(payload.get("reason") or "resource pressure")
                self._last_resource_action = f"Pressure active for {snapshot.scan_name}: {reason}"
                self.general_status.setText(f"Resource pressure: {snapshot.scan_name}")
                self.performance_guard_status_label.setText(self._last_resource_action)
                self._append_audit(
                    "worker.resource_pressure",
                    f"Resource pressure active for {snapshot.scan_name}",
                    run_id=run_id,
                    workspace_id=snapshot.workspace_id,
                    details=payload,
                )
        elif event.event == "worker.resource_relief":
            run_id = self._process_run_ids.get(process) or str(payload.get("run_id") or "")
            if run_id and run_id in self._run_snapshots:
                snapshot = self._run_snapshots[run_id]
                snapshot.state = "running"
                snapshot.live_process = True
                self._sync_run_registry_for_snapshot(snapshot)
                self._last_resource_action = f"Resource limits healthy for {snapshot.scan_name}."
                self.general_status.setText(f"Resource limits healthy: {snapshot.scan_name}")
                self.performance_guard_status_label.setText(self._last_resource_action)
                self._append_audit(
                    "worker.resource_relief",
                    f"Resource limits healthy for {snapshot.scan_name}",
                    run_id=run_id,
                    workspace_id=snapshot.workspace_id,
                    details=payload,
                )
        elif event.event == "worker.resource_limit_unmet":
            run_id = self._process_run_ids.get(process) or str(payload.get("run_id") or "")
            snapshot = self._run_snapshots.get(run_id) if run_id else None
            scan_name = snapshot.scan_name if snapshot is not None else str(payload.get("scan_name") or "run")
            workspace_id = snapshot.workspace_id if snapshot is not None else ""
            self.general_status.setText(f"Resource limit unmet: {scan_name}")
            self.performance_guard_status_label.setText(
                f"AttackCastle is still above the configured CPU/RAM limit for {scan_name}."
            )
            self._append_audit(
                "worker.resource_limit_unmet",
                f"Resource limit unmet for {scan_name}",
                run_id=run_id,
                workspace_id=workspace_id,
                details=payload,
            )
            self._show_resource_limit_unmet_alert(run_id or scan_name, scan_name, payload)
        elif event.event == "worker.error":
            message = str(payload.get("message", "Worker failed"))
            self.general_status.setText(message)
            self._append_audit("worker.error", message, run_id=str(payload.get("run_id") or ""))
            QMessageBox.critical(self, "Worker Error", message)
        else:
            snapshot = self._get_or_create_snapshot(payload)
            if snapshot is None:
                return
            if event.event in {"task.queued", "task.started", "task.waiting", "task.completed", "task.terminal"}:
                self._apply_task_event(snapshot, event.event, payload)
            elif event.event == "entity.upserted":
                self._apply_entity_event(snapshot, payload)
            elif event.event == "site_map.updated":
                self._apply_site_map_event(snapshot, payload)
            elif event.event == "task_result.recorded":
                result = payload.get("result", {})
                if isinstance(result, dict):
                    self._append_unique(snapshot.task_results, result, "task_id")
            elif event.event == "tool_execution.recorded":
                execution = payload.get("execution", {})
                if isinstance(execution, dict):
                    self._append_unique(snapshot.tool_executions, execution, "execution_id")
            elif event.event == "artifact.available":
                artifact_row = {
                    "path": payload.get("artifact_path", ""),
                    "kind": payload.get("kind", ""),
                    "source_tool": payload.get("source_tool", ""),
                    "caption": payload.get("caption", ""),
                }
                self._append_unique(snapshot.artifacts, artifact_row, "path")
                if any(payload.get(key) for key in ("artifact_id", "source_task_id", "source_execution_id")):
                    evidence_artifact_row = dict(artifact_row)
                    evidence_artifact_row.update(
                        {
                            "artifact_id": payload.get("artifact_id", ""),
                            "source_task_id": payload.get("source_task_id", ""),
                            "source_execution_id": payload.get("source_execution_id", ""),
                        }
                    )
                    self._append_unique(snapshot.evidence_artifacts, evidence_artifact_row, "path")
                if str(payload.get("kind")) == "web_screenshot":
                    self._append_unique(snapshot.screenshots, {
                        "path": payload.get("artifact_path", ""),
                        "caption": payload.get("caption", ""),
                        "source_tool": payload.get("source_tool", ""),
                    }, "path")
            elif event.event == "task.progress":
                snapshot.current_task = str(payload.get("adapter") or snapshot.current_task)
            if event.event in {"task.started", "task.progress"}:
                self.general_status.setText(str(payload.get("label") or payload.get("adapter") or event.event))
            self._refresh_snapshot_issue_state(snapshot)
            snapshot.live_process = process.state() != QProcess.NotRunning
            self._sync_run_registry_for_snapshot(snapshot)
            self._sync_run_table()
            self._update_output_snapshot(self._selected_run_id)
            if event.event in {"task.started", "task.completed", "task.terminal"}:
                self._append_audit(
                    event.event,
                    str(payload.get("label") or payload.get("task") or event.event),
                    run_id=snapshot.run_id,
                    workspace_id=snapshot.workspace_id,
                    details=payload,
                )
        self._refresh_dashboard()
        self._refresh_health_panel()

    def _get_or_create_snapshot(self, payload: dict[str, Any]) -> RunSnapshot | None:
        run_id = payload.get("run_id")
        run_dir = payload.get("run_dir")
        if not isinstance(run_id, str) or not run_id:
            return None
        existing = self._run_snapshots.get(run_id)
        if existing is not None:
            return existing
        if isinstance(run_dir, str) and run_dir and Path(run_dir).exists():
            snapshot = load_run_snapshot(Path(run_dir))
        else:
            snapshot = RunSnapshot(
                run_id=run_id,
                scan_name=str(payload.get("scan_name") or run_id),
                run_dir=str(run_dir or ""),
                state="running",
                elapsed_seconds=0.0,
                eta_seconds=None,
                current_task="Starting",
                total_tasks=int(payload.get("total_tasks") or 0),
                completed_tasks=0,
                workspace_id=str(payload.get("workspace_id") or payload.get("engagement_id") or ""),
                workspace_name=str(payload.get("workspace_name") or payload.get("engagement_name") or ""),
                target_input=str(payload.get("target_input") or ""),
                profile_name=str(payload.get("profile_name") or ""),
                live_process=True,
            )
        self._refresh_snapshot_issue_state(snapshot)
        self._run_snapshots[run_id] = snapshot
        return snapshot

    def _refresh_snapshot_issue_state(self, snapshot: RunSnapshot) -> None:
        issues = build_execution_issues(snapshot)
        issue_summary = summarize_execution_issues(snapshot, issues)
        snapshot.execution_issues = issues
        snapshot.execution_issues_summary = issue_summary
        snapshot.completeness_status = str(issue_summary.get("completeness_status") or "healthy")

    def _append_unique(self, rows: list[dict[str, Any]], row: dict[str, Any], key: str) -> None:
        value = str(row.get(key) or "")
        if not value:
            return
        for idx, existing in enumerate(rows):
            if str(existing.get(key) or "") == value:
                rows[idx] = row
                return
        rows.append(row)

    @staticmethod
    def _task_update_value_present(value: Any) -> bool:
        return value is not None and value != ""

    def _apply_task_event(self, snapshot: RunSnapshot, event_name: str, payload: dict[str, Any]) -> None:
        task_key = str(payload.get("task") or "")
        if not task_key:
            return
        detail = {
            key: value
            for key, value in {
                "reason": payload.get("reason"),
                "attempt": payload.get("attempt"),
                "error": payload.get("error"),
            }.items()
            if self._task_update_value_present(value)
        }
        row = {
            "key": task_key,
            "label": payload.get("label") or task_key,
            "status": payload.get("status") or event_name.replace("task.", ""),
            "started_at": payload.get("started_at") or "",
            "ended_at": payload.get("ended_at") or "",
        }
        if detail:
            row["detail"] = detail
        for idx, existing in enumerate(snapshot.tasks):
            if str(existing.get("key") or "") == task_key:
                merged = dict(existing)
                if detail:
                    merged_detail = dict(existing.get("detail") or {})
                    merged_detail.update(detail)
                    merged["detail"] = merged_detail
                merged.update({k: v for k, v in row.items() if self._task_update_value_present(v)})
                snapshot.tasks[idx] = merged
                break
        else:
            snapshot.tasks.append(row)
        snapshot.current_task = str(payload.get("label") or task_key)
        terminal = {"completed", "skipped", "failed", "blocked", "cancelled"}
        snapshot.completed_tasks = len(
            [item for item in snapshot.tasks if str(item.get("status") or "") in terminal]
        )
        status = str(payload.get("status") or row["status"])
        if status in {"failed", "blocked"}:
            snapshot.state = "failed"
        elif status == "cancelled":
            snapshot.state = "cancelled"
        else:
            snapshot.state = "running"
        self._refresh_snapshot_issue_state(snapshot)

    def _apply_entity_event(self, snapshot: RunSnapshot, payload: dict[str, Any]) -> None:
        entity_type = str(payload.get("entity_type") or "")
        entity = payload.get("entity", {})
        if not isinstance(entity, dict):
            return
        if entity_type == "asset":
            self._append_unique(snapshot.assets, entity, "asset_id")
        elif entity_type == "service":
            key = "service_id"
            self._append_unique(snapshot.services, entity, key)
        elif entity_type == "web_app":
            self._append_unique(snapshot.web_apps, entity, "webapp_id")
        elif entity_type == "technology":
            self._append_unique(snapshot.technologies, entity, "tech_id")
        elif entity_type == "endpoint":
            self._append_unique(snapshot.endpoints, entity, "endpoint_id")
        elif entity_type == "parameter":
            self._append_unique(snapshot.parameters, entity, "parameter_id")
        elif entity_type == "form":
            self._append_unique(snapshot.forms, entity, "form_id")
        elif entity_type == "login_surface":
            self._append_unique(snapshot.login_surfaces, entity, "login_surface_id")
        elif entity_type == "replay_request":
            self._append_unique(snapshot.replay_requests, entity, "replay_request_id")
        elif entity_type == "surface_signal":
            self._append_unique(snapshot.surface_signals, entity, "surface_signal_id")
        elif entity_type == "attack_path":
            self._append_unique(snapshot.attack_paths, entity, "attack_path_id")
        elif entity_type == "investigation_step":
            self._append_unique(snapshot.investigation_steps, entity, "investigation_step_id")
        elif entity_type == "playbook_execution":
            self._append_unique(snapshot.playbook_executions, entity, "playbook_execution_id")
        elif entity_type == "coverage_decision":
            self._append_unique(snapshot.coverage_decisions, entity, "coverage_decision_id")
        elif entity_type == "validation_result":
            self._append_unique(snapshot.validation_results, entity, "validation_result_id")
        elif entity_type == "coverage_gap":
            self._append_unique(snapshot.coverage_gaps, entity, "coverage_gap_id")
        elif entity_type == "evidence":
            self._append_unique(snapshot.evidence, entity, "evidence_id")
            artifact_path = str(entity.get("artifact_path") or "")
            if artifact_path:
                self._append_unique(
                    snapshot.artifacts,
                    {
                        "path": artifact_path,
                        "kind": entity.get("kind", ""),
                        "source_tool": entity.get("source_tool", ""),
                        "caption": entity.get("snippet", ""),
                    },
                    "path",
                )
            if str(entity.get("kind")) == "web_screenshot" and artifact_path:
                self._append_unique(
                    snapshot.screenshots,
                    {
                        "path": artifact_path,
                        "caption": entity.get("snippet", ""),
                        "source_tool": entity.get("source_tool", ""),
                    },
                    "path",
                )

    def _apply_site_map_event(self, snapshot: RunSnapshot, payload: dict[str, Any]) -> None:
        source_map = {
            "urls": "web.discovery.urls",
            "js_endpoints": "web.discovery.js_endpoints",
            "graphql_endpoints": "web.discovery.graphql_endpoints",
            "source_maps": "web.discovery.source_maps",
        }
        entity_id = str(payload.get("webapp_id") or "")
        for field, source in source_map.items():
            values = payload.get(field, [])
            if not isinstance(values, list):
                continue
            for item in values:
                url = str(item).strip()
                if not url:
                    continue
                self._append_unique(
                    snapshot.site_map,
                    {"source": source, "url": url, "entity_id": entity_id},
                    "url",
                )

    def _worker_finished(self, process: QProcess, exit_code: int, _status: QProcess.ExitStatus) -> None:
        job_file = self._job_files.pop(process, None)
        self._process_buffers.pop(process, None)
        run_id = self._process_run_ids.pop(process, "")
        if run_id:
            self._run_processes.pop(run_id, None)
            if run_id in self._run_snapshots:
                self._run_snapshots[run_id].live_process = False
                self._sync_run_registry_for_snapshot(self._run_snapshots[run_id])
        if job_file is not None:
            job_file.unlink(missing_ok=True)
        if exit_code != 0:
            self.general_status.setText(f"Worker exited with code {exit_code}")
        process.deleteLater()
        self._refresh_runs()

    def _refresh_runs(self) -> None:
        refreshed: dict[str, RunSnapshot] = {}
        registry_by_run = {entry.run_id: entry for entry in self._run_registry}
        for run_id, snapshot in list(self._run_snapshots.items()):
            refreshed_snapshot = snapshot
            if snapshot.run_dir:
                try:
                    refreshed_snapshot = load_run_snapshot(Path(snapshot.run_dir))
                except Exception:
                    refreshed_snapshot = snapshot
            if refreshed_snapshot is snapshot and snapshot.state not in {"completed", "failed", "cancelled"}:
                snapshot.elapsed_seconds = round(snapshot.elapsed_seconds + (self._refresh_timer.interval() / 1000.0), 1)
                self._refresh_snapshot_issue_state(snapshot)
            else:
                self._refresh_snapshot_issue_state(refreshed_snapshot)
            entry = registry_by_run.get(run_id)
            if entry is not None:
                self._apply_registry_overrides(refreshed_snapshot, entry)
            refreshed[run_id] = refreshed_snapshot
        self._run_snapshots = refreshed
        self._sync_run_table()
        self._update_output_snapshot(self._selected_run_id)
        self._refresh_context_panels()
        self._refresh_dashboard()
        self._refresh_health_panel()

    def _sync_run_table(self, *_args: Any) -> None:
        rows = [
            {
                "run_id": snapshot.run_id,
                "scan_name": snapshot.scan_name,
                "state": snapshot.state,
                "elapsed_seconds": snapshot.elapsed_seconds,
                "eta_seconds": snapshot.eta_seconds,
                "current_task": snapshot.current_task,
                "target_summary": summarize_target_input(snapshot.target_input),
                "finding_count": len(snapshot.findings),
            }
            for snapshot in sorted(
                self._run_snapshots.values(),
                key=lambda item: (
                    RUN_STATE_ORDER.get(item.state, 99),
                    item.workspace_name.lower(),
                    item.scan_name.lower(),
                ),
            )
        ]
        search = self.run_search_edit.text().strip().lower()
        state_filter = self.run_state_filter.currentText()
        filtered_rows: list[dict[str, Any]] = []
        for row in rows:
            if state_filter != "All States" and str(row.get("state") or "") != state_filter:
                continue
            if search and search not in json.dumps(row, sort_keys=True).lower():
                continue
            filtered_rows.append(row)
        self.run_model.set_rows(filtered_rows)
        self.run_results_label.setText(f"Showing {len(filtered_rows)}/{len(rows)} runs")
        self._sync_workspace_run_table()
        self._sync_general_overview()
        self._update_run_action_state()

    def _run_selected(self, index: QModelIndex) -> None:
        row = index.data(Qt.UserRole) or {}
        run_id = row.get("run_id")
        if isinstance(run_id, str) and run_id in self._run_snapshots:
            self._select_run_by_id(run_id)

    def _focus_output_tab(self, index: QModelIndex) -> None:
        self._run_selected(index)
        self._navigate_to("findings")
        self.output_tab.focus_findings()

    def _update_output_snapshot(self, run_id: str | None) -> None:
        inventory_snapshot = self._workspace_inventory_snapshot(preferred_run_id=run_id)
        self.assets_tab.set_snapshot(inventory_snapshot)
        if hasattr(self, "attacker_tab"):
            self.attacker_tab.set_snapshot(inventory_snapshot)
        if not run_id or run_id not in self._run_snapshots:
            self.output_tab.set_snapshot(None)
            if self.reports_tab is not None:
                self.reports_tab.set_snapshot(None)
            self.scanner_panel.set_snapshot(None)
            return
        snapshot = self._run_snapshots[run_id]
        self.output_tab.set_snapshot(snapshot, self._finding_states_by_run.get(run_id, {}))
        if self.reports_tab is not None:
            self.reports_tab.set_snapshot(snapshot)
        self.scanner_panel.set_snapshot(snapshot)

    def _resolve_snapshot(self, run_id: str) -> RunSnapshot | None:
        return self._run_snapshots.get(run_id)

    def _workspace_inventory_snapshot(self, preferred_run_id: str | None = None) -> RunSnapshot | None:
        if not self._run_snapshots:
            return None
        ordered: list[RunSnapshot] = []
        if preferred_run_id and preferred_run_id in self._run_snapshots:
            ordered.append(self._run_snapshots[preferred_run_id])
        ordered.extend(
            snapshot
            for run_id, snapshot in sorted(
                self._run_snapshots.items(),
                key=lambda item: (item[1].scan_name.lower(), item[0]),
            )
            if run_id != preferred_run_id
        )
        active_workspace = self._active_workspace()
        return build_workspace_inventory_snapshot(
            ordered,
            workspace_id=active_workspace.workspace_id if active_workspace is not None else self._active_workspace_id,
            workspace_name=active_workspace.name if active_workspace is not None else "",
        )

    def _select_run_by_id(self, run_id: str, *, status_prefix: str = "Selected") -> None:
        snapshot = self._resolve_snapshot(run_id)
        if snapshot is None:
            return
        self._selected_run_id = run_id
        self._update_output_snapshot(run_id)
        self.general_status.setText(f"{status_prefix}: {snapshot.scan_name}")
        self._refresh_health_panel()
        self._refresh_context_panels()
        self._update_run_action_state()

    def _run_snapshot_for_row(self, row: dict[str, Any]) -> RunSnapshot | None:
        run_id = str(row.get("run_id") or "").strip()
        return self._resolve_snapshot(run_id) if run_id else None

    def _set_run_table_current_row(
        self,
        table: QTableView,
        run_id: str,
        fallback_index: QModelIndex | None = None,
    ) -> None:
        if not run_id:
            return
        current_index = QModelIndex(fallback_index) if fallback_index is not None else QModelIndex()
        model = table.model()
        if model is None:
            return
        if current_index.isValid():
            current_row = current_index.data(Qt.UserRole) or {}
            current_run_id = str(current_row.get("run_id") or "") if isinstance(current_row, dict) else ""
            if current_run_id != run_id:
                current_index = QModelIndex()
        if not current_index.isValid():
            for row_number in range(model.rowCount()):
                candidate = model.index(row_number, 0)
                candidate_row = candidate.data(Qt.UserRole) or {}
                if isinstance(candidate_row, dict) and str(candidate_row.get("run_id") or "") == run_id:
                    current_index = candidate
                    break
        if not current_index.isValid():
            return
        selection = table.selectionModel()
        if selection is not None:
            selection.setCurrentIndex(current_index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        table.setCurrentIndex(current_index)
        table.selectRow(current_index.row())

    def _can_pause_snapshot(self, snapshot: RunSnapshot) -> bool:
        if snapshot.pause_requested or snapshot.resume_required:
            return False
        return snapshot.state not in {"paused", "completed", "failed", "cancelled", "blocked"}

    def _can_resume_snapshot(self, snapshot: RunSnapshot) -> bool:
        return snapshot.state == "paused" or snapshot.resume_required

    def _can_stop_snapshot(self, snapshot: RunSnapshot) -> bool:
        return snapshot.state in {"running", "paused"} or snapshot.resume_required

    def _can_skip_snapshot(self, snapshot: RunSnapshot) -> bool:
        if snapshot.state != "running" or snapshot.pause_requested or snapshot.resume_required:
            return False
        return bool(self._current_task_key(snapshot))

    @staticmethod
    def _can_retry_snapshot(snapshot: RunSnapshot) -> bool:
        return bool(str(snapshot.run_dir or "").strip())

    def _current_task_key(self, snapshot: RunSnapshot) -> str:
        current_task = str(snapshot.current_task or "").strip()
        for row in snapshot.tasks:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or row.get("task_key") or "").strip()
            label = str(row.get("label") or row.get("name") or "").strip()
            if current_task and current_task in {key, label}:
                return key or current_task
        for row in snapshot.tasks:
            if not isinstance(row, dict):
                continue
            if str(row.get("status") or "").strip().lower() in {"running", "in_progress", "started"}:
                return str(row.get("key") or row.get("task_key") or row.get("label") or "").strip()
        return current_task

    def _has_debug_data(self, snapshot: RunSnapshot) -> bool:
        if any(
            (
                snapshot.tasks,
                snapshot.tool_executions,
                snapshot.task_results,
                snapshot.evidence_artifacts,
                snapshot.warnings,
                snapshot.errors,
                snapshot.execution_issues,
            )
        ):
            return True
        run_dir_text = str(snapshot.run_dir or "").strip()
        if not run_dir_text:
            return False
        run_dir = Path(run_dir_text)
        if not run_dir.exists() or not run_dir.is_dir():
            return False
        persisted_paths = (
            run_dir / "data" / "scan_data.json",
            run_dir / "data" / "plan.json",
            run_dir / "logs" / "run.log",
            run_dir / "checkpoints" / "manifest.json",
        )
        return any(path.exists() for path in persisted_paths)

    def _show_debug_log_dialog(
        self,
        snapshot: RunSnapshot,
        *,
        task_row: dict[str, Any] | None = None,
        tool_row: dict[str, Any] | None = None,
        initial_tab: int = 0,
    ) -> None:
        bundle = build_run_debug_bundle(snapshot, task_row=task_row, tool_row=tool_row)
        dialog = DebugLogDialog(
            bundle["title"],
            bundle["overview"],
            bundle["combined_log"],
            bundle["current_task"],
            current_task_title=bundle["current_task_title"],
            initial_tab=initial_tab,
            parent=self,
        )
        dialog.finished.connect(lambda _result, window=dialog: self._discard_debug_dialog(window))
        self._debug_dialogs.append(dialog)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _discard_debug_dialog(self, dialog: DebugLogDialog) -> None:
        if dialog in self._debug_dialogs:
            self._debug_dialogs.remove(dialog)

    def _build_run_context_menu(
        self,
        parent: QWidget,
        snapshot: RunSnapshot,
    ) -> tuple[QMenu, Any, Any, Any, Any, Any, Any, Any]:
        menu = QMenu(parent)
        pause_action = menu.addAction("Pause Scan")
        pause_action.setEnabled(self._can_pause_snapshot(snapshot))
        resume_action = menu.addAction("Resume")
        resume_action.setEnabled(self._can_resume_snapshot(snapshot))
        stop_action = menu.addAction("Stop")
        stop_action.setEnabled(self._can_stop_snapshot(snapshot))
        skip_task_action = menu.addAction("Skip Current Task")
        skip_task_action.setEnabled(self._can_skip_snapshot(snapshot))
        retry_action = menu.addAction("Relaunch Scan")
        retry_action.setEnabled(self._can_retry_snapshot(snapshot))
        menu.addSeparator()
        debug_action = menu.addAction("View Debug Log")
        current_task_action = menu.addAction("View Current Task Debug Log")
        has_debug_data = self._has_debug_data(snapshot)
        debug_action.setEnabled(has_debug_data)
        current_task_action.setEnabled(has_debug_data)
        return menu, pause_action, resume_action, stop_action, skip_task_action, retry_action, debug_action, current_task_action

    def _open_run_context_menu(self, table: QTableView, point: QPoint) -> None:
        index = table.indexAt(point)
        if not index.isValid():
            selection = table.selectionModel()
            if selection is not None and selection.currentIndex().isValid():
                index = selection.currentIndex()
            elif table.model() is not None and table.model().rowCount() > 0:
                index = table.model().index(0, 0)
        if not index.isValid():
            return
        selection = table.selectionModel()
        if selection is not None:
            selection.setCurrentIndex(index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        table.selectRow(index.row())
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict):
            return
        snapshot = self._run_snapshot_for_row(row)
        if snapshot is None:
            return
        self._select_run_by_id(snapshot.run_id)
        self._set_run_table_current_row(table, snapshot.run_id, index)
        (
            menu,
            pause_action,
            resume_action,
            stop_action,
            skip_task_action,
            retry_action,
            debug_action,
            current_task_action,
        ) = self._build_run_context_menu(table, snapshot)
        action = self._exec_menu(menu, table.viewport().mapToGlobal(point))
        self._set_run_table_current_row(table, snapshot.run_id, index)
        if action is pause_action:
            self._send_control_action("pause")
        elif action is resume_action:
            self._send_control_action("resume")
        elif action is stop_action:
            self._send_control_action("stop")
        elif action is skip_task_action:
            self._send_skip_current_task_action()
        elif action is retry_action:
            self._retry_selected_run()
        elif action is debug_action:
            self._show_debug_log_dialog(snapshot, initial_tab=1)
        elif action is current_task_action:
            self._show_debug_log_dialog(snapshot, initial_tab=2)

    def _handle_scanner_context_menu(
        self,
        context_kind: str,
        table: QTableView,
        point: QPoint,
        row: dict[str, Any],
    ) -> None:
        snapshot = self._selected_snapshot()
        if snapshot is None:
            return
        (
            menu,
            pause_action,
            resume_action,
            stop_action,
            skip_task_action,
            retry_action,
            debug_action,
            current_task_action,
        ) = self._build_run_context_menu(table, snapshot)
        action = self._exec_menu(menu, table.viewport().mapToGlobal(point))
        if action is pause_action:
            self._send_control_action("pause")
        elif action is resume_action:
            self._send_control_action("resume")
        elif action is stop_action:
            self._send_control_action("stop")
        elif action is skip_task_action:
            self._send_skip_current_task_action()
        elif action is retry_action:
            self._retry_selected_run()
        elif action is debug_action:
            self._show_debug_log_dialog(snapshot, initial_tab=1)
        elif action is current_task_action:
            task_row = row if context_kind == "task" else None
            tool_row = row if context_kind == "tool" else None
            self._show_debug_log_dialog(snapshot, task_row=task_row, tool_row=tool_row, initial_tab=2)

    @staticmethod
    def _exec_menu(menu: QMenu, global_point: QPoint):
        app = QApplication.instance()
        if app is not None and app.platformName().strip().lower() in {"offscreen", "minimal"}:
            return None
        return menu.exec(global_point)

    def _selected_snapshot(self) -> RunSnapshot | None:
        if self._selected_run_id and self._selected_run_id in self._run_snapshots:
            return self._run_snapshots[self._selected_run_id]
        return None

    def _selected_run_directory(self, action_label: str) -> tuple[RunSnapshot, Path] | None:
        snapshot = self._selected_snapshot()
        if snapshot is None or not snapshot.run_dir:
            QMessageBox.information(self, "No Run Selected", f"Select a run to {action_label}.")
            return None
        run_dir = Path(snapshot.run_dir)
        if not run_dir.exists():
            message = f"The run folder for {snapshot.scan_name} is no longer available."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Run Folder Missing", f"{message}\n\nExpected path:\n{run_dir}")
            return None
        if not run_dir.is_dir():
            message = f"The saved run path for {snapshot.scan_name} is not a folder."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Invalid Run Folder", f"{message}\n\nConfigured path:\n{run_dir}")
            return None
        return snapshot, run_dir

    def _load_retry_payload(self, path: Path, payload_name: str) -> tuple[dict[str, Any], str | None]:
        if not path.exists():
            return {}, None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return {}, f"{payload_name} could not be read from {path.name}: {exc}"
        if not isinstance(loaded, dict):
            return {}, f"{payload_name} in {path.name} is not a JSON object."
        return loaded, None

    def _send_control_action(self, action: str) -> None:
        selected = self._selected_run_directory("send a control action")
        if selected is None:
            return
        snapshot, run_dir = selected
        if action == "resume" and snapshot.run_id not in self._run_processes:
            self._resume_selected_run()
            return
        try:
            RunStore.from_existing(run_dir).write_control(action)
        except Exception as exc:  # noqa: BLE001
            message = f"AttackCastle could not request {action} for {snapshot.scan_name}."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Control Request Failed", f"{message}\n\n{exc}")
            return
        if action == "pause":
            snapshot.pause_requested = True
            snapshot.resume_required = True
        elif action == "resume":
            snapshot.pause_requested = False
            snapshot.resume_required = False
        self._sync_run_registry_for_snapshot(snapshot)
        self.general_status.setText(f"Requested {action} for {snapshot.scan_name}")
        self._append_audit("control.requested", f"{action.title()} requested for {snapshot.scan_name}", run_id=snapshot.run_id, workspace_id=snapshot.workspace_id)
        self._update_run_action_state()

    def _send_skip_current_task_action(self) -> None:
        selected = self._selected_run_directory("skip the current task")
        if selected is None:
            return
        snapshot, run_dir = selected
        task_key = self._current_task_key(snapshot)
        if not task_key:
            QMessageBox.information(self, "No Current Task", f"{snapshot.scan_name} does not have a current task to skip.")
            return
        try:
            RunStore.from_existing(run_dir).write_control(
                "skip_task",
                {"task_key": task_key, "reason": "operator_requested_skip"},
            )
        except Exception as exc:  # noqa: BLE001
            message = f"AttackCastle could not request a task skip for {snapshot.scan_name}."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Control Request Failed", f"{message}\n\n{exc}")
            return
        self.general_status.setText(f"Requested skip for {task_key} on {snapshot.scan_name}")
        self._append_audit(
            "control.requested",
            f"Skip requested for {task_key} on {snapshot.scan_name}",
            run_id=snapshot.run_id,
            workspace_id=snapshot.workspace_id,
        )
        self._update_run_action_state()

    def _resume_selected_run(self) -> None:
        selected = self._selected_run_directory("resume")
        if selected is None:
            return
        snapshot, run_dir = selected
        session_path = run_dir / "data" / "gui_session.json"
        profile_path = run_dir / "data" / "gui_requested_profile.json"
        session, _session_warning = self._load_retry_payload(session_path, "Resume session data")
        profile_payload, _profile_warning = self._load_retry_payload(profile_path, "Resume profile data")
        request = ScanRequest(
            scan_name=str(session.get("scan_name") or snapshot.scan_name),
            target_input=str(session.get("target_input") or snapshot.target_input),
            profile=GuiProfile.from_dict(profile_payload if isinstance(profile_payload, dict) else {}),
            output_directory=str(run_dir.parent),
            workspace_id=snapshot.workspace_id,
            workspace_name=snapshot.workspace_name,
            resume_run_dir=str(run_dir),
            launch_mode="resume",
            enabled_extension_ids=[
                str(item) for item in session.get("enabled_extension_ids", []) if str(item).strip()
            ]
            if isinstance(session.get("enabled_extension_ids"), list)
            else [],
        )
        try:
            self._launch_request(request)
        except Exception as exc:  # noqa: BLE001
            message = f"AttackCastle could not resume {snapshot.scan_name}."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Resume Failed", f"{message}\n\n{exc}")
            return
        snapshot.pause_requested = False
        snapshot.resume_required = False
        snapshot.live_process = True
        self._sync_run_registry_for_snapshot(snapshot)
        self.general_status.setText(f"Resuming: {snapshot.scan_name}")
        self._append_audit("scan.resumed", f"Resume requested for {snapshot.scan_name}", run_id=snapshot.run_id, workspace_id=snapshot.workspace_id)
        self._update_run_action_state()

    def _retry_selected_run(self) -> None:
        selected = self._selected_run_directory("retry")
        if selected is None:
            return
        snapshot, run_dir = selected
        run_store = RunStore.from_existing(run_dir)
        session_path = run_store.data_dir / "gui_session.json"
        profile_path = run_store.data_dir / "gui_requested_profile.json"
        session, session_warning = self._load_retry_payload(session_path, "Retry session data")
        profile_payload, profile_warning = self._load_retry_payload(profile_path, "Retry profile data")
        active_workspace = self._active_workspace()
        request = ScanRequest(
            scan_name=f"{snapshot.scan_name} Retry",
            target_input=str(session.get("target_input") or snapshot.target_input),
            profile=GuiProfile.from_dict(profile_payload if isinstance(profile_payload, dict) else {}),
            output_directory=active_workspace.home_dir if active_workspace is not None else ad_hoc_output_home(),
            workspace_id=active_workspace.workspace_id if active_workspace is not None else "",
            workspace_name=active_workspace.name if active_workspace is not None else "",
            enabled_extension_ids=[
                str(item) for item in session.get("enabled_extension_ids", []) if str(item).strip()
            ]
            if isinstance(session.get("enabled_extension_ids"), list)
            else [],
        )
        try:
            self._launch_request(request)
        except Exception as exc:  # noqa: BLE001
            message = f"AttackCastle could not launch a retry for {snapshot.scan_name}."
            self.general_status.setText(message)
            QMessageBox.warning(self, "Retry Launch Failed", f"{message}\n\n{exc}")
            return
        warnings = [warning for warning in (session_warning, profile_warning) if warning]
        if warnings:
            self.general_status.setText(f"Retry launched for {snapshot.scan_name} using fallback metadata.")
            self._append_audit(
                "scan.retry.fallback",
                f"Retry launched for {snapshot.scan_name} with fallback metadata",
                run_id=snapshot.run_id,
                workspace_id=snapshot.workspace_id,
                details={"warnings": warnings},
            )
        else:
            self.general_status.setText(f"Retry launched for {snapshot.scan_name}")
        self._append_audit("scan.retry", f"Retry launched for {snapshot.scan_name}", run_id=snapshot.run_id, workspace_id=snapshot.workspace_id)

    def _open_selected_run_folder(self) -> None:
        selected = self._selected_run_directory("open the run folder")
        if selected is None:
            return
        _snapshot, run_dir = selected
        self._open_local_path(str(run_dir))

    def _open_local_path(self, path: str) -> None:
        if not path:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).resolve())))

    def _save_finding_state(self, run_id: str, state: FindingState) -> None:
        self._finding_states_by_run.setdefault(run_id, {})[state.finding_id] = state
        self.workspace_store.save_finding_state(self._active_workspace_id, run_id, state)
        self._append_audit("finding.updated", f"Updated triage for {state.finding_id}", run_id=run_id, details=state.to_dict())
        self._refresh_dashboard()
        if self.reports_tab is not None:
            self.reports_tab.set_snapshot(self._selected_snapshot())

    def _current_finding_states(self) -> dict[str, FindingState]:
        if not self._selected_run_id:
            return {}
        return self._finding_states_by_run.get(self._selected_run_id, {})

    def _current_workspace_home(self) -> str:
        workspace = self._active_workspace()
        if workspace is not None and workspace.home_dir:
            return workspace.home_dir
        return ad_hoc_output_home()

    def _current_client_name(self) -> str:
        workspace = self._active_workspace()
        return workspace.client_name if workspace is not None else ""

    def _load_reports_config(self) -> ReportsConfig:
        return self.workspace_store.load_reports_config(self._active_workspace_id)

    def _save_reports_config(self, config: ReportsConfig) -> None:
        self.workspace_store.save_reports_config(self._active_workspace_id, config)
        self._append_audit("reports.config.saved", "Saved report export settings.", details=config.to_dict())

    def _load_manual_findings(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.workspace_store.load_manual_findings(self._active_workspace_id, run_id)
        return rows if isinstance(rows, list) else []

    def _save_manual_findings(self, run_id: str, findings: list[dict[str, Any]]) -> None:
        self.workspace_store.save_manual_findings(self._active_workspace_id, run_id, findings)
        self._append_audit(
            "finding.manual.saved",
            f"Saved manual finding set for {run_id}",
            run_id=run_id,
            details={"finding_count": len(findings)},
        )
        self._refresh_dashboard()

    def _load_entity_notes(self, workspace_id: str) -> dict[str, EntityNote]:
        return self.workspace_store.load_entity_notes(workspace_id)

    def _save_entity_note(self, workspace_id: str, note: EntityNote) -> None:
        self.workspace_store.save_entity_note(note, workspace_id)
        self._append_audit(
            "asset.note.updated",
            f"Updated notes for {note.label or note.signature}",
            workspace_id=workspace_id,
            details=note.to_dict(),
        )

    def _load_attack_workspaces(self, workspace_id: str) -> list[AttackWorkspace]:
        return self.workspace_store.load_attack_workspaces(workspace_id)

    def _save_attack_workspaces(self, workspace_id: str, workspaces: list[AttackWorkspace]) -> None:
        self.workspace_store.save_attack_workspaces(workspace_id, workspaces)

    def _attacker_action_types(self, entity_kind: str) -> list[tuple[str, str]]:
        compatible = self.attacker_tab.compatible_workspace_types(entity_kind) if hasattr(self, "attacker_tab") else []
        return [
            (workspace_type, str(WORKSPACE_TYPES.get(workspace_type, {}).get("label") or title_case_label(workspace_type)))
            for workspace_type in compatible
        ]

    def _load_current_overview_state(self, workspace_id: str) -> None:
        self._overview_notes_timer.stop()
        workspace_id = str(workspace_id or "").strip()
        self._overview_state = (
            self.workspace_store.load_overview_state(workspace_id)
            if workspace_id
            else WorkspaceOverviewState()
        )
        self._apply_overview_state_to_ui()

    def _apply_overview_state_to_ui(self) -> None:
        self._applying_overview_state = True
        try:
            self.overview_checklist_panel.clear_input()
            self._render_overview_checklist()
            self.overview_notes_edit.setPlainText(self._overview_state.notes)
        finally:
            self._applying_overview_state = False

    def _render_overview_checklist(self) -> None:
        self.overview_checklist_panel.set_items(self._overview_state.checklist_items)

    def _add_overview_checklist_item(self, label: str) -> None:
        normalized = str(label or "").strip()
        if not normalized:
            self.overview_checklist_panel.clear_input()
            return
        timestamp = now_iso()
        self._overview_state.checklist_items.append(
            OverviewChecklistItem(
                item_id=uuid4().hex,
                label=normalized,
                completed=False,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )
        self._render_overview_checklist()
        self.overview_checklist_panel.clear_input()
        self.overview_checklist_panel.focus_input()
        self._persist_overview_state()

    def _toggle_overview_checklist_item(self, item_id: str) -> None:
        for item in self._overview_state.checklist_items:
            if item.item_id != item_id:
                continue
            item.completed = not item.completed
            item.updated_at = now_iso()
            break
        self._render_overview_checklist()
        self._persist_overview_state()

    def _delete_overview_checklist_item(self, item_id: str) -> None:
        self._overview_state.checklist_items = [
            item for item in self._overview_state.checklist_items if item.item_id != item_id
        ]
        self._render_overview_checklist()
        self._persist_overview_state()

    def _handle_overview_notes_changed(self) -> None:
        if self._applying_overview_state:
            return
        self._overview_state.notes = self.overview_notes_edit.toPlainText()
        if self._active_workspace_id:
            self._overview_notes_timer.start()

    def _persist_overview_state(self) -> None:
        if not self._active_workspace_id:
            return
        self.workspace_store.save_overview_state(self._active_workspace_id, self._overview_state)

    def _send_asset_to_attacker(
        self,
        entity_kind: str,
        row: dict[str, Any],
        snapshot: RunSnapshot,
        workspace_type: str,
    ) -> None:
        if not hasattr(self, "attacker_tab"):
            return
        if not self._active_workspace_id and snapshot is not None and snapshot.workspace_id:
            self.attacker_tab.set_workspace(snapshot.workspace_id)
        workspace = self.attacker_tab.add_workspace_from_asset(entity_kind, row, snapshot, workspace_type)
        self._navigate_to("attacker")
        self.general_status.setText(f"Created attacker workspace: {workspace.name}")
        self._append_audit(
            "attacker.workspace.created",
            f"Sent {row.get('__label') or title_case_label(entity_kind)} to Attacker",
            run_id=snapshot.run_id if snapshot is not None else "",
            workspace_id=snapshot.workspace_id if snapshot is not None else self._active_workspace_id,
            details={
                "attack_workspace_id": workspace.attack_workspace_id,
                "workspace_type": workspace.workspace_type,
                "entity_kind": entity_kind,
            },
        )

    def _start_scan_for_target(self, target_input: str, label: str = "") -> None:
        if self._switch_in_progress:
            return
        target = str(target_input or "").strip()
        if not target:
            QMessageBox.information(self, "No Target", "Select an asset with a resolvable target before launching a scan.")
            return
        snapshot = self._selected_snapshot()
        preferred_profile_name = snapshot.profile_name if snapshot is not None else ""
        workspace = (
            self.workspace_store.load_workspace(snapshot.workspace_id)
            if snapshot is not None and snapshot.workspace_id
            else self._active_workspace()
        )
        dialog = StartScanDialog(
            self._profiles,
            workspace,
            available_extensions=self.extension_store.list_command_hook_extensions(),
            prefill_scan_name=f"{label or target} Targeted Scan",
            prefill_target_input=target,
            preferred_profile_name=preferred_profile_name,
            parent=self,
        )
        if dialog.exec() != QDialog.Accepted:
            return
        request = dialog.build_request()
        self.store.save_profile(request.profile)
        self._profiles = self.store.load()
        self.configuration_tab.reload_profiles(preferred_profile_name=request.profile.name)
        self._launch_request(request)
        self._append_audit(
            "scan.started",
            f"Targeted scan requested for {label or target}",
            workspace_id=request.workspace_id,
            details={"target_summary": summarize_target_input(request.target_input), "profile": request.profile.name},
        )
        self._refresh_dashboard()

    def _refresh_dashboard(self) -> None:
        self._refresh_context_panels()
        self._sync_general_overview()

    def _refresh_audit_table(self) -> None:
        self.scanner_panel.set_audit_rows([entry.to_dict() for entry in reversed(self._audit_entries[-100:])])

    def _refresh_health_panel(self) -> None:
        self.scanner_panel.set_snapshot(self._selected_snapshot())

    def _active_workspace(self) -> Workspace | None:
        if not self._active_workspace_id:
            return None
        for workspace in self._workspaces:
            if workspace.workspace_id == self._active_workspace_id:
                return workspace
        return None

    def _selected_workspace(self) -> Workspace | None:
        if not self._selected_workspace_id:
            return None
        for workspace in self._workspaces:
            if workspace.workspace_id == self._selected_workspace_id:
                return workspace
        return None

    def _sync_workspace_list(self) -> None:
        active_workspace = self._active_workspace()
        self.workspace_list.blockSignals(True)
        self.workspace_list.clear()
        if active_workspace is not None:
            label = f"{active_workspace.name} | Active"
            if active_workspace.client_name:
                label += f" | {active_workspace.client_name}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, active_workspace.workspace_id)
            self.workspace_list.addItem(item)
        self.workspace_list.blockSignals(False)
        if active_workspace is not None:
            self.workspace_list.setCurrentRow(0)
            self._workspace_selected(0)
        else:
            self._selected_workspace_id = ""
            self._selected_engagement_id = ""
            if self._workspaces:
                self.workspace_summary.setPlainText("Ad-hoc mode is active. Switch to a saved project from Settings when you want project-scoped context.")
            else:
                self.workspace_summary.setPlainText("No saved projects yet. Use the project editor to create one, or continue in ad-hoc mode.")
            self._update_workspace_action_state()

    def _workspace_selected(self, row: int) -> None:
        workspace = self._active_workspace()
        if workspace is None or row != 0:
            self._selected_workspace_id = ""
            self._selected_engagement_id = ""
            self.workspace_summary.clear()
            self._update_workspace_action_state()
            return
        self._selected_workspace_id = workspace.workspace_id
        self._selected_engagement_id = self._selected_workspace_id
        self.workspace_summary.setPlainText(
            f"Project Home: {workspace.home_dir}\n"
            f"Client: {workspace.client_name}\n"
            f"\nScope:\n{workspace.scope_summary}"
        )
        self._update_workspace_action_state()

    def _update_workspace_action_state(self) -> None:
        for button in (
            self.new_workspace_button,
            self.edit_workspace_button,
            self.open_workspace_button,
            self.no_workspace_button,
            self.delete_workspace_button,
        ):
            button.setEnabled(False)
        self.start_scan_button.setEnabled(not self._switch_in_progress)

    def _new_workspace(self) -> None:
        dialog = WorkspaceDialog(parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        workspace = dialog.build_workspace()
        self.workspace_store.save_workspace(workspace)
        self._workspaces = self.workspace_store.load_workspaces()
        self._selected_workspace_id = workspace.workspace_id
        self._append_audit("workspace.created", f"Created project {workspace.name}", workspace_id=workspace.workspace_id)
        self._sync_workspace_list()

    def _edit_selected_workspace(self) -> None:
        workspace = self._selected_workspace()
        if workspace is None:
            return
        dialog = WorkspaceDialog(workspace, self)
        if dialog.exec() != QDialog.Accepted:
            return
        updated = dialog.build_workspace()
        self.workspace_store.save_workspace(updated)
        self._workspaces = self.workspace_store.load_workspaces()
        if updated.workspace_id == self._active_workspace_id:
            self._active_workspace_id = updated.workspace_id
        self._append_audit("workspace.updated", f"Updated project {updated.name}", workspace_id=updated.workspace_id)
        self._sync_workspace_list()
        if updated.workspace_id == self._active_workspace_id:
            self._refresh_context_panels()

    @staticmethod
    def _path_contains(parent: Path, child: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _resolve_target_path(raw_path: str) -> Path | None:
        text = str(raw_path or "").strip()
        if not text:
            return None
        return Path(text).expanduser().resolve()

    def _validate_workspace_delete_path(self, path: Path) -> None:
        home_path = Path.home().resolve()
        critical_paths = {
            home_path,
            self.store.path.parent.resolve(),
            self.workspace_store.path.parent.resolve(),
            Path.cwd().resolve(),
        }
        if path == path.parent:
            raise ValueError(f"Refusing to delete root path: {path}")
        if path in critical_paths:
            raise ValueError(f"Refusing to delete protected path: {path}")
        if self._path_contains(path, Path.cwd().resolve()):
            raise ValueError(f"Refusing to delete the current working directory tree: {path}")

    def _workspace_has_live_processes(self, workspace_id: str) -> bool:
        for entry in self.workspace_store.load_run_registry(workspace_id):
            process = self._run_processes.get(entry.run_id)
            if process is not None and process.state() != QProcess.NotRunning:
                return True
        return False

    def _build_workspace_delete_plan(self, workspace_ids: list[str]) -> tuple[list[Workspace], list[Path], int]:
        target_ids = {str(workspace_id or "").strip() for workspace_id in workspace_ids if str(workspace_id or "").strip()}
        target_workspaces = [workspace for workspace in self._workspaces if workspace.workspace_id in target_ids]
        if not target_workspaces:
            return [], [], 0

        protected_paths: list[Path] = []
        total_run_count = 0
        candidate_paths: list[Path] = []
        for workspace in self._workspaces:
            home_dir = self._resolve_target_path(workspace.home_dir)
            run_entries = self.workspace_store.load_run_registry(workspace.workspace_id)
            run_dirs = [resolved for resolved in (self._resolve_target_path(entry.run_dir) for entry in run_entries) if resolved is not None]
            if workspace.workspace_id in target_ids:
                total_run_count += len(run_entries)
                if home_dir is not None:
                    candidate_paths.append(home_dir)
                candidate_paths.extend(run_dirs)
            else:
                if home_dir is not None:
                    protected_paths.append(home_dir)
                protected_paths.extend(run_dirs)

        unique_candidates: list[Path] = []
        for path in sorted({path for path in candidate_paths}, key=lambda item: (len(item.parts), str(item).lower())):
            self._validate_workspace_delete_path(path)
            if any(self._path_contains(existing, path) for existing in unique_candidates):
                continue
            unique_candidates.append(path)

        for candidate in unique_candidates:
            for protected in protected_paths:
                if candidate == protected or self._path_contains(candidate, protected) or self._path_contains(protected, candidate):
                    raise ValueError(
                        f"Deletion would overlap data that still belongs to another project: {candidate} conflicts with {protected}"
                    )
        return target_workspaces, unique_candidates, total_run_count

    @staticmethod
    def _delete_paths(paths: list[Path]) -> list[str]:
        removed: list[str] = []
        for path in paths:
            if not path.exists():
                continue
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            else:
                shutil.rmtree(path)
            removed.append(str(path))
        return removed

    @staticmethod
    def _delete_plan_preview(paths: list[Path], limit: int = 4) -> str:
        if not paths:
            return "No on-disk paths are currently tracked for deletion."
        lines = [f"- {path}" for path in paths[:limit]]
        if len(paths) > limit:
            lines.append(f"- ... and {len(paths) - limit} more path(s)")
        return "\n".join(lines)

    def _confirm_workspace_deletion(self, *, title: str, message: str, final_title: str, final_message: str) -> bool:
        if QMessageBox.question(self, title, message) != QMessageBox.Yes:
            return False
        return QMessageBox.question(self, final_title, final_message) == QMessageBox.Yes

    def _delete_workspaces_and_data(self, workspace_ids: list[str]) -> bool:
        try:
            target_workspaces, delete_paths, run_count = self._build_workspace_delete_plan(workspace_ids)
        except Exception as exc:
            QMessageBox.warning(self, "Project Deletion Blocked", str(exc))
            return False
        if not target_workspaces:
            return False
        live_workspaces = [workspace.name for workspace in target_workspaces if self._workspace_has_live_processes(workspace.workspace_id)]
        if live_workspaces:
            QMessageBox.warning(
                self,
                "Project Deletion Blocked",
                "One or more targeted projects still have live runs owned by this GUI session.\n\n"
                + "\n".join(f"- {name}" for name in live_workspaces),
            )
            return False

        names = [workspace.name for workspace in target_workspaces]
        workspace_label = names[0] if len(names) == 1 else f"{len(names)} projects"
        if not self._confirm_workspace_deletion(
            title="Delete Project Data",
            message=(
                f"Permanently delete {workspace_label} and all tracked data?\n\n"
                f"Tracked runs: {run_count}\n"
                f"Filesystem targets: {len(delete_paths)}"
            ),
            final_title="Final Deletion Confirmation",
            final_message=(
                "This action cannot be undone.\n\n"
                + self._delete_plan_preview(delete_paths)
            ),
        ):
            return False

        try:
            removed_paths = self._delete_paths(delete_paths)
            self.workspace_store.delete_workspaces([workspace.workspace_id for workspace in target_workspaces])
        except Exception as exc:
            QMessageBox.warning(self, "Project Deletion Failed", f"AttackCastle could not finish deleting the requested project data.\n\n{exc}")
            return False

        next_workspace_id = self.workspace_store.get_active_workspace_id()
        self._load_workspace_state(next_workspace_id)
        summary = (
            f"Deleted project {names[0]} and removed {len(removed_paths)} path(s)."
            if len(names) == 1
            else f"Deleted {len(names)} projects and removed {len(removed_paths)} path(s)."
        )
        self.general_status.setText(summary)
        self._append_audit(
            "workspace.deleted",
            summary,
            details={"workspaces": names, "removed_paths": removed_paths, "tracked_runs_deleted": run_count},
        )
        return True

    def _delete_selected_workspace(self) -> None:
        workspace = self._selected_workspace()
        if workspace is None:
            return
        self._delete_workspaces_and_data([workspace.workspace_id])

    def _delete_active_workspace_and_data(self) -> None:
        workspace = self._active_workspace()
        if workspace is None:
            return
        self._delete_workspaces_and_data([workspace.workspace_id])

    def _delete_all_workspaces_and_data(self) -> None:
        if not self._workspaces:
            return
        self._delete_workspaces_and_data([workspace.workspace_id for workspace in self._workspaces])

    def _switch_to_selected_workspace(self) -> None:
        workspace = self._selected_workspace()
        if workspace is None:
            return
        self._switch_workspace(workspace.workspace_id)

    def _switch_to_no_workspace(self) -> None:
        self._switch_workspace("")

    def _switch_workspace(self, workspace_id: str) -> bool:
        workspace_id = str(workspace_id or "")
        if workspace_id == self._active_workspace_id or self._switch_in_progress:
            return True
        self._switch_in_progress = True
        self._update_workspace_action_state()
        running_live_ids = [
            snapshot.run_id
            for snapshot in self._run_snapshots.values()
            if snapshot.state == "running" and snapshot.run_id in self._run_processes
        ]
        for run_id in running_live_ids:
            snapshot = self._run_snapshots.get(run_id)
            if snapshot is None:
                continue
            try:
                RunStore.from_existing(Path(snapshot.run_dir)).write_control("pause")
            except Exception:
                self._switch_in_progress = False
                self._update_workspace_action_state()
                QMessageBox.warning(self, "Project Switch Failed", f"Could not pause {snapshot.scan_name} before switching projects.")
                return False
            snapshot.pause_requested = True
            snapshot.resume_required = True
            self._sync_run_registry_for_snapshot(snapshot)

        if running_live_ids and not self._wait_for_paused_runs(running_live_ids):
            self._switch_in_progress = False
            self._update_workspace_action_state()
            QMessageBox.warning(
                self,
                "Project Switch Failed",
                "One or more runs did not acknowledge pause in time. The current project is still active.",
            )
            return False

        self._load_workspace_state(workspace_id)
        self._switch_in_progress = False
        self._update_workspace_action_state()
        return True

    def _wait_for_paused_runs(self, run_ids: list[str], timeout_seconds: float = 90.0) -> bool:
        deadline = monotonic() + timeout_seconds
        while monotonic() < deadline:
            QApplication.processEvents()
            self._refresh_runs()
            if all(
                run_id not in self._run_snapshots or self._run_snapshots[run_id].state == "paused"
                for run_id in run_ids
            ):
                return True
        return False

    def _load_workspace_state(self, workspace_id: str) -> None:
        workspace_id = str(workspace_id or "")
        self._overview_notes_timer.stop()
        self._active_workspace_id = workspace_id
        self.workspace_store.set_active_workspace(workspace_id)
        self._workspaces = self.workspace_store.load_workspaces()
        self._engagements = self._workspaces
        self._run_registry = self.workspace_store.load_run_registry(workspace_id)
        self._finding_states_by_run = self.workspace_store.load_finding_states(workspace_id)
        self._audit_entries = self.workspace_store.load_audit(workspace_id)
        self._selected_workspace_id = workspace_id or (self._workspaces[0].workspace_id if self._workspaces else "")
        self._selected_engagement_id = self._selected_workspace_id
        self._run_snapshots = {}
        for entry in self._run_registry:
            run_dir = Path(entry.run_dir)
            if not run_dir.exists():
                continue
            try:
                snapshot = load_run_snapshot(run_dir)
            except Exception:
                continue
            self._apply_registry_overrides(snapshot, entry)
            self._run_snapshots[snapshot.run_id] = snapshot
        self._selected_run_id = next(iter(self._run_snapshots), None)
        self._sync_workspace_list()
        self._load_current_overview_state(workspace_id)
        self._refresh_audit_table()
        self._sync_run_table()
        self._refresh_context_panels()
        if hasattr(self, "attacker_tab"):
            self.attacker_tab.set_workspace(workspace_id)
        self._refresh_dashboard()
        self._refresh_health_panel()
        self._refresh_settings_page()
        if self.reports_tab is not None:
            self.reports_tab.reload_config()
            self.reports_tab.set_snapshot(self._selected_snapshot())

    def _apply_registry_overrides(self, snapshot: RunSnapshot, entry: RunRegistryEntry) -> None:
        snapshot.workspace_id = entry.workspace_id or snapshot.workspace_id
        if entry.scan_name:
            snapshot.scan_name = entry.scan_name
        snapshot.pause_requested = entry.pause_requested
        snapshot.resume_required = entry.resume_required
        snapshot.live_process = entry.run_id in self._run_processes and self._run_processes[entry.run_id].state() != QProcess.NotRunning
        if snapshot.resume_required or entry.last_known_state == "paused":
            snapshot.state = "paused"

    def _sync_run_registry_for_snapshot(self, snapshot: RunSnapshot) -> None:
        workspace_id = snapshot.workspace_id or self._active_workspace_id
        entry = RunRegistryEntry(
            run_id=snapshot.run_id,
            run_dir=snapshot.run_dir,
            workspace_id=workspace_id,
            scan_name=snapshot.scan_name,
            last_known_state=snapshot.state,
            pause_requested=snapshot.pause_requested,
            resume_required=snapshot.resume_required,
        )
        self.workspace_store.register_run(entry)
        if (workspace_id or "") == self._active_workspace_id:
            self._run_registry = self.workspace_store.load_run_registry(workspace_id)

    def _append_audit(self, action: str, summary: str, run_id: str = "", workspace_id: str = "", details: dict[str, Any] | None = None) -> None:
        workspace_id = workspace_id or self._active_workspace_id
        entry = AuditEntry(timestamp=now_iso(), action=action, summary=summary, run_id=run_id, workspace_id=workspace_id, details=details or {})
        self.workspace_store.append_audit(entry, workspace_id=workspace_id)
        if (workspace_id or "") == self._active_workspace_id:
            self._audit_entries = self.workspace_store.load_audit(workspace_id)
            self._refresh_audit_table()

    # Compatibility wrappers while the rest of the GUI/tests fully rename away from engagement terminology.
    def _sync_engagement_list(self) -> None:
        self._workspaces = self._engagements
        self._sync_workspace_list()

    def _engagement_selected(self, row: int) -> None:
        self._workspace_selected(row)

    def _get_selected_engagement(self) -> Workspace | None:
        return self._selected_workspace()

    def _update_engagement_action_state(self) -> None:
        self._update_workspace_action_state()

    def _refresh_context_panels(self) -> None:
        self._refresh_header_context()

    def _refresh_header_context(self) -> None:
        return

    def _update_run_action_state(self) -> None:
        snapshot = self._selected_snapshot()
        if snapshot is None:
            self.general_status_detail.setText(
                "Select a run to review context, health, and findings for the current session."
            )
            return
        issue_count = int(snapshot.execution_issues_summary.get("total_count", 0) or 0)
        self.general_status_detail.setText(
            f"Focused on {snapshot.workspace_name or 'the ad-hoc session'} with {issue_count} execution issue(s). "
            "Use Scanner > Issues for the consolidated review."
        )


def run() -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv)
    profile_store = GuiProfileStore()
    workspace_store = WorkspaceStore()

    if workspace_store.migration_required():
        if not _run_workspace_migration(workspace_store, profile_store):
            return 0

    workspaces = workspace_store.load_workspaces()
    chooser = WorkspaceChooserDialog(workspaces, workspace_store.get_active_workspace_id(), workspace_store=workspace_store)
    if chooser.exec() != QDialog.Accepted:
        return 0
    selected_workspace: Workspace | None = None
    if chooser.launch_action() == "open_workspace":
        selected_workspace = workspace_store.load_workspace(chooser.selected_workspace_id())
        if selected_workspace is None:
            return 0
        workspace_store.set_active_workspace(selected_workspace.workspace_id)
    elif chooser.launch_action() == "launch_without_workspace":
        workspace_store.set_active_workspace("")
    else:
        return 0
    window = MainWindow(store=profile_store, workspace_store=workspace_store, active_workspace=selected_workspace)
    window._apply_restore_geometry()
    window._geometry_synced_to_screen = True
    window.showMaximized()
    return app.exec()


def _discover_legacy_import_roots(profile_store: GuiProfileStore) -> list[Path]:
    roots: list[Path] = []
    candidates = {Path("./output").resolve(), profile_store.path.parent.resolve()}
    for profile in profile_store.load():
        raw = str(profile.output_directory or "").strip()
        if raw:
            candidates.add(Path(raw).expanduser().resolve())
    for path in candidates:
        if path.exists() and path.is_dir():
            roots.append(path)
    return sorted(roots, key=lambda item: str(item))


def _scan_legacy_run_dirs(import_roots: list[Path]) -> list[dict[str, str]]:
    discovered: dict[str, dict[str, str]] = {}
    for root in import_roots:
        for gui_session in root.rglob("gui_session.json"):
            run_dir = gui_session.parent.parent
            if not run_dir.is_dir():
                continue
            try:
                payload = json.loads(gui_session.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            run_id = str(payload.get("run_id") or run_dir.name.replace("run_", "", 1))
            discovered[run_id] = {
                "run_id": run_id,
                "run_dir": str(run_dir),
                "scan_name": str(payload.get("scan_name") or run_dir.name),
                "workspace_id": str(payload.get("workspace_id") or payload.get("engagement_id") or ""),
                "workspace_name": str(payload.get("workspace_name") or payload.get("engagement_name") or ""),
            }
    return list(discovered.values())


def _run_workspace_migration(workspace_store: WorkspaceStore, profile_store: GuiProfileStore) -> bool:
    legacy_payload = workspace_store.load_legacy_payload()
    legacy_workspaces = workspace_store.load_workspaces()
    import_roots = _discover_legacy_import_roots(profile_store)
    discovered_runs = _scan_legacy_run_dirs(import_roots)
    workspace_ids = {workspace.workspace_id for workspace in legacy_workspaces}
    run_to_workspace: dict[str, str] = {}
    pending_rows: list[dict[str, str]] = []

    for row in discovered_runs:
        workspace_id = row.get("workspace_id", "")
        if workspace_id in workspace_ids:
            run_to_workspace[row["run_id"]] = workspace_id
            continue
        pending_rows.append(row)

    legacy_states = legacy_payload.get("finding_states", {})
    if isinstance(legacy_states, dict):
        for run_id in legacy_states:
            if not isinstance(run_id, str) or run_id in run_to_workspace:
                continue
            pending_rows.append({"run_id": run_id, "run_dir": f"run:{run_id}", "scan_name": run_id, "workspace_id": ""})

    legacy_audit = legacy_payload.get("audit", [])
    if isinstance(legacy_audit, list):
        for raw in legacy_audit:
            if not isinstance(raw, dict):
                continue
            run_id = str(raw.get("run_id") or "")
            workspace_id = str(raw.get("engagement_id") or raw.get("workspace_id") or "")
            if workspace_id in workspace_ids:
                run_to_workspace[run_id] = workspace_id
            elif run_id and run_id not in run_to_workspace and not any(item.get("run_id") == run_id for item in pending_rows):
                pending_rows.append({"run_id": run_id, "run_dir": f"run:{run_id}", "scan_name": run_id, "workspace_id": ""})

    if pending_rows:
        dialog = WorkspaceMigrationDialog(legacy_workspaces, [str(path) for path in import_roots], pending_rows)
        if dialog.exec() != QDialog.Accepted:
            return False
        for key, workspace_id in dialog.selected_assignments().items():
            run_id = key.removeprefix("run:") if key.startswith("run:") else next(
                (item.get("run_id", "") for item in pending_rows if item.get("run_dir") == key),
                "",
            )
            if run_id:
                run_to_workspace[run_id] = workspace_id

    active_workspace_id = legacy_workspaces[0].workspace_id if legacy_workspaces else ""
    run_registry: dict[str, list[RunRegistryEntry]] = {workspace.workspace_id: [] for workspace in legacy_workspaces}
    run_registry.setdefault(NO_WORKSPACE_SCOPE_ID, [])
    for row in discovered_runs:
        workspace_id = run_to_workspace.get(row["run_id"], row.get("workspace_id", ""))
        scope_id = workspace_id if workspace_id in run_registry else NO_WORKSPACE_SCOPE_ID
        if not row.get("run_dir"):
            continue
        run_registry[scope_id].append(
            RunRegistryEntry(
                run_id=row["run_id"],
                run_dir=row["run_dir"],
                workspace_id=workspace_id if scope_id != NO_WORKSPACE_SCOPE_ID else "",
                scan_name=row.get("scan_name", ""),
                last_known_state="paused" if row.get("workspace_id") else "",
            )
        )

    finding_states: dict[str, dict[str, dict[str, FindingState]]] = {workspace.workspace_id: {} for workspace in legacy_workspaces}
    finding_states.setdefault(NO_WORKSPACE_SCOPE_ID, {})
    if isinstance(legacy_states, dict):
        for run_id, states in legacy_states.items():
            workspace_id = run_to_workspace.get(str(run_id), active_workspace_id)
            scope_id = workspace_id if workspace_id in finding_states else NO_WORKSPACE_SCOPE_ID
            if not isinstance(states, dict):
                continue
            finding_states[scope_id][str(run_id)] = {
                finding_id: FindingState.from_dict(payload)
                for finding_id, payload in states.items()
                if isinstance(finding_id, str) and isinstance(payload, dict)
            }

    audit_rows: dict[str, list[AuditEntry]] = {workspace.workspace_id: [] for workspace in legacy_workspaces}
    audit_rows.setdefault(NO_WORKSPACE_SCOPE_ID, [])
    if isinstance(legacy_audit, list):
        for raw in legacy_audit:
            if not isinstance(raw, dict):
                continue
            entry = AuditEntry.from_dict(raw)
            workspace_id = entry.workspace_id or run_to_workspace.get(entry.run_id, active_workspace_id)
            scope_id = workspace_id if workspace_id in audit_rows else NO_WORKSPACE_SCOPE_ID
            entry.workspace_id = workspace_id if scope_id != NO_WORKSPACE_SCOPE_ID else ""
            audit_rows[scope_id].append(entry)

    workspace_store.apply_migration(
        workspaces=legacy_workspaces,
        active_workspace_id=active_workspace_id,
        run_registry=run_registry,
        finding_states=finding_states,
        audit=audit_rows,
        import_roots=[str(path) for path in import_roots],
    )
    return True
