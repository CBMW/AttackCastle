from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from time import monotonic
from typing import Any

from PySide6.QtCore import QModelIndex, QProcess, QRect, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    FlowButtonRow,
    MappingTableModel,
    RUN_STATE_ORDER,
    SummaryCard,
    apply_responsive_splitter,
    build_workstation_stylesheet,
    configure_scroll_surface,
    ensure_table_defaults,
    finding_metrics,
    format_duration,
    format_progress,
    progress_percent,
    refresh_widget_style,
    set_tooltip,
    set_tooltips,
    summarize_target_input,
    title_case_label,
)
from attackcastle.gui.assets_tab import AssetsTab
from attackcastle.gui.configuration_tab import ConfigurationTab
from attackcastle.gui.dialogs import (
    StartScanDialog,
    WorkspaceChooserDialog,
    WorkspaceDialog,
    WorkspaceMigrationDialog,
)
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.extensions_tab import ExtensionsTab
from attackcastle.gui.models import (
    AuditEntry,
    EntityNote,
    FindingState,
    GuiProfile,
    MigrationState,
    RunRegistryEntry,
    RunSnapshot,
    ScanRequest,
    Workspace,
    now_iso,
)
from attackcastle.gui.output_tab import OutputTab
from attackcastle.gui.profile_store import GuiProfileStore
from attackcastle.gui.runtime import load_run_snapshot
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
        self._selected_run_id: str | None = None
        self._geometry_synced_to_screen = False
        self._nav_order = ["workspaces", "runs", "assets", "findings", "profiles", "extensions", "settings"]
        self._page_indices: dict[str, int] = {}
        self._switch_in_progress = False
        self._init_ui()
        self._apply_initial_geometry()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(1000)
        self._refresh_timer.timeout.connect(self._refresh_runs)
        self._refresh_timer.start()
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
        elif width >= 1180:
            mode = "compact"
        else:
            mode = "stacked"

        self._arrange_cards(self.workspace_card_grid, self.workspace_cards, 4 if mode == "desktop" else 2)
        self.nav_hint.setVisible(mode != "compact")
        if mode == "stacked":
            self.workspace_content_split.setOrientation(Qt.Vertical)
            self.workspace_primary_split.setOrientation(Qt.Vertical if width < 980 else Qt.Horizontal)
            self.workspace_content_split.setSizes([max(int(self.height() * 0.62), 320), max(int(self.height() * 0.38), 220)])
        else:
            self.workspace_content_split.setOrientation(Qt.Horizontal)
            self.workspace_primary_split.setOrientation(Qt.Horizontal)
            self.workspace_content_split.setSizes([max(int(width * 0.7), 700), max(int(width * 0.3), 320)])
            self.workspace_primary_split.setSizes([max(int(width * 0.28), 260), max(int(width * 0.42), 420)])

        if mode == "stacked":
            self.body_split.setSizes([200, max(width - 200, 680)])
        elif mode == "compact":
            self.body_split.setSizes([220, max(width - 220, 760)])
        else:
            self.body_split.setSizes([240, max(width - 240, 900)])

        self._arrange_run_filters(width)
        if hasattr(self, "runs_top_split"):
            if width >= 1360:
                self.runs_top_split.setOrientation(Qt.Horizontal)
                self.runs_top_split.setSizes([max(int(width * 0.24), 300), max(int(width * 0.76), 720)])
            else:
                self.runs_top_split.setOrientation(Qt.Vertical)
                self.runs_top_split.setSizes([max(int(self.height() * 0.18), 150), max(int(self.height() * 0.22), 180)])
        self.output_tab.sync_responsive_mode(width)
        self.scanner_panel.sync_responsive_mode(width)
        self.configuration_tab.sync_profile_form_width(width)

    def _arrange_cards(self, grid: QGridLayout, cards: tuple[SummaryCard, ...], columns: int) -> None:
        while grid.count():
            grid.takeAt(0)
        for index, card in enumerate(cards):
            grid.addWidget(card, index // columns, index % columns)

    def _arrange_run_filters(self, width: int) -> None:
        while self.run_filter_grid.count():
            self.run_filter_grid.takeAt(0)
        if width >= 1480:
            column = 0
            for label, widget in self.run_filter_controls:
                self.run_filter_grid.addWidget(label, 0, column)
                self.run_filter_grid.addWidget(widget, 0, column + 1)
                column += 2
        else:
            for row, (label, widget) in enumerate(self.run_filter_controls):
                self.run_filter_grid.addWidget(label, row, 0)
                self.run_filter_grid.addWidget(widget, row, 1)

    def _init_ui(self) -> None:
        central = QWidget()
        central.setObjectName("appRoot")
        root = QVBoxLayout(central)
        root.setContentsMargins(22, 22, 22, 22)
        root.setSpacing(16)

        header_panel = QFrame()
        header_panel.setObjectName("headerPanel")
        header = QHBoxLayout(header_panel)
        header.setContentsMargins(18, 18, 18, 18)
        header.setSpacing(16)
        self.header_context_label = QLabel("Run context: none selected")
        self.header_context_label.setObjectName("headerMeta")
        self.header_context_label.setVisible(False)
        self.header_workspace_label = QLabel("Workspace: select a project to review scope and activity.")
        self.header_workspace_label.setObjectName("headerMeta")
        self.header_workspace_label.setWordWrap(True)
        header.addWidget(self.header_workspace_label, 1)
        header.addStretch(1)

        status_column = QVBoxLayout()
        status_column.setSpacing(8)
        self.header_status_badge = QLabel("Idle")
        self.header_status_badge.setObjectName("statusBadge")
        status_column.addWidget(self.header_status_badge, 0, Qt.AlignRight)
        header.addLayout(status_column)
        root.addWidget(header_panel)

        self.general_status = QLabel("Ready")
        self.general_status.setObjectName("statusBanner")
        self.general_status.setWordWrap(True)
        self.general_status_detail = QLabel("Workspace, run actions, and findings stay in sync across every section.")
        self.general_status_detail.setObjectName("helperText")
        self.general_status_detail.setWordWrap(True)

        body_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (0, 1))
        self.body_split = body_split
        self.nav_rail = QFrame()
        self.nav_rail.setObjectName("navRail")
        nav_layout = QVBoxLayout(self.nav_rail)
        nav_layout.setContentsMargins(14, 14, 14, 14)
        nav_layout.setSpacing(10)
        nav_title = QLabel("Workflow")
        nav_title.setObjectName("sectionTitle")
        nav_layout.addWidget(nav_title)
        self.nav_list = configure_scroll_surface(QListWidget())
        self.nav_list.setObjectName("navList")
        self.nav_list.currentRowChanged.connect(self._nav_row_changed)
        for label in ("Workspaces", "Scanner", "Assets", "Findings", "Profiles", "Extensions", "Settings"):
            self.nav_list.addItem(QListWidgetItem(label))
        set_tooltip(self.nav_list, "Switch between the main workflow areas of the GUI.")
        nav_layout.addWidget(self.nav_list, 1)
        self.nav_hint = QLabel("Ctrl+1..7 switches sections.")
        self.nav_hint.setObjectName("helperText")
        self.nav_hint.setWordWrap(True)
        nav_layout.addWidget(self.nav_hint)
        body_split.addWidget(self.nav_rail)

        self.section_stack = QStackedWidget()
        self.section_stack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        self.section_stack.setMinimumHeight(0)
        self.workspace_page = self._build_workspace_page()
        self.runs_page = self._build_runs_page()
        self.assets_tab = AssetsTab(self._start_scan_for_target, self._load_entity_notes, self._save_entity_note)
        self.assets_tab.setMinimumHeight(0)
        self.output_tab = OutputTab(self._resolve_snapshot, self._save_finding_state, self._open_local_path)
        self.output_tab.setMinimumHeight(0)
        self.configuration_tab = ConfigurationTab(self.store, self._profiles_changed)
        self.configuration_tab.setMinimumHeight(0)
        self.extensions_tab = ExtensionsTab(self.extension_store, self._apply_theme_manifest, self._open_local_path)
        self.extensions_tab.setMinimumHeight(0)
        self.settings_page = self._build_settings_page()
        for key, page in (
            ("workspaces", self.workspace_page),
            ("runs", self.runs_page),
            ("assets", self.assets_tab),
            ("findings", self.output_tab),
            ("profiles", self.configuration_tab),
            ("extensions", self.extensions_tab),
            ("settings", self.settings_page),
        ):
            self._page_indices[key] = self.section_stack.addWidget(page)
        body_split.addWidget(self.section_stack)
        root.addWidget(body_split, 1)
        self.setCentralWidget(central)

    def _build_workspace_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        card_grid = QGridLayout()
        card_grid.setHorizontalSpacing(14)
        card_grid.setVerticalSpacing(14)
        self.workspace_card_grid = card_grid
        self.card_active_runs = SummaryCard("Active Runs")
        self.card_critical_findings = SummaryCard("Critical + High")
        self.card_needs_validation = SummaryCard("Needs Validation")
        self.card_recent_failures = SummaryCard("Recent Failures")
        self.workspace_cards = (
            self.card_active_runs,
            self.card_critical_findings,
            self.card_needs_validation,
            self.card_recent_failures,
        )
        for idx, card in enumerate(self.workspace_cards):
            card_grid.addWidget(card, 0, idx)
        layout.addLayout(card_grid)

        content_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (5, 2))
        self.workspace_content_split = content_split
        self.workspace_primary_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 3))
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(12)
        left_title = QLabel("Workspaces")
        left_title.setObjectName("sectionTitle")
        left_layout.addWidget(left_title)
        self.workspace_tab_context_label = QLabel("Active session workspace")
        self.workspace_tab_context_label.setObjectName("infoBanner")
        self.workspace_tab_context_label.setWordWrap(True)
        set_tooltip(self.workspace_tab_context_label, "Shows which workspace is currently active for this GUI session.")
        left_layout.addWidget(self.workspace_tab_context_label)
        self.workspace_list = configure_scroll_surface(QListWidget())
        self.workspace_list.setObjectName("sidebarList")
        self.workspace_list.currentRowChanged.connect(self._workspace_selected)
        self.engagement_list = self.workspace_list
        self.workspace_list.setEnabled(False)
        set_tooltip(self.workspace_list, "Shows the active workspace for this session. Switch active workspace from Settings.")
        engagement_buttons = FlowButtonRow()
        self.new_workspace_button = QPushButton("New")
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
        left_layout.addWidget(engagement_buttons)
        self.workspace_summary = configure_scroll_surface(QTextEdit())
        self.workspace_summary.setObjectName("richBrief")
        self.workspace_summary.setReadOnly(True)
        self.engagement_summary = self.workspace_summary
        set_tooltip(self.workspace_summary, "Read-only workspace details for the selected saved project.")
        left_layout.addWidget(self._wrap_group("Workspace Details", self.workspace_summary), 1)
        self.workspace_primary_split.addWidget(left_panel)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setSpacing(12)
        workspace_runs = QWidget()
        workspace_runs_layout = QVBoxLayout(workspace_runs)
        workspace_runs_layout.setContentsMargins(0, 0, 0, 0)
        workspace_runs_layout.setSpacing(10)
        filter_row = QHBoxLayout()
        self.workspace_run_search_edit = QLineEdit()
        self.workspace_run_search_edit.setPlaceholderText("Search current session runs")
        self.workspace_run_search_edit.textChanged.connect(self._sync_workspace_run_table)
        set_tooltip(self.workspace_run_search_edit, "Filter current-session runs by scan name, state, task, or progress.")
        filter_row.addWidget(QLabel("Search"))
        filter_row.addWidget(self.workspace_run_search_edit, 1)
        workspace_runs_layout.addLayout(filter_row)
        self.workspace_run_results_label = QLabel("Showing 0/0 runs")
        self.workspace_run_results_label.setObjectName("helperText")
        workspace_runs_layout.addWidget(self.workspace_run_results_label)
        self.workspace_run_model = MappingTableModel(
            [("Scan Name", "scan_name"), ("State", "state"), ("Current Task", "current_task"), ("Progress", lambda row: row.get("progress") or "--")]
        )
        self.workspace_run_table = configure_scroll_surface(QTableView())
        self.workspace_run_table.setObjectName("dataGrid")
        self.workspace_run_table.setModel(self.workspace_run_model)
        ensure_table_defaults(self.workspace_run_table)
        self.workspace_run_table.clicked.connect(self._workspace_run_selected)
        self.workspace_run_table.doubleClicked.connect(self._focus_output_tab)
        set_tooltip(self.workspace_run_table, "Select a run to inspect it, or double-click to jump into Findings.")
        workspace_runs_layout.addWidget(self.workspace_run_table, 1)
        center_layout.addWidget(self._wrap_group("Runs In Workspace", workspace_runs), 1)
        self.workspace_primary_split.addWidget(center_panel)
        content_split.addWidget(self.workspace_primary_split)

        self.workspace_brief = configure_scroll_surface(QTextEdit())
        self.workspace_brief.setObjectName("richBrief")
        self.workspace_brief.setReadOnly(True)
        self.workspace_brief.setMinimumHeight(120)

        self.run_progress_label = QLabel("No run selected")
        self.run_progress_label.setObjectName("helperText")
        self.run_progress_bar = QProgressBar()
        self.run_progress_bar.setRange(0, 100)
        self.run_progress_bar.setTextVisible(False)
        self.run_progress_bar.setValue(0)
        self.run_brief = configure_scroll_surface(QTextEdit())
        self.run_brief.setObjectName("richBrief")
        self.run_brief.setReadOnly(True)
        self.run_brief.setMinimumHeight(120)

        self.workspace_alerts_text = configure_scroll_surface(QTextEdit())
        self.workspace_alerts_text.setObjectName("consoleText")
        self.workspace_alerts_text.setReadOnly(True)
        self.workspace_alerts_text.setMinimumHeight(140)
        layout.addWidget(content_split, 1)
        return page

    def _build_runs_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        launch_panel = QWidget()
        launch_layout = QVBoxLayout(launch_panel)
        launch_layout.setContentsMargins(0, 0, 0, 0)
        launch_layout.setSpacing(10)
        launch_helper = QLabel("Launch a new scan for the active workspace or continue in the current ad-hoc session.")
        launch_helper.setObjectName("helperText")
        launch_helper.setWordWrap(True)
        self.start_scan_button = QPushButton("New Scan")
        self.start_scan_button.clicked.connect(self._start_scan)
        self.start_scan_button.setToolTip("Start a new scan in the active workspace or ad-hoc session. Shortcut: Ctrl+N.")
        launch_layout.addWidget(launch_helper)
        launch_layout.addWidget(self.start_scan_button, 0, Qt.AlignLeft)

        controls_panel = QWidget()
        controls_layout = QVBoxLayout(controls_panel)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.setSpacing(10)
        self.selected_run_status_label = QLabel("No run selected. Choose a run from the table before using Scanner controls.")
        self.selected_run_status_label.setObjectName("infoBanner")
        self.selected_run_status_label.setWordWrap(True)
        controls_layout.addWidget(self.selected_run_status_label)
        controls_row = FlowButtonRow()
        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(lambda: self._send_control_action("pause"))
        self.pause_button.setToolTip("Pause the selected running job. Shortcut: Ctrl+P.")
        self.resume_button = QPushButton("Resume")
        self.resume_button.clicked.connect(lambda: self._send_control_action("resume"))
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(lambda: self._send_control_action("stop"))
        self.skip_button = QPushButton("Skip Task")
        self.skip_button.clicked.connect(lambda: self._send_control_action("skip"))
        self.retry_button = QPushButton("Retry Run")
        self.retry_button.clicked.connect(self._retry_selected_run)
        self.retry_button.setToolTip("Relaunch the selected run configuration. Shortcut: Ctrl+R.")
        self.open_run_button = QPushButton("Open Run Folder")
        self.open_run_button.clicked.connect(self._open_selected_run_folder)
        self.open_output_button = QPushButton("Open Findings")
        self.open_output_button.clicked.connect(lambda checked=False: self._navigate_to("findings"))
        self.open_health_button = QPushButton("Open Health")
        self.open_health_button.clicked.connect(self._focus_health_panel)
        set_tooltips(
            (
                (self.pause_button, "Pause the selected running job. Shortcut: Ctrl+P."),
                (self.resume_button, "Resume the selected paused run."),
                (self.stop_button, "Stop the selected run."),
                (self.skip_button, "Skip the current task for the selected run."),
                (self.retry_button, "Relaunch the selected run configuration. Shortcut: Ctrl+R."),
                (self.open_run_button, "Open the selected run folder in the file manager."),
                (self.open_output_button, "Open the Findings workspace for the selected run."),
                (self.open_health_button, "Open the Scanner health view for the selected run."),
            )
        )
        for button in (
            self.pause_button,
            self.resume_button,
            self.stop_button,
            self.skip_button,
            self.retry_button,
            self.open_run_button,
            self.open_output_button,
            self.open_health_button,
        ):
            button.setProperty("variant", "secondary")
            controls_row.addWidget(button)
        controls_layout.addWidget(controls_row)
        self.run_actions_hint_label = QLabel("Scanner controls stay disabled until a run is selected.")
        self.run_actions_hint_label.setObjectName("helperText")
        self.run_actions_hint_label.setWordWrap(True)
        controls_layout.addWidget(self.run_actions_hint_label)
        self.runs_top_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 5))
        self.runs_top_split.addWidget(self._wrap_group("Launch", launch_panel))
        self.runs_top_split.addWidget(self._wrap_group("Run Actions", controls_panel))
        layout.addWidget(self.runs_top_split)

        run_panel = QWidget()
        run_layout = QVBoxLayout(run_panel)
        run_layout.setContentsMargins(0, 0, 0, 0)
        run_layout.setSpacing(12)
        self.run_filter_grid = QGridLayout()
        self.run_filter_grid.setHorizontalSpacing(10)
        self.run_filter_grid.setVerticalSpacing(10)
        self.run_search_edit = QLineEdit()
        self.run_search_edit.setPlaceholderText("Search runs, targets, or current task")
        self.run_search_edit.textChanged.connect(self._sync_run_table)
        self.run_state_filter = QComboBox()
        self.run_state_filter.addItems(["All States", "running", "failed", "blocked", "paused", "completed", "cancelled"])
        self.run_state_filter.currentTextChanged.connect(self._sync_run_table)
        set_tooltips(
            (
                (self.run_search_edit, "Filter the run queue by scan name, targets, or current task."),
                (self.run_state_filter, "Show only runs in the selected state."),
            )
        )
        self.run_filter_controls: list[tuple[QLabel, QWidget]] = [
            (QLabel("Search"), self.run_search_edit),
            (QLabel("State"), self.run_state_filter),
        ]
        run_layout.addLayout(self.run_filter_grid)
        self.run_results_label = QLabel("Showing 0/0 runs")
        self.run_results_label.setObjectName("helperText")
        run_layout.addWidget(self.run_results_label)
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
        ensure_table_defaults(self.run_table)
        self.run_table.clicked.connect(self._run_selected)
        self.run_table.doubleClicked.connect(self._focus_output_tab)
        set_tooltip(self.run_table, "Select a run to enable controls, or double-click to open it in Findings.")
        run_layout.addWidget(self.run_table, 1)
        layout.addWidget(self._wrap_group("Run Queue", run_panel), 2)

        self.scanner_panel = ScannerPanel()
        layout.addWidget(self._wrap_group("Scanner Detail", self.scanner_panel), 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        helper = QLabel("Utility paths, about information, and keyboard-first workflow hints live here instead of being buried in a header menu.")
        helper.setObjectName("helperText")
        helper.setWordWrap(True)
        layout.addWidget(helper)
        self.settings_summary_label = QLabel("Operator settings and storage paths.")
        self.settings_summary_label.setObjectName("infoBanner")
        self.settings_summary_label.setWordWrap(True)
        layout.addWidget(self.settings_summary_label)

        session_panel = QWidget()
        session_layout = QVBoxLayout(session_panel)
        session_layout.setContentsMargins(0, 0, 0, 0)
        session_layout.setSpacing(12)
        self.active_workspace_status_label = QLabel("Session workspace: Ad-Hoc")
        self.active_workspace_status_label.setObjectName("infoBanner")
        self.active_workspace_status_label.setWordWrap(True)
        set_tooltip(self.active_workspace_status_label, "Shows the workspace currently bound to this GUI session.")
        self.settings_workspace_combo = QComboBox()
        self.settings_workspace_combo.setObjectName("workspaceSwitchCombo")
        self.settings_workspace_combo.currentIndexChanged.connect(lambda _index: self._update_settings_workspace_switch_actions())
        session_actions = FlowButtonRow()
        self.apply_workspace_button = QPushButton("Apply Workspace")
        self.apply_workspace_button.clicked.connect(self._apply_settings_workspace_selection)
        self.apply_workspace_button.setProperty("variant", "secondary")
        self.settings_ad_hoc_button = QPushButton("Use Ad-Hoc Session")
        self.settings_ad_hoc_button.clicked.connect(self._switch_to_no_workspace)
        self.settings_ad_hoc_button.setProperty("variant", "secondary")
        set_tooltips(
            (
                (self.settings_workspace_combo, "Choose which workspace should be active for this GUI session."),
                (self.apply_workspace_button, "Switch the current GUI session to the selected workspace."),
                (self.settings_ad_hoc_button, "Leave workspace-scoped mode and continue in ad-hoc session mode."),
            )
        )
        session_actions.addWidget(self.apply_workspace_button)
        session_actions.addWidget(self.settings_ad_hoc_button)
        session_layout.addWidget(self.active_workspace_status_label)
        session_layout.addWidget(QLabel("Active workspace"))
        session_layout.addWidget(self.settings_workspace_combo)
        session_layout.addWidget(session_actions)
        layout.addWidget(self._wrap_group("Session Workspace", session_panel))

        store_panel = QWidget()
        store_layout = QVBoxLayout(store_panel)
        store_layout.setContentsMargins(0, 0, 0, 0)
        store_layout.setSpacing(12)
        self.profile_store_path_label = QLabel("")
        self.profile_store_path_label.setObjectName("monoLabel")
        self.profile_store_path_label.setWordWrap(True)
        open_profiles = QPushButton("Open Profile Store Folder")
        open_profiles.setProperty("variant", "secondary")
        open_profiles.clicked.connect(lambda: self._open_local_path(str(self.store.path.parent)))
        self.workspace_store_path_label = QLabel("")
        self.workspace_store_path_label.setObjectName("monoLabel")
        self.workspace_store_path_label.setWordWrap(True)
        open_workspace = QPushButton("Open Workspace Store Folder")
        open_workspace.setProperty("variant", "secondary")
        open_workspace.clicked.connect(lambda: self._open_local_path(str(self.workspace_store.path.parent)))
        about_button = QPushButton("About AttackCastle")
        about_button.setProperty("variant", "secondary")
        about_button.clicked.connect(self._show_about)
        set_tooltips(
            (
                (open_profiles, "Open the folder that stores saved GUI profiles."),
                (open_workspace, "Open the folder that stores workspace metadata, audit, and run registry state."),
                (about_button, "Show a short description of the GUI."),
            )
        )
        shortcuts_label = QLabel("Shortcuts: Ctrl+1..7 navigate sections, Ctrl+N new scan, / focus search, Ctrl+F findings search, Ctrl+P pause/resume, Ctrl+R retry, Ctrl+O open artifact or run folder.")
        shortcuts_label.setObjectName("helperText")
        shortcuts_label.setWordWrap(True)
        store_layout.addWidget(QLabel("Profile store path"))
        store_layout.addWidget(self.profile_store_path_label)
        store_layout.addWidget(open_profiles, 0, Qt.AlignLeft)
        store_layout.addWidget(QLabel("Workspace store path"))
        store_layout.addWidget(self.workspace_store_path_label)
        store_layout.addWidget(open_workspace, 0, Qt.AlignLeft)
        store_layout.addWidget(about_button, 0, Qt.AlignLeft)
        store_layout.addWidget(shortcuts_label)
        layout.addWidget(self._wrap_group("Settings & Paths", store_panel))
        layout.addStretch(1)
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

    def _nav_row_changed(self, row: int) -> None:
        if 0 <= row < len(self._nav_order):
            self.section_stack.setCurrentIndex(self._page_indices[self._nav_order[row]])

    def _navigate_to(self, key: str) -> None:
        if key not in self._page_indices:
            return
        row = self._nav_order.index(key)
        self.nav_list.blockSignals(True)
        self.nav_list.setCurrentRow(row)
        self.nav_list.blockSignals(False)
        self.section_stack.setCurrentIndex(self._page_indices[key])

    def _workspace_run_selected(self, index: QModelIndex) -> None:
        self._run_selected(index)

    def _sync_workspace_run_table(self) -> None:
        search = self.workspace_run_search_edit.text().strip().lower()
        rows = []
        total = 0
        for snapshot in sorted(self._run_snapshots.values(), key=lambda item: (RUN_STATE_ORDER.get(item.state, 99), item.scan_name.lower())):
            total += 1
            row = {
                "run_id": snapshot.run_id,
                "scan_name": snapshot.scan_name,
                "state": snapshot.state,
                "current_task": snapshot.current_task,
                "progress": format_progress(snapshot.completed_tasks, snapshot.total_tasks),
            }
            if search and search not in json.dumps(row, sort_keys=True).lower():
                continue
            rows.append(row)
        self.workspace_run_model.set_rows(rows)
        self.workspace_run_results_label.setText(f"Showing {len(rows)}/{total} runs")

    def _focus_active_search(self) -> None:
        current_key = self._nav_order[self.nav_list.currentRow()] if self.nav_list.currentRow() >= 0 else "workspaces"
        if current_key == "findings":
            self.output_tab.focus_search()
        elif current_key == "assets":
            self.assets_tab.focus_search()
        elif current_key == "runs":
            self.run_search_edit.setFocus()
            self.run_search_edit.selectAll()
        else:
            self.workspace_run_search_edit.setFocus()
            self.workspace_run_search_edit.selectAll()

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
        if self.section_stack.currentWidget() is self.output_tab and self.output_tab.has_current_artifact():
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
        group.setObjectName("panelGroup")
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(14, 18, 14, 14)
        group_layout.addWidget(widget)
        return group

    def _apply_styles(self) -> None:
        self._apply_theme_manifest(self.extension_store.get_active_theme_manifest())

    def _apply_theme_manifest(self, manifest) -> None:
        tokens = manifest.theme.tokens if manifest is not None and manifest.theme is not None else None
        qss_append = manifest.theme.qss_append if manifest is not None and manifest.theme is not None else ""
        self.setStyleSheet(build_workstation_stylesheet(tokens=tokens, qss_append=qss_append))
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
            "AttackCastle GUI\n\nKali-native PySide6 operator workspace for launching, monitoring, comparing, and staging external assessment findings without changing CLI behavior.",
        )

    def _refresh_settings_page(self) -> None:
        if not hasattr(self, "profile_store_path_label"):
            return
        self.profile_store_path_label.setText(str(self.store.path))
        self.workspace_store_path_label.setText(str(self.workspace_store.path))
        self._sync_settings_workspace_switcher()
        self.settings_summary_label.setText(
            f"Profiles: {len(self._profiles)} stored | Workspaces: {len(self._workspaces)} tracked | Active runs: {len(self._run_snapshots)}"
        )

    def _sync_settings_workspace_switcher(self) -> None:
        if not hasattr(self, "settings_workspace_combo"):
            return
        active_workspace = self._active_workspace()
        self.settings_workspace_combo.blockSignals(True)
        self.settings_workspace_combo.clear()
        self.settings_workspace_combo.addItem("No Workspace (Ad-Hoc Session)", "")
        for workspace in self._workspaces:
            label = workspace.name
            if workspace.client_name:
                label += f" | {workspace.client_name}"
            self.settings_workspace_combo.addItem(label, workspace.workspace_id)
        current_index = self.settings_workspace_combo.findData(self._active_workspace_id)
        self.settings_workspace_combo.setCurrentIndex(current_index if current_index >= 0 else 0)
        self.settings_workspace_combo.blockSignals(False)
        if active_workspace is None:
            self.active_workspace_status_label.setText("Session workspace: Ad-Hoc")
        else:
            self.active_workspace_status_label.setText(
                f"Session workspace: {active_workspace.name} | Client: {active_workspace.client_name or 'Unassigned'}"
            )
        self._update_settings_workspace_switch_actions()

    def _update_settings_workspace_switch_actions(self) -> None:
        if not hasattr(self, "settings_workspace_combo"):
            return
        target_workspace_id = str(self.settings_workspace_combo.currentData() or "")
        self.apply_workspace_button.setEnabled(
            not self._switch_in_progress and target_workspace_id != self._active_workspace_id
        )
        self.settings_ad_hoc_button.setEnabled(
            not self._switch_in_progress and bool(self._active_workspace_id)
        )

    def _apply_settings_workspace_selection(self) -> None:
        workspace_id = str(self.settings_workspace_combo.currentData() or "")
        self._switch_workspace(workspace_id)

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
            elif event.event == "artifact.available":
                self._append_unique(snapshot.artifacts, {
                    "path": payload.get("artifact_path", ""),
                    "kind": payload.get("kind", ""),
                    "source_tool": payload.get("source_tool", ""),
                    "caption": payload.get("caption", ""),
                }, "path")
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

    def _apply_task_event(self, snapshot: RunSnapshot, event_name: str, payload: dict[str, Any]) -> None:
        task_key = str(payload.get("task") or "")
        if not task_key:
            return
        row = {
            "key": task_key,
            "label": payload.get("label") or task_key,
            "status": payload.get("status") or event_name.replace("task.", ""),
            "started_at": payload.get("started_at") or "",
            "ended_at": payload.get("ended_at") or "",
            "detail": {"reason": payload.get("reason"), "attempt": payload.get("attempt")},
        }
        for idx, existing in enumerate(snapshot.tasks):
            if str(existing.get("key") or "") == task_key:
                merged = dict(existing)
                merged.update({k: v for k, v in row.items() if v not in {"", None}})
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
            if snapshot.state in {"completed", "failed", "cancelled"} and snapshot.run_dir:
                try:
                    refreshed_snapshot = load_run_snapshot(Path(snapshot.run_dir))
                except Exception:
                    refreshed_snapshot = snapshot
            else:
                snapshot.elapsed_seconds = round(snapshot.elapsed_seconds + (self._refresh_timer.interval() / 1000.0), 1)
                self._refresh_snapshot_issue_state(snapshot)
                refreshed_snapshot = snapshot
            entry = registry_by_run.get(run_id)
            if entry is not None:
                self._apply_registry_overrides(refreshed_snapshot, entry)
            refreshed[run_id] = refreshed_snapshot
        self._run_snapshots = refreshed
        self._sync_run_table()
        self._update_output_snapshot(self._selected_run_id)
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
        self.output_tab.set_compare_options(list(self._run_snapshots.values()), self._selected_run_id)
        self._update_run_action_state()

    def _run_selected(self, index: QModelIndex) -> None:
        row = index.data(Qt.UserRole) or {}
        run_id = row.get("run_id")
        if isinstance(run_id, str) and run_id in self._run_snapshots:
            self._selected_run_id = run_id
            self._update_output_snapshot(run_id)
            self.general_status.setText(f"Selected: {self._run_snapshots[run_id].scan_name}")
            self._refresh_health_panel()
            self._refresh_context_panels()
            self._update_run_action_state()

    def _focus_output_tab(self, index: QModelIndex) -> None:
        self._run_selected(index)
        self._navigate_to("findings")
        self.output_tab.focus_findings()

    def _update_output_snapshot(self, run_id: str | None) -> None:
        if not run_id or run_id not in self._run_snapshots:
            self.assets_tab.set_snapshot(None)
            self.output_tab.set_snapshot(None)
            self.scanner_panel.set_snapshot(None)
            return
        snapshot = self._run_snapshots[run_id]
        self.assets_tab.set_snapshot(snapshot)
        self.output_tab.set_snapshot(snapshot, self._finding_states_by_run.get(run_id, {}))
        self.scanner_panel.set_snapshot(snapshot)
        self.output_tab.set_compare_options(list(self._run_snapshots.values()), run_id)

    def _resolve_snapshot(self, run_id: str) -> RunSnapshot | None:
        return self._run_snapshots.get(run_id)

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
        active_runs = [item for item in self._run_snapshots.values() if item.state == "running"]
        failed_runs = [item for item in self._run_snapshots.values() if item.state in {"failed", "blocked"}]
        findings = 0
        critical_high = 0
        needs_validation = 0
        for snapshot in self._run_snapshots.values():
            metrics = finding_metrics(snapshot.findings, self._finding_states_by_run.get(snapshot.run_id, {}))
            findings += len(snapshot.findings)
            critical_high += metrics["critical_high"]
            for finding in snapshot.findings:
                state = self._finding_states_by_run.get(snapshot.run_id, {}).get(str(finding.get("finding_id") or ""))
                if state is None or state.status == "needs-validation":
                    needs_validation += 1
        self.card_active_runs.set_value(str(len(active_runs)), f"{len(self._run_snapshots)} runs tracked")
        self.card_critical_findings.set_value(str(critical_high), f"{findings} total findings across tracked runs")
        self.card_needs_validation.set_value(str(needs_validation), "Analyst attention queue")
        latest_failure = failed_runs[0].scan_name if failed_runs else "No failed or blocked runs"
        self.card_recent_failures.set_value(str(len(failed_runs)), latest_failure)
        self._refresh_context_panels()
        self._refresh_workspace_alerts()

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
            self.workspace_tab_context_label.setText(
                f"Active workspace: {active_workspace.name} | Client: {active_workspace.client_name or 'Unassigned'}"
            )
            self.workspace_list.setCurrentRow(0)
            self._workspace_selected(0)
        else:
            self._selected_workspace_id = ""
            self._selected_engagement_id = ""
            self.workspace_tab_context_label.setText("Active workspace: Ad-Hoc session")
            if self._workspaces:
                self.workspace_summary.setPlainText("Ad-hoc mode is active. Switch to a saved workspace from Settings when you want project-scoped context.")
            else:
                self.workspace_summary.setPlainText("No saved workspaces yet. Use the workspace editor to create one, or continue in ad-hoc mode.")
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
            f"Workspace Home: {workspace.home_dir}\n"
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
        if hasattr(self, "settings_workspace_combo"):
            self._sync_settings_workspace_switcher()

    def _new_workspace(self) -> None:
        dialog = WorkspaceDialog(parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        workspace = dialog.build_workspace()
        self.workspace_store.save_workspace(workspace)
        self._workspaces = self.workspace_store.load_workspaces()
        self._selected_workspace_id = workspace.workspace_id
        self._append_audit("workspace.created", f"Created workspace {workspace.name}", workspace_id=workspace.workspace_id)
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
        self._append_audit("workspace.updated", f"Updated workspace {updated.name}", workspace_id=updated.workspace_id)
        self._sync_workspace_list()
        if updated.workspace_id == self._active_workspace_id:
            self._refresh_context_panels()

    def _delete_selected_workspace(self) -> None:
        workspace = self._selected_workspace()
        if workspace is None:
            return
        if self.workspace_store.load_run_registry(workspace.workspace_id):
            QMessageBox.information(
                self,
                "Workspace Has Runs",
                "This workspace still has tracked runs and cannot be deleted. Archive or remove the run registry entries first.",
            )
            return
        if QMessageBox.question(self, "Delete Workspace", f"Delete workspace '{workspace.name}'?") != QMessageBox.Yes:
            return
        self.workspace_store.delete_workspace(workspace.workspace_id)
        self._workspaces = self.workspace_store.load_workspaces()
        self._selected_workspace_id = self._workspaces[0].workspace_id if self._workspaces else ""
        self._sync_workspace_list()

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
                QMessageBox.warning(self, "Workspace Switch Failed", f"Could not pause {snapshot.scan_name} before switching workspaces.")
                return False
            snapshot.pause_requested = True
            snapshot.resume_required = True
            self._sync_run_registry_for_snapshot(snapshot)

        if running_live_ids and not self._wait_for_paused_runs(running_live_ids):
            self._switch_in_progress = False
            self._update_workspace_action_state()
            QMessageBox.warning(
                self,
                "Workspace Switch Failed",
                "One or more runs did not acknowledge pause in time. The current workspace is still active.",
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
        self._refresh_audit_table()
        self._sync_run_table()
        self._refresh_dashboard()
        self._refresh_health_panel()
        self._refresh_settings_page()

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
            self._refresh_workspace_alerts()

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
        self._refresh_workspace_brief()
        self._refresh_run_brief()
        self._refresh_header_context()
        self._refresh_workspace_alerts()

    def _refresh_workspace_alerts(self) -> None:
        snapshot = self._selected_snapshot()
        lines: list[str] = []
        if snapshot is not None:
            metrics = finding_metrics(snapshot.findings, self._finding_states_by_run.get(snapshot.run_id, {}))
            issue_count = int(snapshot.execution_issues_summary.get("total_count", 0) or 0)
            if metrics["critical_high"]:
                lines.append(f"- {metrics['critical_high']} critical/high findings on {snapshot.scan_name}")
            pending_validation = sum(
                1
                for finding in snapshot.findings
                if (
                    self._finding_states_by_run.get(snapshot.run_id, {}).get(str(finding.get("finding_id") or "")) is None
                    or self._finding_states_by_run.get(snapshot.run_id, {}).get(str(finding.get("finding_id") or "")).status == "needs-validation"
                )
            )
            if pending_validation:
                lines.append(f"- {pending_validation} findings still need validation")
            if issue_count:
                lines.append(f"- {issue_count} execution issue(s) affecting completeness on {snapshot.scan_name}")
        recent_failures = [item for item in self._run_snapshots.values() if item.state in {"failed", "blocked"}][:3]
        for failed in recent_failures:
            lines.append(f"- {failed.scan_name} is {title_case_label(failed.state)}")
        if not lines:
            lines.append("- No urgent operator alerts. Use quick filters in Findings to drill into triage queues.")
        self.workspace_alerts_text.setPlainText("\n".join(lines))

    def _refresh_workspace_brief(self) -> None:
        workspace = self._active_workspace()
        if workspace is None:
            self.workspace_brief.setHtml(
                f"<h3>No Workspace</h3><p>Ad-hoc session mode is active.</p><p><b>Home:</b> {ad_hoc_output_home()}<br>"
                "<b>Saved Projects:</b> Use the workspace editor or startup chooser whenever you want project-scoped context.</p>"
            )
            return
        active_runs = [item for item in self._run_snapshots.values() if item.state == "running"]
        finding_total = sum(len(item.findings) for item in self._run_snapshots.values())
        latest_audit = next(
            (entry.summary for entry in reversed(self._audit_entries) if entry.workspace_id == workspace.workspace_id),
            "No recent workspace activity.",
        )
        self.workspace_brief.setHtml(
            f"<h3>{workspace.name}</h3>"
            f"<p><b>Client:</b> {workspace.client_name or 'Unassigned'}<br>"
            f"<b>Home:</b> {workspace.home_dir}<br>"
            f"<b>Scope:</b> {workspace.scope_summary or 'Scope not documented yet.'}</p>"
            f"<p><b>Operational Snapshot:</b> {len(self._run_snapshots)} tracked runs, {len(active_runs)} active, {finding_total} findings captured.</p>"
            f"<p><b>Latest Activity:</b> {latest_audit}</p>"
        )

    def _refresh_run_brief(self) -> None:
        snapshot = self._selected_snapshot()
        if snapshot is None:
            self.run_progress_label.setText("No run selected")
            self.run_progress_bar.setValue(0)
            self.run_brief.setHtml("<h3>Run Brief</h3><p>Select a run to review progress, triage posture, and current operator health.</p>")
            return
        metrics = finding_metrics(snapshot.findings, self._finding_states_by_run.get(snapshot.run_id, {}))
        self.run_progress_label.setText(
            f"{format_progress(snapshot.completed_tasks, snapshot.total_tasks)} | State: {title_case_label(snapshot.state)}"
        )
        self.run_progress_bar.setValue(progress_percent(snapshot.completed_tasks, snapshot.total_tasks))
        self.run_brief.setHtml(
            f"<h3>{snapshot.scan_name}</h3>"
            f"<p><b>Workspace:</b> {snapshot.workspace_name or 'Ad-Hoc Session'}<br>"
            f"<b>Target Summary:</b> {summarize_target_input(snapshot.target_input)}<br>"
            f"<b>Current Task:</b> {snapshot.current_task}<br>"
            f"<b>Elapsed:</b> {format_duration(snapshot.elapsed_seconds)} | <b>ETA:</b> {format_duration(snapshot.eta_seconds)}</p>"
            f"<p><b>Triage Snapshot:</b> {metrics['critical_high']} critical/high, {metrics['report_ready']} report-ready, "
            f"{metrics['confirmed']} confirmed findings.</p>"
            f"<p><b>Execution Health:</b> {title_case_label(snapshot.completeness_status)} with "
            f"{snapshot.execution_issues_summary.get('total_count', 0)} issue(s). Review Scanner &gt; Issues for detail.</p>"
            f"<p><b>Surface:</b> {len(snapshot.assets)} assets, {len(snapshot.services)} services, {len(snapshot.web_apps)} web apps, "
            f"{len(snapshot.technologies)} technologies.</p>"
        )

    def _refresh_header_context(self) -> None:
        workspace = self._active_workspace()
        snapshot = self._selected_snapshot()
        if snapshot is None:
            self.header_context_label.setText("Run context: none selected")
            self.header_status_badge.setText("Idle")
            self.header_status_badge.setProperty("state", "idle")
        else:
            self.header_context_label.setText(
                f"Run context: {snapshot.scan_name} | {title_case_label(snapshot.state)} | {format_progress(snapshot.completed_tasks, snapshot.total_tasks)}"
            )
            self.header_status_badge.setText(title_case_label(snapshot.state))
            self.header_status_badge.setProperty("state", snapshot.state)
        if workspace is None:
            self.header_workspace_label.setText("Workspace: No Workspace (Ad-Hoc Session)")
        else:
            self.header_workspace_label.setText(
                f"Workspace: {workspace.name} | Client: {workspace.client_name or 'Unassigned'}"
            )
        refresh_widget_style(self.header_status_badge)

    def _update_run_action_state(self) -> None:
        snapshot = self._selected_snapshot()
        has_snapshot = snapshot is not None
        for button in (
            self.pause_button,
            self.resume_button,
            self.stop_button,
            self.skip_button,
            self.retry_button,
            self.open_run_button,
            self.open_output_button,
            self.open_health_button,
        ):
            button.setEnabled(has_snapshot)
        if snapshot is None:
            self.selected_run_status_label.setText(
                "No run selected. Choose a run from the table before using Scanner controls."
            )
            self.run_actions_hint_label.setText("Scanner controls stay disabled until a run is selected.")
            self.general_status_detail.setText(
                "Select a run to review context, health, and findings for the current session."
            )
            return
        self.selected_run_status_label.setText(
            f"{snapshot.scan_name} is {title_case_label(snapshot.state)} and {progress_percent(snapshot.completed_tasks, snapshot.total_tasks)}% complete."
        )
        self.run_actions_hint_label.setText(self._selected_run_action_hint(snapshot))
        issue_count = int(snapshot.execution_issues_summary.get("total_count", 0) or 0)
        self.general_status_detail.setText(
            f"Focused on {snapshot.workspace_name or 'the ad-hoc session'} with {issue_count} execution issue(s). "
            "Use Scanner > Issues for the consolidated review."
        )

    def _selected_run_action_hint(self, snapshot: RunSnapshot) -> str:
        if snapshot.state == "running":
            return "Use Pause, Stop, or Skip Task to adjust the active run without leaving the Scanner dashboard."
        if snapshot.state == "paused":
            return "Resume restarts execution. Open Findings and Open Health are available for review before continuing."
        if snapshot.state in {"failed", "blocked"}:
            return "Review Scanner health first, then retry the run or inspect the run folder for artifacts and logs."
        if snapshot.state in {"completed", "cancelled"}:
            return "Open Findings to review results or Retry Run to launch the same configuration again."
        return "Open Findings, Open Health, or the run folder to inspect the current run."


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
