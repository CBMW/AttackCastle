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
    QMenu,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
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
    PAGE_CARD_SPACING,
    PAGE_SECTION_SPACING,
    PANEL_CONTENT_PADDING,
    PANEL_COMPACT_PADDING,
    PersistentSplitterController,
    RUN_STATE_ORDER,
    SURFACE_FLAT,
    SURFACE_PRIMARY,
    SURFACE_SECONDARY,
    apply_responsive_splitter,
    build_inspector_panel,
    build_section_header,
    build_surface_frame,
    build_table_section,
    build_workstation_stylesheet,
    configure_scroll_surface,
    ensure_table_defaults,
    format_duration,
    format_progress,
    progress_percent,
    refresh_widget_style,
    style_button,
    set_tooltip,
    set_tooltips,
    summarize_target_input,
    table_height_for_rows,
    title_case_label,
)
from attackcastle.gui.asset_inventory import build_workspace_inventory_snapshot
from attackcastle.gui.assets_tab import AssetsTab
from attackcastle.gui.configuration_tab import ConfigurationTab
from attackcastle.gui.dialogs import (
    DebugLogDialog,
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
    OverviewChecklistItem,
    RunRegistryEntry,
    RunSnapshot,
    ScanRequest,
    Workspace,
    WorkspaceOverviewState,
    now_iso,
)
from attackcastle.gui.overview_checklist import OverviewChecklistPanel
from attackcastle.gui.output_tab import OutputTab
from attackcastle.gui.profile_store import GuiProfileStore
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
        self._nav_order = ["workspaces", "runs", "assets", "findings", "profiles", "extensions", "settings"]
        self._page_indices: dict[str, int] = {}
        self._splitter_controllers: dict[str, PersistentSplitterController] = {}
        self._switch_in_progress = False
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

        self.nav_hint.setVisible(mode != "compact")
        if mode == "stacked":
            self.workspace_content_split.setOrientation(Qt.Vertical)
            self.workspace_primary_split.setOrientation(Qt.Vertical if width < 980 else Qt.Horizontal)
            self._apply_splitter_layout(
                "workspace_content_split",
                [max(int(self.height() * 0.56), 420), max(int(self.height() * 0.44), 280)],
            )
            self._apply_splitter_layout(
                "workspace_primary_split",
                [max(int(width * 0.34), 280), max(int(self.height() * 0.48), 320)],
            )
        else:
            self.workspace_content_split.setOrientation(Qt.Horizontal)
            self.workspace_primary_split.setOrientation(Qt.Horizontal)
            self._apply_splitter_layout(
                "workspace_content_split",
                [max(int(width * 0.72), 760), max(int(width * 0.28), 320)],
            )
            self._apply_splitter_layout(
                "workspace_primary_split",
                [max(int(width * 0.28), 260), max(int(width * 0.42), 420)],
            )
        if mode == "stacked":
            self._apply_splitter_layout("body_split", [200, max(width - 200, 680)])
        elif mode == "compact":
            self._apply_splitter_layout("body_split", [220, max(width - 220, 760)])
        else:
            self._apply_splitter_layout("body_split", [240, max(width - 240, 900)])

        self._arrange_run_filters(width)
        if hasattr(self, "runs_page_split"):
            if width >= 1360:
                self.runs_page_split.setOrientation(Qt.Horizontal)
                self._apply_splitter_layout(
                    "runs_page_split",
                    [max(int(width * 0.24), 320), max(int(width * 0.76), 920)],
                )
            else:
                self.runs_page_split.setOrientation(Qt.Vertical)
                self._apply_splitter_layout(
                    "runs_page_split",
                    [max(int(self.height() * 0.34), 280), max(int(self.height() * 0.66), 480)],
                )
        if hasattr(self, "runs_top_split"):
            self.runs_top_split.setOrientation(Qt.Vertical)
            self._apply_splitter_layout(
                "runs_top_split",
                [max(int(self.height() * 0.18), 170), max(int(self.height() * 0.42), 380)],
            )
        if hasattr(self, "runs_body_split"):
            if width >= 1240:
                self.runs_body_split.setOrientation(Qt.Horizontal)
                content_width = max(int(width * (0.76 if width >= 1360 else 0.96)), 920)
                self._apply_splitter_layout(
                    "runs_body_split",
                    [max(int(content_width * 0.58), 560), max(int(content_width * 0.42), 400)],
                )
            else:
                self.runs_body_split.setOrientation(Qt.Vertical)
                self._apply_splitter_layout(
                    "runs_body_split",
                    [max(int(self.height() * 0.42), 300), max(int(self.height() * 0.42), 320)],
                )
        if hasattr(self, "settings_split"):
            if width >= 1260:
                self.settings_split.setOrientation(Qt.Horizontal)
                self._apply_splitter_layout(
                    "settings_split",
                    [max(int(width * 0.46), 420), max(int(width * 0.54), 500)],
                )
            else:
                self.settings_split.setOrientation(Qt.Vertical)
                self._apply_splitter_layout(
                    "settings_split",
                    [max(int(self.height() * 0.28), 220), max(int(self.height() * 0.42), 320)],
                )
        self.output_tab.sync_responsive_mode(width)
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
        else:
            for row, (label, widget) in enumerate(self.run_filter_controls):
                self.run_filter_grid.addWidget(label, row, 0)
                self.run_filter_grid.addWidget(widget, row, 1)

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
        central = QWidget()
        central.setObjectName("appRoot")
        root = QVBoxLayout(central)
        root.setContentsMargins(22, 22, 22, 22)
        root.setSpacing(PAGE_SECTION_SPACING)

        self.general_status = QLabel("Ready")
        self.general_status_detail = QLabel("Workspace, run actions, and findings stay in sync across every section.")

        body_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (0, 1))
        self.body_split = body_split
        self._register_splitter(self.body_split, "body_split")
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
        for label in ("Overview", "Scanner", "Assets", "Findings", "Profiles", "Extensions", "Settings"):
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
        self.assets_tab = AssetsTab(
            self._start_scan_for_target,
            self._load_entity_notes,
            self._save_entity_note,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
        self.assets_tab.setMinimumHeight(0)
        self.output_tab = OutputTab(
            self._resolve_snapshot,
            self._save_finding_state,
            self._open_local_path,
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
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
            layout_loader=self._load_ui_layout,
            layout_saver=self._save_ui_layout,
        )
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
        layout.setSpacing(PAGE_SECTION_SPACING)

        content_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (5, 2))
        self.workspace_content_split = content_split
        self._register_splitter(self.workspace_content_split, "workspace_content_split")
        self.workspace_primary_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 3))
        self._register_splitter(self.workspace_primary_split, "workspace_primary_split")
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(PAGE_SECTION_SPACING)
        left_top_panel = QWidget()
        left_top_layout = QVBoxLayout(left_top_panel)
        left_top_layout.setContentsMargins(0, 0, 0, 0)
        left_top_layout.setSpacing(10)
        left_title = QLabel("Overview")
        left_title.setObjectName("sectionTitle")
        left_top_layout.addWidget(left_title)
        self.workspace_tab_context_label = QLabel("Active session workspace")
        self.workspace_tab_context_label.setObjectName("infoBanner")
        self.workspace_tab_context_label.setWordWrap(True)
        set_tooltip(self.workspace_tab_context_label, "Shows which workspace is currently active for this GUI session.")
        left_top_layout.addWidget(self.workspace_tab_context_label)
        self.workspace_list = configure_scroll_surface(QListWidget(left_panel))
        self.workspace_list.setObjectName("sidebarList")
        self.workspace_list.currentRowChanged.connect(self._workspace_selected)
        self.engagement_list = self.workspace_list
        self.workspace_list.setEnabled(False)
        self.workspace_list.hide()
        set_tooltip(self.workspace_list, "Shows the active workspace for this session. Switch active workspace from Settings.")
        engagement_buttons = FlowButtonRow()
        self.new_workspace_button = QPushButton("New Workspace")
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
        set_tooltip(self.workspace_summary, "Read-only workspace details for the selected saved project.")
        workspace_summary_panel, _workspace_summary_title, _workspace_summary_summary = build_inspector_panel(
            "Workspace Details",
            self.workspace_summary,
        )
        left_layout.addWidget(left_top_panel)
        left_layout.addWidget(workspace_summary_panel, 1)
        self.workspace_primary_split.addWidget(left_panel)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(PAGE_SECTION_SPACING)
        workspace_runs = QWidget()
        workspace_runs_layout = QVBoxLayout(workspace_runs)
        workspace_runs_layout.setContentsMargins(0, 0, 0, 0)
        workspace_runs_layout.setSpacing(10)
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(10)
        self.workspace_run_search_edit = QLineEdit()
        self.workspace_run_search_edit.setPlaceholderText("Search current session runs")
        self.workspace_run_search_edit.textChanged.connect(self._sync_workspace_run_table)
        set_tooltip(self.workspace_run_search_edit, "Filter current-session runs by scan name, state, task, or progress.")
        filter_row.addWidget(QLabel("Search"))
        filter_row.addWidget(self.workspace_run_search_edit, 1)
        self.workspace_run_results_label = QLabel("Showing 0/0 runs")
        self.workspace_run_results_label.setObjectName("helperText")
        self.workspace_run_results_label.setWordWrap(True)
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
        workspace_toolbar, workspace_toolbar_layout = build_surface_frame(
            surface=SURFACE_FLAT,
            padding=0,
            spacing=8,
        )
        workspace_toolbar.setObjectName("toolbarStrip")
        workspace_toolbar_layout.setContentsMargins(0, 0, 0, 0)
        workspace_toolbar_layout.addLayout(filter_row)
        runs_panel, _runs_title, _runs_summary = build_table_section(
            "Runs In Workspace",
            workspace_runs,
            surface=SURFACE_PRIMARY,
            toolbar=workspace_toolbar,
            status_label=self.workspace_run_results_label,
        )
        center_layout.addWidget(runs_panel, 1)
        self.workspace_primary_split.addWidget(center_panel)

        inspector_body = QWidget()
        inspector_layout = QVBoxLayout(inspector_body)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        inspector_layout.setSpacing(10)

        self.overview_checklist_panel = OverviewChecklistPanel()
        self.overview_checklist_panel.add_requested.connect(self._add_overview_checklist_item)
        self.overview_checklist_panel.toggled.connect(self._toggle_overview_checklist_item)
        self.overview_checklist_panel.delete_requested.connect(self._delete_overview_checklist_item)

        # The right rail is already a primary panel, so keep inner sections lighter and let spacing do the grouping.
        notes_panel, notes_layout = build_surface_frame(
            object_name="sectionPanel",
            surface=SURFACE_SECONDARY,
            padding=12,
            spacing=10,
        )
        notes_header = QLabel("Notes")
        notes_header.setObjectName("sectionTitle")
        self.overview_notes_edit = configure_scroll_surface(QPlainTextEdit())
        self.overview_notes_edit.setObjectName("consoleText")
        self.overview_notes_edit.setPlaceholderText("Operator notes for this engagement...")
        self.overview_notes_edit.textChanged.connect(self._handle_overview_notes_changed)
        notes_layout.addWidget(notes_header)
        notes_layout.addWidget(self.overview_notes_edit, 1)

        inspector_layout.addWidget(self.overview_checklist_panel, 1)
        inspector_layout.addWidget(notes_panel, 1)
        inspector_panel, inspector_panel_layout = build_surface_frame(
            object_name="inspectorPanel",
            surface=SURFACE_PRIMARY,
            spacing=10,
        )
        inspector_panel_layout.addWidget(inspector_body, 1)

        content_split.addWidget(self.workspace_primary_split)
        content_split.addWidget(inspector_panel)
        layout.addWidget(content_split, 1)
        return page

    def _build_runs_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("scannerPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        # Keep the left rail aligned to the operator workflow: launch a scan, then act on the selected run.
        self.runs_top_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (2, 5))
        self._register_splitter(self.runs_top_split, "runs_top_split")
        self.runs_top_split.setChildrenCollapsible(False)
        self.runs_top_split.addWidget(self._wrap_group("", self._build_scanner_launch_card()))
        self.runs_top_split.addWidget(self._wrap_group("Active Run", self._build_selected_run_control_card()))
        runs_control_panel = QFrame()
        runs_control_panel.setObjectName("scannerConsoleLeftColumn")
        runs_control_panel.setProperty("surface", SURFACE_PRIMARY)
        runs_control_panel.setMinimumWidth(300)
        runs_control_layout = QVBoxLayout(runs_control_panel)
        runs_control_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        runs_control_layout.setSpacing(PAGE_SECTION_SPACING)
        runs_control_layout.addWidget(self.runs_top_split, 1)

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
        run_toolbar, run_toolbar_layout = build_surface_frame(
            surface=SURFACE_FLAT,
            padding=0,
            spacing=8,
        )
        run_toolbar.setObjectName("toolbarStrip")
        run_toolbar_layout.setContentsMargins(0, 0, 0, 0)
        run_toolbar_layout.addLayout(self.run_filter_grid)
        self.run_results_label = QLabel("Showing 0/0 runs")
        self.run_results_label.setObjectName("helperText")
        self.run_results_label.setWordWrap(True)
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
        set_tooltip(self.run_table, "Select a run to enable controls, or double-click to open it in Findings.")
        self.scanner_panel = ScannerPanel(layout_loader=self._load_ui_layout, layout_saver=self._save_ui_layout)
        self.scanner_panel.set_context_menu_handler(self._handle_scanner_context_menu)
        self.runs_body_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (3, 4))
        self._register_splitter(self.runs_body_split, "runs_body_split")
        run_queue_panel, _queue_title, _queue_summary = build_table_section(
            "Run Queue",
            self.run_table,
            summary_text="",
            surface=SURFACE_PRIMARY,
            toolbar=run_toolbar,
            status_label=self.run_results_label,
        )
        scanner_detail_panel, _scanner_title, _scanner_summary = build_inspector_panel(
            "Scanner Detail",
            self.scanner_panel,
            summary_text="",
            surface=SURFACE_PRIMARY,
        )
        self.runs_body_split.addWidget(run_queue_panel)
        self.runs_body_split.addWidget(scanner_detail_panel)
        self.runs_page_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 5))
        self._register_splitter(self.runs_page_split, "runs_page_split")
        self.runs_page_split.addWidget(runs_control_panel)
        self.runs_page_split.addWidget(self.runs_body_split)
        layout.addWidget(self.runs_page_split, 1)
        return page

    def _build_scanner_launch_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("scannerLaunchCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.start_scan_button = QPushButton("Launch New Scan")
        self.start_scan_button.setObjectName("scannerStartButton")
        self.start_scan_button.clicked.connect(self._start_scan)
        self.start_scan_button.setToolTip("Start a new scan in the active workspace or ad-hoc session. Shortcut: Ctrl+N.")
        style_button(self.start_scan_button, min_height=48)
        self.start_scan_button.setMinimumWidth(220)
        self.start_scan_button.setMaximumWidth(320)
        self.start_scan_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout.addStretch(1)
        layout.addWidget(self.start_scan_button, 0, Qt.AlignCenter)
        layout.addStretch(1)
        return card

    def _build_selected_run_control_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("scannerRunCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_CARD_SPACING)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(10)
        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(4)

        self.selected_run_name_label = QLabel("No run selected")
        self.selected_run_name_label.setObjectName("scannerRunName")
        self.selected_run_name_label.setWordWrap(True)
        self.selected_run_target_label = QLabel("Choose a run from the queue to inspect and control it here.")
        self.selected_run_target_label.setObjectName("scannerRunContext")
        self.selected_run_target_label.setWordWrap(True)
        header_text.addWidget(self.selected_run_name_label)
        header_text.addWidget(self.selected_run_target_label)

        self.selected_run_state_badge = QLabel("Idle")
        self.selected_run_state_badge.setObjectName("statusBadge")
        self.selected_run_state_badge.setProperty("state", "idle")
        self.selected_run_state_badge.setAlignment(Qt.AlignCenter)

        header_row.addLayout(header_text, 1)
        header_row.addWidget(self.selected_run_state_badge, 0, Qt.AlignTop)
        layout.addLayout(header_row)

        self.selected_run_status_label = QLabel("No run selected. Choose a run from the table before using Scanner controls.")
        self.selected_run_status_label.setObjectName("scannerRunSummaryText")
        self.selected_run_status_label.setWordWrap(True)
        layout.addWidget(self.selected_run_status_label)

        summary_grid = QGridLayout()
        summary_grid.setContentsMargins(0, 0, 0, 0)
        summary_grid.setHorizontalSpacing(10)
        summary_grid.setVerticalSpacing(10)
        progress_tile, self.selected_run_progress_value = self._build_scanner_summary_tile("Progress")
        task_tile, self.selected_run_task_value = self._build_scanner_summary_tile("Current Task")
        elapsed_tile, self.selected_run_elapsed_value = self._build_scanner_summary_tile("Elapsed")
        eta_tile, self.selected_run_eta_value = self._build_scanner_summary_tile("ETA")
        summary_grid.addWidget(progress_tile, 0, 0)
        summary_grid.addWidget(task_tile, 0, 1)
        summary_grid.addWidget(elapsed_tile, 1, 0)
        summary_grid.addWidget(eta_tile, 1, 1)
        layout.addLayout(summary_grid)

        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(lambda: self._send_control_action("pause"))
        self.resume_button = QPushButton("Resume")
        self.resume_button.clicked.connect(lambda: self._send_control_action("resume"))
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(lambda: self._send_control_action("stop"))
        self.skip_button = QPushButton("Skip Task")
        self.skip_button.clicked.connect(lambda: self._send_control_action("skip"))
        self.retry_button = QPushButton("Retry Run")
        self.retry_button.clicked.connect(self._retry_selected_run)

        set_tooltips(
            (
                (self.pause_button, "Pause the selected running job. Shortcut: Ctrl+P."),
                (self.resume_button, "Resume the selected paused run."),
                (self.stop_button, "Stop the selected run."),
                (self.skip_button, "Skip the current task for the selected run."),
                (self.retry_button, "Relaunch the selected run configuration. Shortcut: Ctrl+R."),
            )
        )

        for button in (
            self.pause_button,
            self.resume_button,
            self.skip_button,
            self.retry_button,
        ):
            button.setObjectName("scannerActionButton")
            style_button(button, role="secondary", min_height=38)
        self.stop_button.setObjectName("scannerDangerButton")
        style_button(self.stop_button, role="danger", min_height=38)

        layout.addWidget(
            self._build_scanner_action_section("Run Control", (self.pause_button, self.resume_button, self.stop_button))
        )
        layout.addWidget(
            self._build_scanner_action_section("Task Flow", (self.skip_button, self.retry_button))
        )
        layout.addStretch(1)
        return card

    def _build_scanner_summary_tile(self, label: str) -> tuple[QFrame, QLabel]:
        tile = QFrame()
        tile.setObjectName("scannerMetricTile")
        tile_layout = QVBoxLayout(tile)
        tile_layout.setContentsMargins(PANEL_COMPACT_PADDING, PANEL_COMPACT_PADDING - 2, PANEL_COMPACT_PADDING, PANEL_COMPACT_PADDING - 2)
        tile_layout.setSpacing(4)
        key_label = QLabel(label)
        key_label.setObjectName("scannerMetricLabel")
        value_label = QLabel("--")
        value_label.setObjectName("scannerMetricValue")
        value_label.setWordWrap(True)
        tile_layout.addWidget(key_label)
        tile_layout.addWidget(value_label)
        return tile, value_label

    def _build_scanner_action_section(self, title: str, buttons: tuple[QPushButton, ...]) -> QWidget:
        section = QWidget()
        section.setObjectName("scannerActionSection")
        section_layout = QVBoxLayout(section)
        section_layout.setContentsMargins(0, 0, 0, 0)
        section_layout.setSpacing(6)
        section_label = QLabel(title.upper())
        section_label.setObjectName("scannerActionGroupLabel")
        button_row = FlowButtonRow(h_spacing=8, v_spacing=8)
        for button in buttons:
            button_row.addWidget(button)
        section_layout.addWidget(section_label)
        section_layout.addWidget(button_row)
        return section

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        session_panel, session_layout = build_surface_frame(spacing=12)
        session_header, _session_title, _session_summary = build_section_header("Session")
        session_layout.addWidget(session_header)
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
        self.settings_ad_hoc_button = QPushButton("Use Ad-Hoc Session")
        self.settings_ad_hoc_button.clicked.connect(self._switch_to_no_workspace)
        style_button(self.apply_workspace_button)
        style_button(self.settings_ad_hoc_button, role="secondary")
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
        self.settings_split = apply_responsive_splitter(QSplitter(Qt.Vertical), (2, 3))
        self._register_splitter(self.settings_split, "settings_split")
        self.settings_split.addWidget(session_panel)

        store_panel, store_layout = build_surface_frame(spacing=12)
        store_header, _store_title, _store_summary = build_section_header("Storage & Utilities")
        store_layout.addWidget(store_header)
        self.profile_store_path_label = QLabel("")
        self.profile_store_path_label.setObjectName("monoLabel")
        self.profile_store_path_label.setWordWrap(True)
        open_profiles = QPushButton("Open Profile Store Folder")
        style_button(open_profiles, role="secondary")
        open_profiles.clicked.connect(lambda: self._open_local_path(str(self.store.path.parent)))
        self.workspace_store_path_label = QLabel("")
        self.workspace_store_path_label.setObjectName("monoLabel")
        self.workspace_store_path_label.setWordWrap(True)
        open_workspace = QPushButton("Open Workspace Store Folder")
        style_button(open_workspace, role="secondary")
        open_workspace.clicked.connect(lambda: self._open_local_path(str(self.workspace_store.path.parent)))
        about_button = QPushButton("About AttackCastle")
        style_button(about_button, role="secondary")
        about_button.clicked.connect(self._show_about)
        set_tooltips(
            (
                (open_profiles, "Open the folder that stores saved GUI profiles."),
                (open_workspace, "Open the folder that stores workspace metadata, audit, and run registry state."),
                (about_button, "Show a short description of the GUI."),
            )
        )
        self.shortcut_summary_label = QLabel(
            "Shortcuts: Ctrl+1..7 navigate sections, Ctrl+N new scan, / focus search, Ctrl+F findings search, Ctrl+P pause/resume, Ctrl+R retry, Ctrl+O open artifact or run folder."
        )
        self.shortcut_summary_label.setObjectName("infoBanner")
        self.shortcut_summary_label.setWordWrap(True)
        store_layout.addWidget(QLabel("Profile store path"))
        store_layout.addWidget(self.profile_store_path_label)
        store_layout.addWidget(open_profiles, 0, Qt.AlignLeft)
        store_layout.addWidget(QLabel("Workspace store path"))
        store_layout.addWidget(self.workspace_store_path_label)
        store_layout.addWidget(open_workspace, 0, Qt.AlignLeft)
        store_layout.addWidget(about_button, 0, Qt.AlignLeft)
        store_layout.addWidget(self.shortcut_summary_label)
        self.settings_split.addWidget(store_panel)
        layout.addWidget(self.settings_split, 1)

        danger_panel, danger_layout = build_surface_frame(spacing=10)
        danger_header, _danger_title, _danger_summary = build_section_header("Danger Zone")
        self.danger_zone_status_label = QLabel("No workspace deletion is currently armed.")
        self.danger_zone_status_label.setObjectName("attentionBanner")
        self.danger_zone_status_label.setProperty("tone", "alert")
        self.danger_zone_status_label.setWordWrap(True)
        self.delete_active_workspace_data_button = QPushButton("Delete This Workspace (and All Its Data)")
        self.delete_active_workspace_data_button.clicked.connect(self._delete_active_workspace_and_data)
        self.delete_all_workspaces_data_button = QPushButton("Delete All Workspaces (and All Data)")
        self.delete_all_workspaces_data_button.clicked.connect(self._delete_all_workspaces_and_data)
        style_button(self.delete_active_workspace_data_button, role="danger")
        style_button(self.delete_all_workspaces_data_button, role="danger")
        set_tooltips(
            (
                (
                    self.delete_active_workspace_data_button,
                    "Permanently delete the active workspace, its tracked runs, and the workspace home directory after confirmation.",
                ),
                (
                    self.delete_all_workspaces_data_button,
                    "Permanently delete every saved workspace, tracked run directory, and workspace-scoped GUI data after confirmation.",
                ),
            )
        )
        danger_actions = FlowButtonRow()
        danger_actions.addWidget(self.delete_active_workspace_data_button)
        danger_actions.addWidget(self.delete_all_workspaces_data_button)
        danger_layout.addWidget(danger_header)
        danger_layout.addWidget(self.danger_zone_status_label)
        danger_layout.addWidget(danger_actions)
        layout.addWidget(danger_panel)
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
        group.setObjectName("panelGroup" if title else "panelGroupUntitled")
        group_layout = QVBoxLayout(group)
        if title:
            group_layout.setContentsMargins(14, 18, 14, 14)
        else:
            group_layout.setContentsMargins(14, 14, 14, 14)
        group_layout.setSpacing(0)
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
        self._update_danger_zone_state()

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

    def _update_danger_zone_state(self) -> None:
        if not hasattr(self, "danger_zone_status_label"):
            return
        active_workspace = self._active_workspace()
        if active_workspace is None:
            self.danger_zone_status_label.setText(
                "No active workspace is selected. Switch into a workspace to enable single-workspace deletion, or delete all saved workspaces at once."
            )
        else:
            run_count = len(self.workspace_store.load_run_registry(active_workspace.workspace_id))
            self.danger_zone_status_label.setText(
                f"Active workspace '{active_workspace.name}' will remove {run_count} tracked run(s) and delete data rooted at {active_workspace.home_dir}."
            )
        self.delete_active_workspace_data_button.setEnabled(
            not self._switch_in_progress and active_workspace is not None
        )
        self.delete_all_workspaces_data_button.setEnabled(
            not self._switch_in_progress and bool(self._workspaces)
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
        self.output_tab.set_compare_options(list(self._run_snapshots.values()), self._selected_run_id)
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
        self.assets_tab.set_snapshot(self._workspace_inventory_snapshot(preferred_run_id=run_id))
        if not run_id or run_id not in self._run_snapshots:
            self.output_tab.set_snapshot(None)
            self.scanner_panel.set_snapshot(None)
            return
        snapshot = self._run_snapshots[run_id]
        self.output_tab.set_snapshot(snapshot, self._finding_states_by_run.get(run_id, {}))
        self.scanner_panel.set_snapshot(snapshot)
        self.output_tab.set_compare_options(list(self._run_snapshots.values()), run_id)

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
    ) -> tuple[QMenu, Any, Any, Any, Any, Any]:
        menu = QMenu(parent)
        pause_action = menu.addAction("Pause Scan")
        pause_action.setEnabled(self._can_pause_snapshot(snapshot))
        resume_action = menu.addAction("Resume")
        resume_action.setEnabled(self._can_resume_snapshot(snapshot))
        stop_action = menu.addAction("Stop")
        stop_action.setEnabled(self._can_stop_snapshot(snapshot))
        menu.addSeparator()
        debug_action = menu.addAction("View Debug Log")
        current_task_action = menu.addAction("View Current Task Debug Log")
        has_debug_data = self._has_debug_data(snapshot)
        debug_action.setEnabled(has_debug_data)
        current_task_action.setEnabled(has_debug_data)
        return menu, pause_action, resume_action, stop_action, debug_action, current_task_action

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
        menu, pause_action, resume_action, stop_action, debug_action, current_task_action = self._build_run_context_menu(table, snapshot)
        action = self._exec_menu(menu, table.viewport().mapToGlobal(point))
        self._set_run_table_current_row(table, snapshot.run_id, index)
        if action is pause_action:
            self._send_control_action("pause")
        elif action is resume_action:
            self._send_control_action("resume")
        elif action is stop_action:
            self._send_control_action("stop")
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
        menu, pause_action, resume_action, stop_action, debug_action, current_task_action = self._build_run_context_menu(table, snapshot)
        action = self._exec_menu(menu, table.viewport().mapToGlobal(point))
        if action is pause_action:
            self._send_control_action("pause")
        elif action is resume_action:
            self._send_control_action("resume")
        elif action is stop_action:
            self._send_control_action("stop")
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
                        f"Deletion would overlap data that still belongs to another workspace: {candidate} conflicts with {protected}"
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
            QMessageBox.warning(self, "Workspace Deletion Blocked", str(exc))
            return False
        if not target_workspaces:
            return False
        live_workspaces = [workspace.name for workspace in target_workspaces if self._workspace_has_live_processes(workspace.workspace_id)]
        if live_workspaces:
            QMessageBox.warning(
                self,
                "Workspace Deletion Blocked",
                "One or more targeted workspaces still have live runs owned by this GUI session.\n\n"
                + "\n".join(f"- {name}" for name in live_workspaces),
            )
            return False

        names = [workspace.name for workspace in target_workspaces]
        workspace_label = names[0] if len(names) == 1 else f"{len(names)} workspaces"
        if not self._confirm_workspace_deletion(
            title="Delete Workspace Data",
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
            QMessageBox.warning(self, "Workspace Deletion Failed", f"AttackCastle could not finish deleting the requested workspace data.\n\n{exc}")
            return False

        next_workspace_id = self.workspace_store.get_active_workspace_id()
        self._load_workspace_state(next_workspace_id)
        summary = (
            f"Deleted workspace {names[0]} and removed {len(removed_paths)} path(s)."
            if len(names) == 1
            else f"Deleted {len(names)} workspaces and removed {len(removed_paths)} path(s)."
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

    def _set_selected_run_badge(self, state: str) -> None:
        normalized = str(state or "idle").strip().lower() or "idle"
        self.selected_run_state_badge.setText(title_case_label(normalized))
        self.selected_run_state_badge.setProperty("state", normalized)
        refresh_widget_style(self.selected_run_state_badge)

    def _selected_run_context_text(self, snapshot: RunSnapshot) -> str:
        target_summary = summarize_target_input(snapshot.target_input)
        workspace_label = snapshot.workspace_name or "Ad-Hoc Session"
        return f"{target_summary} | {workspace_label}"

    def _update_run_action_state(self) -> None:
        snapshot = self._selected_snapshot()
        has_snapshot = snapshot is not None
        if snapshot is None:
            for button in (
                self.pause_button,
                self.resume_button,
                self.stop_button,
                self.skip_button,
                self.retry_button,
            ):
                button.setEnabled(False)
            self.selected_run_name_label.setText("No run selected")
            self.selected_run_target_label.setText("Choose a run from the queue to inspect and control it here.")
            self.selected_run_progress_value.setText("--")
            self.selected_run_task_value.setText("--")
            self.selected_run_elapsed_value.setText("--")
            self.selected_run_eta_value.setText("--")
            self._set_selected_run_badge("idle")
            self.selected_run_status_label.setText(
                "No run selected. Choose a run from the table before using Scanner controls."
            )
            self.general_status_detail.setText(
                "Select a run to review context, health, and findings for the current session."
            )
            return
        self.selected_run_name_label.setText(snapshot.scan_name or snapshot.run_id)
        self.selected_run_target_label.setText(self._selected_run_context_text(snapshot))
        self.selected_run_progress_value.setText(format_progress(snapshot.completed_tasks, snapshot.total_tasks))
        self.selected_run_task_value.setText(snapshot.current_task or "--")
        self.selected_run_elapsed_value.setText(format_duration(snapshot.elapsed_seconds))
        self.selected_run_eta_value.setText(format_duration(snapshot.eta_seconds))
        self._set_selected_run_badge(snapshot.state)
        self.selected_run_status_label.setText(
            f"{snapshot.scan_name} is {title_case_label(snapshot.state)} and {progress_percent(snapshot.completed_tasks, snapshot.total_tasks)}% complete."
        )
        self.pause_button.setEnabled(self._can_pause_snapshot(snapshot))
        self.resume_button.setEnabled(self._can_resume_snapshot(snapshot))
        self.stop_button.setEnabled(self._can_stop_snapshot(snapshot))
        self.skip_button.setEnabled(snapshot.state == "running" and not snapshot.pause_requested and not snapshot.resume_required)
        self.retry_button.setEnabled(bool(str(snapshot.run_dir or "").strip()))
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
