from __future__ import annotations

import json
from typing import Any, Callable

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtWidgets import (
    QLabel,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.gui.common import (
    MappingTableModel,
    PersistentSplitterController,
    apply_responsive_splitter,
    configure_scroll_surface,
    ensure_table_defaults,
    format_duration,
    summarize_target_input,
    title_case_label,
)
from attackcastle.gui.models import RunSnapshot


class ScannerPanel(QWidget):
    def __init__(
        self,
        parent: QWidget | None = None,
        layout_loader=None,
        layout_saver=None,
    ) -> None:
        super().__init__(parent)
        self._snapshot: RunSnapshot | None = None
        self._context_menu_handler: Callable[[str, QTableView, Any, dict[str, Any]], None] | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.main_split = apply_responsive_splitter(QSplitter(Qt.Horizontal), (3, 2))
        self.main_split.setObjectName("scannerSplit")
        self._main_split_controller = PersistentSplitterController(
            self.main_split,
            "scanner_detail_split",
            layout_loader,
            layout_saver,
            self,
        )
        layout.addWidget(self.main_split)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("subTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.setMinimumWidth(340)

        self.tasks_model = MappingTableModel(
            [
                ("Task", lambda row: row.get("label") or row.get("key")),
                ("Status", "status"),
                ("Started", "started_at"),
                ("Ended", "ended_at"),
            ]
        )
        self.tools_model = MappingTableModel(
            [
                ("Tool", "tool_name"),
                ("Status", "status"),
                ("Exit", lambda row: row.get("exit_code") if row.get("exit_code") is not None else ""),
                ("Started", "started_at"),
                ("Stdout", lambda row: row.get("stdout_path") or ""),
            ]
        )
        self.issues_model = MappingTableModel(
            [
                ("Type", lambda row: title_case_label(str(row.get("kind") or "").replace("_", " "))),
                ("Issue", "label"),
                ("Status", "status"),
                ("Impact", "impact"),
                ("Suggested Action", "suggested_action"),
            ]
        )
        self.audit_model = MappingTableModel(
            [("Time", "timestamp"), ("Action", "action"), ("Summary", "summary"), ("Run", "run_id"), ("Workspace", "workspace_id")]
        )

        self.tasks_view = self._make_table(self.tasks_model, self._task_selected, context_kind="task")
        self.tools_view = self._make_table(self.tools_model, self._tool_selected, context_kind="tool")
        self.issues_view = self._make_table(self.issues_model, self._issue_selected)
        self.audit_view = self._make_table(self.audit_model, self._audit_selected)

        self.health_text = configure_scroll_surface(QTextEdit())
        self.health_text.setObjectName("consoleText")
        self.health_text.setReadOnly(True)

        self.tasks_tab_index = self.tabs.addTab(self._table_surface("Tasks", self.tasks_view), "Tasks")
        self.tools_tab_index = self.tabs.addTab(self._table_surface("Tool Runs", self.tools_view), "Tool Runs")
        self.issues_tab_index = self.tabs.addTab(self._table_surface("Execution Issues", self.issues_view), "Issues")
        self.health_tab_index = self.tabs.addTab(self._tab_surface(self.health_text), "Health")
        self.audit_tab_index = self.tabs.addTab(self._table_surface("Audit Trail", self.audit_view), "Audit")
        self.tabs.setTabToolTip(self.tasks_tab_index, "Inspect task lifecycle updates for the selected run.")
        self.tabs.setTabToolTip(self.tools_tab_index, "Inspect tool execution records and stdout artifact paths.")
        self.tabs.setTabToolTip(self.issues_tab_index, "Inspect consolidated execution issues and suggested actions.")
        self.tabs.setTabToolTip(self.health_tab_index, "Inspect the Scanner health summary for the selected run.")
        self.tabs.setTabToolTip(self.audit_tab_index, "Inspect recent session audit events.")
        self.main_split.addWidget(self.tabs)

        self.inspector_tabs = QTabWidget()
        self.inspector_tabs.setObjectName("subTabs")
        self.inspector_tabs.setDocumentMode(True)
        self.inspector_tabs.setMinimumWidth(300)
        self.inspector_summary = QLabel("Select a task, tool run, issue, or audit entry to inspect details.")
        self.inspector_summary.setObjectName("helperText")
        self.inspector_summary.setWordWrap(True)
        self.inspector_tabs.setCornerWidget(self.inspector_summary, Qt.TopRightCorner)
        self.detail_text = configure_scroll_surface(QTextEdit())
        self.detail_text.setObjectName("consoleText")
        self.detail_text.setReadOnly(True)
        self.raw_text = configure_scroll_surface(QTextEdit())
        self.raw_text.setObjectName("consoleText")
        self.raw_text.setReadOnly(True)
        self.inspector_tabs.addTab(self._tab_surface(self.detail_text), "Details")
        self.inspector_tabs.addTab(self._tab_surface(self.raw_text), "Raw")
        self.main_split.addWidget(self.inspector_tabs)
        self.sync_responsive_mode(self.width())

    def _tab_surface(self, widget: QWidget) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(widget, 1)
        return section

    def _table_surface(self, _title: str, table: QTableView) -> QWidget:
        return self._tab_surface(table)

    def set_context_menu_handler(self, handler: Callable[[str, QTableView, Any, dict[str, Any]], None] | None) -> None:
        self._context_menu_handler = handler

    def _make_table(self, model: MappingTableModel, callback, *, context_kind: str = "") -> QTableView:
        table = configure_scroll_surface(QTableView())
        table.setObjectName("dataGrid")
        table.setModel(model)
        headings = [str(column[0]).lower() for column in model._columns]
        policies = []
        for heading in headings:
            if heading in {"status", "exit"}:
                policies.append({"mode": "content", "min": 90, "max": 120})
            elif heading in {"task", "issue", "summary", "suggested action"}:
                policies.append({"mode": "stretch", "min": 220})
            elif heading in {"stdout", "run", "workspace"}:
                policies.append({"mode": "stretch", "min": 180})
            else:
                policies.append({"mode": "mixed", "min": 120, "width": 160})
        ensure_table_defaults(table, column_policies=policies, minimum_rows=8)
        table.clicked.connect(callback)
        if context_kind:
            table.setProperty("context_kind", context_kind)
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda point, view=table: self._open_context_menu(view, point))
        table.setToolTip("Select a row to inspect more detail in the panel on the right.")
        return table

    def sync_responsive_mode(self, width: int) -> None:
        self.main_split.setOrientation(Qt.Horizontal if width >= 1180 else Qt.Vertical)
        if width >= 1180:
            self._main_split_controller.apply([max(int(width * 0.66), 620), max(int(width * 0.34), 320)])
        else:
            self._main_split_controller.apply([max(int(self.height() * 0.56), 280), max(int(self.height() * 0.44), 220)])

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot
        if snapshot is None:
            self.tasks_model.set_rows([])
            self.tools_model.set_rows([])
            self.issues_model.set_rows([])
            self.health_text.setPlainText("Select a run to inspect task state, tool runs, and Scanner health.")
            self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
            self.detail_text.clear()
            self.raw_text.clear()
            return

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

        self.tasks_model.set_rows(snapshot.tasks)
        self.tools_model.set_rows(snapshot.tool_executions)
        self.issues_model.set_rows(execution_issues)
        self.health_text.setPlainText(self._build_health_text(snapshot, execution_issues, issue_summary))
        self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
        self.detail_text.setPlainText("Select a task, tool run, issue, or audit entry for details.")
        self.raw_text.clear()

    def set_audit_rows(self, rows: list[dict[str, Any]]) -> None:
        self.audit_model.set_rows(rows)

    def focus_tasks(self) -> None:
        self.tabs.setCurrentIndex(self.tasks_tab_index)
        self.tasks_view.setFocus()

    def focus_issues(self) -> None:
        self.tabs.setCurrentIndex(self.issues_tab_index)
        self.issues_view.setFocus()

    def focus_health(self) -> None:
        self.tabs.setCurrentIndex(self.health_tab_index)
        self.health_text.setFocus()

    def _open_context_menu(self, table: QTableView, point) -> None:
        if self._context_menu_handler is None:
            return
        index = table.indexAt(point)
        if not index.isValid():
            selection = table.selectionModel()
            if selection is not None and selection.currentIndex().isValid():
                index = selection.currentIndex()
            elif table.model() is not None and table.model().rowCount() > 0:
                index = table.model().index(0, 0)
        if not index.isValid():
            return
        table.setCurrentIndex(index)
        table.selectRow(index.row())
        row = index.data(Qt.UserRole) or {}
        if not isinstance(row, dict):
            return
        self._context_menu_handler(str(table.property("context_kind") or ""), table, point, row)

    def _build_health_text(
        self,
        snapshot: RunSnapshot,
        execution_issues: list[dict[str, Any]],
        issue_summary: dict[str, Any],
    ) -> str:
        lines = [
            f"Run: {snapshot.scan_name}",
            f"Workspace: {snapshot.workspace_name or 'Ad-Hoc Session'}",
            f"Target Summary: {summarize_target_input(snapshot.target_input)}",
            f"State: {title_case_label(snapshot.state)}",
            f"Elapsed: {format_duration(snapshot.elapsed_seconds)}",
            f"ETA: {format_duration(snapshot.eta_seconds)}",
            f"Current Task: {snapshot.current_task}",
            f"Completeness: {title_case_label(str(issue_summary.get('completeness_status') or snapshot.completeness_status))}",
            f"Issues: {issue_summary.get('total_count', 0)}",
            f"Warnings: {len(snapshot.warnings)}",
            f"Errors: {len(snapshot.errors)}",
            "",
            "Execution Issues:",
        ]
        if execution_issues:
            for issue in execution_issues[:20]:
                lines.append(
                    f"- {issue.get('kind')} | {issue.get('status')} | {issue.get('label')} | {issue.get('message')}"
                )
        else:
            lines.append("- none")
        lines.extend(["", "Tool Transparency:"])
        if snapshot.tool_executions:
            for execution in snapshot.tool_executions[-10:]:
                lines.append(
                    f"- {execution.get('tool_name')} | {execution.get('status')} | exit={execution.get('exit_code')} | stdout={execution.get('stdout_path') or '-'}"
                )
        else:
            lines.append("- no tool executions recorded yet")
        return "\n".join(lines)

    def _show_details(self, row: dict[str, Any]) -> None:
        detail_keys = [title_case_label(str(key)) for key in row.keys()]
        if detail_keys:
            summary = f"Inspecting {', '.join(detail_keys[:3])}"
            if len(detail_keys) > 3:
                summary += "..."
            self.inspector_summary.setText(summary)
        else:
            self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
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

    def _task_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.tasks_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {})

    def _tool_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.tools_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {})

    def _issue_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.issues_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {})

    def _audit_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.audit_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {})

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())
