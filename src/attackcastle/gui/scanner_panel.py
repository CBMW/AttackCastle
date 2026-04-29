from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QTimer, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.gui.common import (
    MappingTableModel,
    PersistentSplitterController,
    apply_responsive_splitter,
    build_flat_container,
    configure_tab_widget,
    configure_scroll_surface,
    ensure_table_defaults,
    format_duration,
    format_elapsed_duration,
    summarize_target_input,
    title_case_label,
)
from attackcastle.gui.models import RunSnapshot
from attackcastle.gui.runtime import resolve_current_task_debug_bundle


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
        self._active_detail_kind = ""
        self._active_detail_identity = ""
        self._active_command_text = ""
        self._copy_buttons: dict[QTextEdit, QToolButton] = {}
        self._copy_status_labels: dict[QTextEdit, QLabel] = {}
        self._tools_elapsed_column = 2

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
        configure_tab_widget(self.tabs, role="group")
        self.tabs.setMinimumWidth(300)
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

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
                ("Elapsed", format_elapsed_duration),
                ("Exit", lambda row: row.get("exit_code") if row.get("exit_code") is not None else ""),
                ("Started", "started_at"),
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
            [("Time", "timestamp"), ("Action", "action"), ("Summary", "summary"), ("Run", "run_id"), ("Project", "workspace_id")]
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
        configure_tab_widget(self.inspector_tabs, role="inspector")
        self.inspector_tabs.setMinimumWidth(260)
        self.inspector_tabs.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.inspector_summary = QLabel("Select a task, tool run, issue, or audit entry to inspect details.")
        self.inspector_summary.setObjectName("helperText")
        self.inspector_summary.setWordWrap(True)
        self.inspector_summary.setMaximumWidth(240)
        self.inspector_summary.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.inspector_tabs.setCornerWidget(self.inspector_summary, Qt.TopRightCorner)
        self.detail_text = configure_scroll_surface(QTextEdit())
        self.detail_text.setObjectName("consoleText")
        self.detail_text.setReadOnly(True)
        self.raw_text = configure_scroll_surface(QTextEdit())
        self.raw_text.setObjectName("consoleText")
        self.raw_text.setReadOnly(True)
        self.command_text = configure_scroll_surface(QTextEdit())
        self.command_text.setObjectName("consoleText")
        self.command_text.setReadOnly(True)
        self.output_text = configure_scroll_surface(QTextEdit())
        self.output_text.setObjectName("consoleText")
        self.output_text.setReadOnly(True)
        detail_surface = self._copyable_tab_surface(self.detail_text, "Details")
        command_surface = self._copyable_tab_surface(self.command_text, "Command", "No command selected.")
        output_surface = self._copyable_tab_surface(self.output_text, "Output")
        raw_surface = self._copyable_tab_surface(self.raw_text, "Raw")
        self.detail_copy_button = self._copy_buttons[self.detail_text]
        self.command_copy_button = self._copy_buttons[self.command_text]
        self.output_copy_button = self._copy_buttons[self.output_text]
        self.raw_copy_button = self._copy_buttons[self.raw_text]
        self.command_status_label = self._copy_status_labels[self.command_text]
        self.inspector_tabs.addTab(detail_surface, "Details")
        self.inspector_tabs.addTab(command_surface, "Command")
        self.inspector_tabs.addTab(output_surface, "Output")
        self.inspector_tabs.addTab(raw_surface, "Raw")
        self.main_split.addWidget(self.inspector_tabs)
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._refresh_elapsed_cells)
        self.sync_responsive_mode(self.width())

    def _tab_surface(self, widget: QWidget) -> QWidget:
        section = build_flat_container()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(widget, 1)
        return section

    def _table_surface(self, _title: str, table: QTableView) -> QWidget:
        return self._tab_surface(table)

    def _copyable_tab_surface(self, widget: QTextEdit, label: str, empty_status: str | None = None) -> QWidget:
        section = build_flat_container()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        header = build_flat_container()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)
        copy_button = QToolButton()
        copy_button.setIcon(QIcon.fromTheme("edit-copy"))
        copy_button.setText("Copy")
        copy_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        copy_button.setEnabled(False)
        copy_button.clicked.connect(lambda _checked=False, source=widget, name=label: self._copy_inspector_text(source, name))
        status_label = QLabel(empty_status or f"No {label.lower()} selected.")
        status_label.setObjectName("helperText")
        status_label.setWordWrap(True)
        self._copy_buttons[widget] = copy_button
        self._copy_status_labels[widget] = status_label
        widget.textChanged.connect(lambda source=widget, name=label: self._refresh_copy_state(source, name))
        header_layout.addWidget(copy_button, 0)
        header_layout.addWidget(status_label, 1)
        layout.addWidget(header, 0)
        layout.addWidget(widget, 1)
        return section

    def _copyable_text(self, widget: QTextEdit) -> str:
        text = widget.toPlainText()
        return "" if text.strip() == "No Data" else text

    def _refresh_copy_state(self, widget: QTextEdit, label: str) -> None:
        text = self._copyable_text(widget)
        button = self._copy_buttons.get(widget)
        status_label = self._copy_status_labels.get(widget)
        if button is not None:
            button.setEnabled(bool(text))
        if status_label is None:
            return
        if text:
            status_label.setText(f"Copy {label.lower()} to clipboard.")
        else:
            status_label.setText(f"No {label.lower()} selected.")

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
            elif heading in {"stdout", "run", "project"}:
                policies.append({"mode": "stretch", "min": 180})
            else:
                policies.append({"mode": "mixed", "min": 120, "width": 160})
        ensure_table_defaults(table, column_policies=policies, minimum_rows=8)
        table.clicked.connect(callback)
        table.doubleClicked.connect(callback)
        if context_kind:
            table.setProperty("context_kind", context_kind)
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda point, view=table: self._open_context_menu(view, point))
        table.setToolTip("Select a row to inspect more detail in the panel on the right.")
        return table

    def sync_responsive_mode(self, width: int) -> None:
        self.main_split.setOrientation(Qt.Horizontal if width >= 1280 else Qt.Vertical)
        if width >= 1280:
            self._main_split_controller.apply([max(int(width * 0.68), 660), max(int(width * 0.32), 300)])
        else:
            self._main_split_controller.apply([max(int(self.height() * 0.56), 280), max(int(self.height() * 0.44), 220)])

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        previous_run_id = self._snapshot.run_id if self._snapshot is not None else ""
        next_run_id = snapshot.run_id if snapshot is not None else ""
        run_changed = bool(previous_run_id and next_run_id and previous_run_id != next_run_id)
        self._snapshot = snapshot
        if snapshot is None:
            self._clear_active_detail()
            self.tasks_model.set_rows([])
            self.tools_model.set_rows([])
            self.issues_model.set_rows([])
            self.health_text.setPlainText("Select a run to inspect task state, tool runs, and Scanner health.")
            self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
            self.detail_text.clear()
            self.raw_text.clear()
            self._set_command_rows([])
            self._set_output_rows([])
            self._update_elapsed_timer()
            return
        if run_changed:
            self._clear_active_detail()

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
        self._update_elapsed_timer()
        if self._active_detail_kind in {"task", "tool", "issue"}:
            self._restore_active_detail()
        elif not self._active_detail_kind:
            self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
            self.detail_text.setPlainText("Select a task, tool run, issue, or audit entry for details.")
            self.raw_text.clear()
            self._set_command_rows([])
            self._set_output_rows([])

    def _update_elapsed_timer(self) -> None:
        rows = self._snapshot.tool_executions if self._snapshot is not None else []
        should_run = any(
            str(row.get("status") or "").strip().lower() in {"running", "in_progress", "started"}
            and bool(row.get("started_at"))
            and not row.get("ended_at")
            for row in rows
        )
        if should_run and not self._elapsed_timer.isActive():
            self._elapsed_timer.start()
        elif not should_run and self._elapsed_timer.isActive():
            self._elapsed_timer.stop()

    def _refresh_elapsed_cells(self) -> None:
        if self._snapshot is None or not self._snapshot.tool_executions:
            self._update_elapsed_timer()
            return
        first = self.tools_model.index(0, self._tools_elapsed_column)
        last = self.tools_model.index(self.tools_model.rowCount() - 1, self._tools_elapsed_column)
        self.tools_model.dataChanged.emit(first, last, [Qt.DisplayRole])
        self._update_elapsed_timer()

    def set_audit_rows(self, rows: list[dict[str, Any]]) -> None:
        self.audit_model.set_rows(rows)
        if self._active_detail_kind == "audit":
            self._restore_active_detail()

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
            f"Project: {snapshot.workspace_name or 'Ad-Hoc Session'}",
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
                    f"- {execution.get('tool_name')} | {execution.get('status')} | elapsed={format_elapsed_duration(execution) or '-'} | exit={execution.get('exit_code')} | stdout={execution.get('stdout_path') or '-'}"
                )
        else:
            lines.append("- no tool executions recorded yet")
        return "\n".join(lines)

    def _show_details(self, row: dict[str, Any], *, kind: str = "") -> None:
        if kind:
            self._active_detail_kind = kind
            self._active_detail_identity = self._row_identity(kind, row)
        detail_keys = [title_case_label(str(key)) for key in row.keys()]
        if detail_keys:
            summary = f"Inspecting {', '.join(detail_keys[:3])}"
            if len(detail_keys) > 3:
                summary += "..."
            self.inspector_summary.setText(summary)
        else:
            self.inspector_summary.setText("Select a task, tool run, issue, or audit entry to inspect details.")
        if kind in {"task", "tool"} and self._snapshot is not None:
            bundle = resolve_current_task_debug_bundle(
                self._snapshot,
                task_row=row if kind == "task" else None,
                tool_row=row if kind == "tool" else None,
            )
            self.detail_text.setPlainText(str(bundle.get("text") or self._build_technical_text(row)))
            self.raw_text.setPlainText(
                json.dumps(
                    {
                        "selected_row": row,
                        "matched_task": bundle.get("task"),
                        "matched_task_results": bundle.get("task_results", []),
                        "matched_tool_executions": bundle.get("tool_executions", []),
                        "matched_evidence_artifacts": bundle.get("evidence_artifacts", []),
                    },
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
            )
            command_rows = [
                item
                for item in bundle.get("tool_executions", [])
                if isinstance(item, dict) and self._command_value(item)
            ]
            if not command_rows:
                command_rows = [
                    item
                    for item in bundle.get("task_results", [])
                    if isinstance(item, dict) and self._command_value(item)
                ]
            self._set_command_rows(command_rows)
            self._set_output_rows(
                [item for item in bundle.get("tool_executions", []) if isinstance(item, dict)]
                or [item for item in bundle.get("task_results", []) if isinstance(item, dict)]
            )
            return
        self.detail_text.setPlainText(self._build_technical_text(row))
        self.raw_text.setPlainText(json.dumps(row, indent=2, sort_keys=True))
        matched_rows = self._matched_command_rows(row, kind=kind)
        self._set_command_rows(matched_rows)
        self._set_output_rows(matched_rows)

    def _clear_active_detail(self) -> None:
        self._active_detail_kind = ""
        self._active_detail_identity = ""

    def _row_identity(self, kind: str, row: dict[str, Any]) -> str:
        if kind == "task":
            detail = row.get("detail", {})
            if isinstance(detail, dict) and detail.get("instance_key"):
                return f"task:{detail.get('instance_key')}"
            return str(row.get("key") or row.get("task_key") or row.get("label") or "")
        if kind == "tool":
            execution_id = row.get("execution_id")
            if execution_id not in (None, ""):
                return f"tool:{execution_id}"
            return "|".join(
                str(row.get(key) or "")
                for key in ("execution_id", "tool_name", "started_at", "stdout_path")
            ).strip("|")
        if kind == "issue":
            issue_id = row.get("issue_id")
            if issue_id not in (None, ""):
                return f"issue:{issue_id}"
            return "|".join(
                str(row.get(key) or "")
                for key in ("kind", "label", "message", "impact", "suggested_action")
            ).strip("|")
        if kind == "audit":
            audit_id = row.get("audit_id")
            if audit_id not in (None, ""):
                return f"audit:{audit_id}"
            return "|".join(
                str(row.get(key) or "")
                for key in ("timestamp", "action", "summary", "run_id", "workspace_id")
            ).strip("|")
        return json.dumps(row, sort_keys=True, default=str)

    def _detail_sources(self) -> dict[str, tuple[QTableView, MappingTableModel]]:
        return {
            "task": (self.tasks_view, self.tasks_model),
            "tool": (self.tools_view, self.tools_model),
            "issue": (self.issues_view, self.issues_model),
            "audit": (self.audit_view, self.audit_model),
        }

    def _restore_active_detail(self) -> None:
        if not self._active_detail_kind or not self._active_detail_identity:
            return
        source = self._detail_sources().get(self._active_detail_kind)
        if source is None:
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
            self._show_details(row, kind=self._active_detail_kind)
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

    def _command_value(self, row: dict[str, Any]) -> str:
        command = str(row.get("raw_command") or row.get("command") or "").strip()
        if command == "internal host-header virtual host discovery":
            return ""
        return command

    def _read_output_path(self, path: str) -> str:
        normalized = str(path or "").strip()
        if not normalized:
            return ""
        output_path = Path(normalized).expanduser()
        if not output_path.exists() or not output_path.is_file():
            return ""
        try:
            return output_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return ""
        except Exception:  # noqa: BLE001
            return ""

    def _output_value(self, row: dict[str, Any]) -> str:
        transcript = self._read_output_path(str(row.get("transcript_path") or ""))
        if transcript:
            return transcript

        inline_parts: list[str] = []
        for key in ("stdout_text", "stderr_text", "raw_output", "output"):
            value = row.get(key)
            if isinstance(value, str) and value:
                inline_parts.append(value)
        if inline_parts:
            return "\n".join(part.rstrip("\n") for part in inline_parts if part).strip("\n")

        path_parts: list[str] = []
        for key in ("stdout_path", "stderr_path"):
            content = self._read_output_path(str(row.get(key) or ""))
            if content:
                path_parts.append(content)
        return "\n".join(part.rstrip("\n") for part in path_parts if part).strip("\n")

    def _matched_command_rows(self, row: dict[str, Any], *, kind: str = "") -> list[dict[str, Any]]:
        if self._snapshot is None or kind not in {"task", "tool"}:
            return []
        if kind == "tool":
            return [row] if self._command_value(row) else []
        bundle = resolve_current_task_debug_bundle(self._snapshot, task_row=row)
        rows = [
            item
            for item in bundle.get("tool_executions", [])
            if isinstance(item, dict) and self._command_value(item)
        ]
        if rows:
            return rows
        return [
            item
            for item in bundle.get("task_results", [])
            if isinstance(item, dict) and self._command_value(item)
        ]

    def _set_command_rows(self, rows: list[dict[str, Any]]) -> None:
        commands: list[str] = []
        for row in rows:
            command = self._command_value(row)
            if not command:
                continue
            commands.append(command)
        if not commands:
            self._active_command_text = ""
            self.command_copy_button.setEnabled(False)
            self.command_status_label.setText("No raw command has been recorded for this selection yet.")
            self.command_text.setPlainText("No Data")
            return
        self._active_command_text = commands[0]
        self.command_copy_button.setEnabled(True)
        self.command_status_label.setText(
            "Copy exact command." if len(commands) == 1 else f"Copy first exact command. {len(commands)} commands matched."
        )
        self.command_text.setPlainText("\n\n".join(commands).strip())

    def _set_output_rows(self, rows: list[dict[str, Any]]) -> None:
        outputs: list[str] = []
        for row in rows:
            output = self._output_value(row)
            if output:
                outputs.append(output)
        self.output_text.setPlainText("\n\n".join(outputs).rstrip("\n") if outputs else "No Data")

    def _copy_inspector_text(self, widget: QTextEdit, label: str) -> None:
        text = self._copyable_text(widget)
        if not text:
            return
        app = QApplication.instance()
        if app is None:
            return
        app.clipboard().setText(text)
        status_label = self._copy_status_labels.get(widget)
        if status_label is not None:
            status_label.setText(f"Copied {label.lower()} to clipboard.")

    def _copy_active_command(self) -> None:
        self._copy_inspector_text(self.command_text, "Command")

    def _task_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.tasks_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {}, kind="task")

    def _tool_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.tools_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {}, kind="tool")

    def _issue_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.issues_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {}, kind="issue")

    def _audit_selected(self, index: QModelIndex) -> None:
        self.tabs.setCurrentIndex(self.audit_tab_index)
        row = index.data(Qt.UserRole) or {}
        self._show_details(row if isinstance(row, dict) else {}, kind="audit")

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())
