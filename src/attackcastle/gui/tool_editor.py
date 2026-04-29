from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QProcess, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    PAGE_SECTION_SPACING,
    apply_form_layout_defaults,
    apply_responsive_splitter,
    build_table_section,
    configure_scroll_surface,
    configure_tab_widget,
    ensure_table_defaults,
    size_dialog_to_screen,
    style_button,
)
from attackcastle.tools.installer import shell_command_args
from attackcastle.tools.library import ToolLibraryStore, default_tool_logs_dir
from attackcastle.tools.schema import (
    CATEGORIES,
    OUTPUT_TYPES,
    PLATFORMS,
    REQUIRED_INPUTS,
    SAVE_SCOPES,
    default_tool_definition,
    normalize_tool_definition,
    validate_tool_definition,
)
from attackcastle.tools.status import check_tool_status

AuditCallback = Callable[[str, str, str, str, dict[str, Any] | None], None]


def _label_status(status: str) -> str:
    return {
        "installed": "Installed",
        "version_detected": "Version detected",
        "missing": "Missing",
        "disabled": "Disabled",
        "unavailable": "Unavailable",
        "install_not_configured": "Install command not configured",
        "installing": "Installing",
        "checking": "Checking",
    }.get(status, status.replace("_", " ").title())


class ToolTableModel(QAbstractTableModel):
    COLUMNS = ("Status", "Tool", "Category", "Platform", "Version", "Scope", "Enabled")

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.definitions: list[dict[str, Any]] = []
        self.statuses: dict[str, dict[str, Any]] = {}

    def set_rows(self, definitions: list[dict[str, Any]], statuses: dict[str, dict[str, Any]]) -> None:
        self.beginResetModel()
        self.definitions = list(definitions)
        self.statuses = dict(statuses)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.definitions)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and 0 <= section < len(self.COLUMNS):
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.definitions)):
            return None
        definition = self.definitions[index.row()]
        status = self.statuses.get(str(definition.get("id")), {})
        if role == Qt.UserRole:
            return definition
        if role != Qt.DisplayRole:
            return None
        column = index.column()
        if column == 0:
            return _label_status(str(status.get("status") or "missing"))
        if column == 1:
            return str(definition.get("display_name") or definition.get("id") or "")
        if column == 2:
            return str(definition.get("category") or "")
        if column == 3:
            return ", ".join(definition.get("platforms", []))
        if column == 4:
            return str(status.get("version") or "")
        if column == 5:
            return str(definition.get("save_scope") or "global")
        if column == 6:
            return "Yes" if definition.get("enabled", True) else "No"
        return None


class ToolDefinitionDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, definition: dict[str, Any] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Tool")
        self.setModal(True)
        self.setMinimumSize(780, 680)
        size_dialog_to_screen(self, default_width=920, default_height=820, min_width=780, min_height=680)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)
        form_frame = QFrame()
        form_frame.setObjectName("settingsContent")
        form = QFormLayout(form_frame)
        apply_form_layout_defaults(form)

        self.id_edit = QLineEdit()
        self.name_edit = QLineEdit()
        self.category_combo = QComboBox()
        self.category_combo.addItems(list(CATEGORIES))
        self.enabled_checkbox = QCheckBox("Enabled by default")
        self.executable_edit = QLineEdit()
        self.install_path_edit = QLineEdit()
        self.install_command_edit = QLineEdit()
        self.detection_command_edit = QLineEdit()
        self.version_command_edit = QLineEdit()
        self.command_template_edit = QLineEdit()
        self.default_arguments_edit = QLineEdit()
        self.timeout_edit = QLineEdit()
        self.platforms_edit = QLineEdit()
        self.required_inputs_edit = QLineEdit()
        self.output_combo = QComboBox()
        self.output_combo.addItems(list(OUTPUT_TYPES))
        self.produced_fields_edit = configure_scroll_surface(QPlainTextEdit())
        self.produced_fields_edit.setMinimumHeight(80)
        self.description_edit = configure_scroll_surface(QPlainTextEdit())
        self.description_edit.setMinimumHeight(70)
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(list(SAVE_SCOPES))

        form.addRow("ID", self.id_edit)
        form.addRow("Name", self.name_edit)
        form.addRow("Category", self.category_combo)
        form.addRow("", self.enabled_checkbox)
        form.addRow("Executable", self.executable_edit)
        form.addRow("Install path", self.install_path_edit)
        form.addRow("Install command", self.install_command_edit)
        form.addRow("Detection command", self.detection_command_edit)
        form.addRow("Version command", self.version_command_edit)
        form.addRow("Run command template", self.command_template_edit)
        form.addRow("Default arguments", self.default_arguments_edit)
        form.addRow("Timeout seconds", self.timeout_edit)
        form.addRow("Supported platforms", self.platforms_edit)
        form.addRow("Required inputs", self.required_inputs_edit)
        form.addRow("Output parsing mode", self.output_combo)
        form.addRow("Produced fields", self.produced_fields_edit)
        form.addRow("Description", self.description_edit)
        form.addRow("Save scope", self.scope_combo)
        root.addWidget(form_frame, 1)

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
        root.addWidget(buttons)
        self.load_definition(definition or default_tool_definition())

    def load_definition(self, definition: dict[str, Any]) -> None:
        tool = normalize_tool_definition(definition)
        self.id_edit.setText(tool["id"])
        self.name_edit.setText(tool["display_name"])
        self.category_combo.setCurrentText(tool["category"])
        self.enabled_checkbox.setChecked(bool(tool["enabled"]))
        self.executable_edit.setText(tool["executable_name"])
        self.install_path_edit.setText(tool["install_path"])
        self.install_command_edit.setText(tool["install_command"])
        self.detection_command_edit.setText(tool["detection_command"])
        self.version_command_edit.setText(tool["version_command"])
        self.command_template_edit.setText(tool["command_template"])
        self.default_arguments_edit.setText(", ".join(tool["default_arguments"]))
        self.timeout_edit.setText(str(tool["timeout_seconds"]))
        self.platforms_edit.setText(", ".join(tool["platforms"]))
        self.required_inputs_edit.setText(", ".join(tool["required_inputs"]))
        self.output_combo.setCurrentText(tool["output"]["type"])
        self.produced_fields_edit.setPlainText("\n".join(row["name"] for row in tool["produced_fields"]))
        self.description_edit.setPlainText(tool["description"])
        self.scope_combo.setCurrentText(tool["save_scope"])

    def definition(self) -> dict[str, Any]:
        produced = [
            {"name": line.strip(), "type": "string", "description": ""}
            for line in self.produced_fields_edit.toPlainText().splitlines()
            if line.strip()
        ]
        return normalize_tool_definition(
            {
                "id": self.id_edit.text().strip(),
                "display_name": self.name_edit.text().strip(),
                "description": self.description_edit.toPlainText(),
                "category": self.category_combo.currentText(),
                "platforms": [item.strip() for item in self.platforms_edit.text().split(",") if item.strip()] or list(PLATFORMS),
                "enabled": self.enabled_checkbox.isChecked(),
                "install_path": self.install_path_edit.text().strip(),
                "executable_name": self.executable_edit.text().strip(),
                "detection_command": self.detection_command_edit.text().strip(),
                "install_command": self.install_command_edit.text().strip(),
                "version_command": self.version_command_edit.text().strip(),
                "command_template": self.command_template_edit.text().strip(),
                "default_arguments": [item.strip() for item in self.default_arguments_edit.text().split(",") if item.strip()],
                "timeout_seconds": self.timeout_edit.text().strip() or "300",
                "required_inputs": [item.strip() for item in self.required_inputs_edit.text().split(",") if item.strip() and item.strip() in REQUIRED_INPUTS],
                "output": {"type": self.output_combo.currentText(), "primary_artifact": "stdout", "parser": "", "regex": ""},
                "produced_fields": produced,
                "save_scope": self.scope_combo.currentText(),
                "metadata": {"source": "user", "capabilities": [], "task_keys": []},
            }
        )

    def accept(self) -> None:
        issues = validate_tool_definition(self.definition())
        if issues:
            QMessageBox.warning(self, "Tool Definition", "\n".join(issues))
            return
        super().accept()


class ToolCommandOutputDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, title: str = "Tool Output") -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(720, 520)
        size_dialog_to_screen(self, default_width=840, default_height=660, min_width=720, min_height=520)
        root = QVBoxLayout(self)
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setObjectName("helperText")
        self.command_preview = configure_scroll_surface(QPlainTextEdit())
        self.command_preview.setReadOnly(True)
        self.command_preview.setMaximumHeight(90)
        self.stdout_edit = configure_scroll_surface(QPlainTextEdit())
        self.stdout_edit.setReadOnly(True)
        self.stderr_edit = configure_scroll_surface(QPlainTextEdit())
        self.stderr_edit.setReadOnly(True)
        tabs = configure_tab_widget(QTabWidget(), role="group")
        tabs.addTab(self.stdout_edit, "stdout")
        tabs.addTab(self.stderr_edit, "stderr")
        root.addWidget(self.summary_label)
        root.addWidget(self.command_preview)
        root.addWidget(tabs, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def set_result(self, *, command: str, stdout: str, stderr: str, exit_code: int | None, summary: str = "") -> None:
        self.command_preview.setPlainText(command)
        self.stdout_edit.setPlainText(stdout)
        self.stderr_edit.setPlainText(stderr)
        self.summary_label.setText(summary or f"Exit code: {exit_code}")


class ToolCommandRunner(QObject):
    finished = Signal(object)

    def __init__(self, command: str, *, timeout_seconds: int, log_dir: Path, artifact_prefix: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.command = command
        self.timeout_seconds = max(1, int(timeout_seconds or 300))
        self.log_dir = log_dir
        self.artifact_prefix = artifact_prefix
        self.process = QProcess(self)
        self.stdout = ""
        self.stderr = ""
        self.started_at = datetime.now().astimezone().isoformat()
        self._timed_out = False
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._timeout)

    def start(self) -> None:
        args = shell_command_args(self.command)
        self.process.start(args[0], args[1:])
        self.timer.start(self.timeout_seconds * 1000)

    def _timeout(self) -> None:
        if self.process.state() == QProcess.NotRunning:
            return
        self._timed_out = True
        self.stderr += f"\ncommand exceeded timeout of {self.timeout_seconds}s\n"
        self.process.kill()

    def _read_stdout(self) -> None:
        self.stdout += bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")

    def _read_stderr(self) -> None:
        self.stderr += bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")

    def _finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self.timer.stop()
        self._read_stdout()
        self._read_stderr()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = self.log_dir / f"{self.artifact_prefix}_stdout.txt"
        stderr_path = self.log_dir / f"{self.artifact_prefix}_stderr.txt"
        transcript_path = self.log_dir / f"{self.artifact_prefix}_transcript.txt"
        stdout_path.write_text(self.stdout, encoding="utf-8")
        stderr_path.write_text(self.stderr, encoding="utf-8")
        transcript_path.write_text("\n".join(part for part in (self.stdout, self.stderr) if part), encoding="utf-8")
        self.finished.emit(
            {
                "command": self.command,
                "started_at": self.started_at,
                "ended_at": datetime.now().astimezone().isoformat(),
                "stdout": self.stdout,
                "stderr": self.stderr,
                "exit_code": exit_code,
                "timed_out": self._timed_out,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "transcript_path": str(transcript_path),
            }
        )


class ToolEditorTab(QWidget):
    def __init__(
        self,
        store: ToolLibraryStore | None = None,
        *,
        audit_callback: AuditCallback | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store or ToolLibraryStore()
        self.audit_callback = audit_callback
        self._definitions: list[dict[str, Any]] = []
        self._statuses: dict[str, dict[str, Any]] = {}
        self._runners: list[ToolCommandRunner] = []
        self._install_queue: list[dict[str, Any]] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)
        splitter = apply_responsive_splitter(QSplitter(Qt.Horizontal), (3, 2))
        root.addWidget(splitter, 1)

        left = QFrame()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.add_button = QPushButton("+")
        self.edit_button = QPushButton("Edit")
        self.refresh_button = QPushButton("Refresh Status")
        self.download_missing_button = QPushButton("Download Missing")
        for button, role in (
            (self.add_button, "primary"),
            (self.edit_button, "secondary"),
            (self.refresh_button, "secondary"),
            (self.download_missing_button, "secondary"),
        ):
            style_button(button, role=role)
            toolbar.addWidget(button)
        toolbar_widget = QWidget()
        toolbar_widget.setLayout(toolbar)
        self.table = QTableView()
        self.table.setObjectName("dataGrid")
        ensure_table_defaults(self.table)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.model = ToolTableModel(self)
        self.table.setModel(self.model)
        self.status_label = QLabel("")
        section, _title, _summary = build_table_section("Tool Library", self.table, toolbar=toolbar_widget, status_label=self.status_label)
        left_layout.addWidget(section, 1)
        splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("settingsContent")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        self.detail_label = QLabel("Select a tool.")
        self.detail_label.setWordWrap(True)
        self.raw_preview = configure_scroll_surface(QPlainTextEdit())
        self.raw_preview.setReadOnly(True)
        right_layout.addWidget(self.detail_label)
        right_layout.addWidget(self.raw_preview, 1)
        splitter.addWidget(right)

        self.add_button.clicked.connect(self._add_tool)
        self.edit_button.clicked.connect(self._edit_selected_tool)
        self.refresh_button.clicked.connect(self.refresh_status)
        self.download_missing_button.clicked.connect(self.download_missing)
        self.table.customContextMenuRequested.connect(self._open_context_menu)
        self.table.selectionModel().currentRowChanged.connect(lambda _current, _previous: self._selected_changed())
        self.reload_definitions()

    def reload_definitions(self) -> None:
        result = self.store.load_definitions()
        self._definitions = result.definitions
        self._statuses = {str(item.get("id")): check_tool_status(item).to_dict() for item in self._definitions}
        self.model.set_rows(self._definitions, self._statuses)
        self.status_label.setText("; ".join(result.warnings[:3]) if result.warnings else f"{len(self._definitions)} tool(s) loaded.")
        if self._definitions:
            self.table.selectRow(0)
        self._selected_changed()

    def refresh_status(self) -> None:
        self.reload_definitions()

    def _selected_definition(self) -> dict[str, Any] | None:
        row = self.table.currentIndex().row()
        if 0 <= row < len(self._definitions):
            return self._definitions[row]
        return None

    def _selected_changed(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            self.detail_label.setText("Select a tool.")
            self.raw_preview.clear()
            return
        status = self._statuses.get(str(definition.get("id")), {})
        self.detail_label.setText(
            f"{definition.get('display_name')} is {_label_status(str(status.get('status') or 'missing'))}. "
            f"Executable: {definition.get('executable_name') or definition.get('install_path') or 'not configured'}"
        )
        self.raw_preview.setPlainText(json.dumps(definition, indent=2, sort_keys=True))

    def _save_definition(self, definition: dict[str, Any]) -> None:
        try:
            self.store.save_definition(definition, str(definition.get("save_scope") or "global"))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Save Tool Failed", str(exc))
            return
        self.reload_definitions()

    def _add_tool(self) -> None:
        dialog = ToolDefinitionDialog(self)
        if dialog.exec() == QDialog.Accepted:
            self._save_definition(dialog.definition())

    def _edit_selected_tool(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        dialog = ToolDefinitionDialog(self, deepcopy(definition))
        if dialog.exec() == QDialog.Accepted:
            self._save_definition(dialog.definition())

    def _duplicate_selected_tool(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        self.store.duplicate_definition(definition, str(definition.get("save_scope") or "global"))
        self.reload_definitions()

    def _toggle_selected_tool(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        updated = deepcopy(definition)
        updated["enabled"] = not bool(updated.get("enabled", True))
        self._save_definition(updated)

    def _log_dir_for(self, definition: dict[str, Any]) -> Path:
        today = datetime.now().strftime("%Y%m%d")
        scope = str(definition.get("save_scope") or "global")
        if scope == "workspace":
            return self.store.workspace_dir() / "logs" / today
        return default_tool_logs_dir() / today

    def _audit(self, action: str, summary: str, details: dict[str, Any] | None = None) -> None:
        if self.audit_callback is not None:
            self.audit_callback(action, summary, "", "", details)

    def _show_output(self, title: str, *, command: str, stdout: str, stderr: str, exit_code: int | None, summary: str = "") -> None:
        dialog = ToolCommandOutputDialog(self, title)
        dialog.set_result(command=command, stdout=stdout, stderr=stderr, exit_code=exit_code, summary=summary)
        dialog.exec()

    def check_selected_tool(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        tool_id = str(definition.get("id") or "")
        self._statuses[tool_id] = {"status": "checking"}
        self.model.set_rows(self._definitions, self._statuses)
        result = check_tool_status(definition)
        self._statuses[tool_id] = result.to_dict()
        self.model.set_rows(self._definitions, self._statuses)
        self._audit("tool.check.finished", f"Checked tool {tool_id}", result.to_dict())
        self._show_output(
            f"Check {definition.get('display_name')}",
            command=result.command,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            summary=f"{_label_status(result.status)}; path={result.detected_path or 'not detected'}; version={result.version or 'not detected'}",
        )

    def download_selected_tool(self) -> None:
        definition = self._selected_definition()
        if definition is not None:
            self._download_tool(definition)

    def _download_tool(self, definition: dict[str, Any]) -> None:
        command = str(definition.get("install_command") or "").strip()
        tool_id = str(definition.get("id") or "")
        if not command:
            self._statuses[tool_id] = {"status": "install_not_configured"}
            self.model.set_rows(self._definitions, self._statuses)
            self._show_output("Download Tool", command="", stdout="", stderr="install command not configured", exit_code=None)
            return
        if QMessageBox.question(self, "Download Tool", f"Run this command?\n\n{command}") != QMessageBox.Yes:
            return
        self._start_install(definition)

    def _start_install(self, definition: dict[str, Any]) -> None:
        command = str(definition.get("install_command") or "").strip()
        tool_id = str(definition.get("id") or "")
        self._statuses[tool_id] = {"status": "installing"}
        self.model.set_rows(self._definitions, self._statuses)
        self._audit("tool.install.started", f"Installing tool {tool_id}", {"tool_id": tool_id, "command": command})
        runner = ToolCommandRunner(
            command,
            timeout_seconds=int(definition.get("timeout_seconds") or 300),
            log_dir=self._log_dir_for(definition),
            artifact_prefix=tool_id,
            parent=self,
        )
        runner.finished.connect(lambda result, selected=definition, active=runner: self._install_finished(selected, result, active))
        self._runners.append(runner)
        runner.start()

    def _install_finished(self, definition: dict[str, Any], result: dict[str, Any], runner: ToolCommandRunner) -> None:
        if runner in self._runners:
            self._runners.remove(runner)
        tool_id = str(definition.get("id") or "")
        status = check_tool_status(definition)
        self._statuses[tool_id] = status.to_dict()
        self.model.set_rows(self._definitions, self._statuses)
        self._audit("tool.install.finished", f"Installed tool {tool_id}", {"tool_id": tool_id, **result, "status": status.to_dict()})
        self._show_output(
            f"Download {definition.get('display_name')}",
            command=str(result.get("command") or ""),
            stdout=str(result.get("stdout") or ""),
            stderr=str(result.get("stderr") or ""),
            exit_code=result.get("exit_code") if isinstance(result.get("exit_code"), int) else None,
            summary=f"Install finished. Current status: {_label_status(status.status)}",
        )
        if self._install_queue:
            self._start_install(self._install_queue.pop(0))

    def download_missing(self) -> None:
        no_command: list[str] = []
        eligible: list[dict[str, Any]] = []
        for definition in self._definitions:
            tool_id = str(definition.get("id") or "")
            status = self._statuses.get(tool_id) or check_tool_status(definition).to_dict()
            if status.get("status") != "missing" or not definition.get("enabled", True):
                continue
            if not str(definition.get("install_command") or "").strip():
                no_command.append(tool_id)
                self._statuses[tool_id] = {"status": "install_not_configured"}
                continue
            eligible.append(definition)
        self.model.set_rows(self._definitions, self._statuses)
        if no_command:
            self.status_label.setText("Install command not configured: " + ", ".join(no_command))
        if not eligible:
            return
        commands = "\n".join(str(item.get("install_command") or "") for item in eligible)
        if QMessageBox.question(self, "Download Missing", f"Run these commands sequentially?\n\n{commands}") != QMessageBox.Yes:
            return
        self._install_queue = eligible[1:]
        self._start_install(eligible[0])

    def _open_context_menu(self, point: Any) -> None:
        index = self.table.indexAt(point)
        if index.isValid():
            self.table.selectRow(index.row())
        definition = self._selected_definition()
        if definition is None:
            return
        menu = self.build_context_menu()
        menu.exec(self.table.viewport().mapToGlobal(point))

    def build_context_menu(self) -> QMenu:
        definition = self._selected_definition()
        menu = QMenu(self)
        check_action = menu.addAction("Check Tool")
        download_action = menu.addAction("Download Tool")
        edit_action = menu.addAction("Edit Tool")
        duplicate_action = menu.addAction("Duplicate Tool")
        toggle_action = menu.addAction("Disable Tool" if definition and definition.get("enabled", True) else "Enable Tool")
        check_action.triggered.connect(self.check_selected_tool)
        download_action.triggered.connect(self.download_selected_tool)
        edit_action.triggered.connect(self._edit_selected_tool)
        duplicate_action.triggered.connect(self._duplicate_selected_tool)
        toggle_action.triggered.connect(self._toggle_selected_tool)
        return menu
