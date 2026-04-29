from __future__ import annotations

from copy import deepcopy
from typing import Any

from PySide6.QtCore import Qt
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
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from attackcastle.findings.library import FindingLibraryStore
from attackcastle.findings.rule_schema import (
    OPERATOR_SCOPES,
    SEVERITIES,
    TRIGGER_OPERATORS,
    default_finding_definition,
    normalize_definition,
    normalize_trigger,
    parse_int_list,
    validate_detection,
)
from attackcastle.gui.common import (
    PAGE_SECTION_SPACING,
    apply_form_layout_defaults,
    apply_responsive_splitter,
    configure_scroll_surface,
    configure_tab_widget,
    size_dialog_to_screen,
    style_button,
)


class TriggerEditorWidget(QWidget):
    def __init__(self, trigger: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.enabled_checkbox = QCheckBox()
        self.enabled_checkbox.setChecked(True)
        self.tool_combo = QComboBox()
        self.tool_combo.setEditable(True)
        self.tool_combo.addItems(
            [
                "http_security_headers",
                "web_probe",
                "whatweb",
                "nikto",
                "nuclei",
                "sqlmap",
                "wpscan",
                "nmap",
                "tls",
                "any",
            ]
        )
        self.operator_combo = QComboBox()
        self.operator_combo.addItems(list(TRIGGER_OPERATORS))
        self.scope_combo = QComboBox()
        self.value_edit = QLineEdit()
        self.delete_button = QPushButton("Delete")
        style_button(self.delete_button, role="danger")

        for widget in (self.tool_combo, self.operator_combo, self.scope_combo, self.value_edit):
            widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(self.enabled_checkbox, 0)
        layout.addWidget(self.tool_combo, 2)
        layout.addWidget(self.operator_combo, 2)
        layout.addWidget(self.scope_combo, 2)
        layout.addWidget(self.value_edit, 3)
        layout.addWidget(self.delete_button, 0)

        self.operator_combo.currentTextChanged.connect(self._sync_scopes)
        self._sync_scopes()
        if trigger:
            self.load_trigger(trigger)

    def _sync_scopes(self) -> None:
        current = self.scope_combo.currentText()
        operator = self.operator_combo.currentText()
        self.scope_combo.clear()
        self.scope_combo.addItems(list(OPERATOR_SCOPES.get(operator, ())))
        if current:
            self.scope_combo.setCurrentText(current)
        value_required = operator not in {"tool succeeded", "tool failed", "timeout occurred"}
        self.value_edit.setEnabled(value_required)

    def load_trigger(self, trigger: dict[str, Any]) -> None:
        normalized = normalize_trigger(trigger)
        self.enabled_checkbox.setChecked(bool(normalized.get("enabled", True)))
        self.tool_combo.setCurrentText(str(normalized.get("tool") or "any"))
        self.operator_combo.setCurrentText(str(normalized.get("operator") or "output contains"))
        self._sync_scopes()
        self.scope_combo.setCurrentText(str(normalized.get("scope") or self.scope_combo.currentText()))
        value = normalized.get("value", "")
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        elif isinstance(value, dict):
            name = value.get("name") or value.get("header") or ""
            expected = value.get("value") or ""
            value = f"{name}={expected}" if expected else str(name)
        self.value_edit.setText(str(value or ""))

    def trigger(self, index: int) -> dict[str, Any]:
        operator = self.operator_combo.currentText()
        value: Any = self.value_edit.text().strip()
        if operator == "status code in list":
            value = parse_int_list(value)
        elif operator in {"status code equals", "exit code equals"}:
            try:
                value = int(value)
            except ValueError:
                value = None
        return normalize_trigger(
            {
                "id": f"trigger-{index}",
                "enabled": self.enabled_checkbox.isChecked(),
                "tool": self.tool_combo.currentText().strip() or "any",
                "operator": operator,
                "scope": self.scope_combo.currentText(),
                "value": value,
            }
        )


class FindingDefinitionDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, definition: dict[str, Any] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Finding Definition")
        self.setModal(True)
        self.setMinimumSize(780, 640)
        size_dialog_to_screen(self, default_width=980, default_height=860, min_width=780, min_height=640)
        self._trigger_widgets: list[TriggerEditorWidget] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)
        self.tabs = QFrame()
        form = QFormLayout(self.tabs)
        form.setContentsMargins(12, 14, 12, 12)
        apply_form_layout_defaults(form)

        self.id_edit = QLineEdit()
        self.title_edit = QLineEdit()
        self.enabled_checkbox = QCheckBox("Enabled")
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(list(SEVERITIES))
        self.root_cause_edit = QLineEdit()
        self.category_edit = QLineEdit()
        self.description_edit = self._text_edit(80)
        self.impact_edit = self._text_edit(72)
        self.likelihood_edit = self._text_edit(72)
        self.recommendations_edit = self._text_edit(80)
        self.references_edit = self._text_edit(60)
        self.tags_edit = QLineEdit()
        self.logic_combo = QComboBox()
        self.logic_combo.addItems(["any", "all"])

        form.addRow("ID", self.id_edit)
        form.addRow("", self.enabled_checkbox)
        form.addRow("Title", self.title_edit)
        form.addRow("Severity", self.severity_combo)
        form.addRow("Root Cause", self.root_cause_edit)
        form.addRow("Category", self.category_edit)
        form.addRow("Description", self.description_edit)
        form.addRow("Impact", self.impact_edit)
        form.addRow("Likelihood", self.likelihood_edit)
        form.addRow("Recommendations", self.recommendations_edit)
        form.addRow("References", self.references_edit)
        form.addRow("Tags", self.tags_edit)
        form.addRow("Combine Triggers", self.logic_combo)
        root.addWidget(self.tabs)

        trigger_panel = QFrame()
        trigger_panel.setObjectName("launchPanelGroup")
        trigger_layout = QVBoxLayout(trigger_panel)
        trigger_layout.setContentsMargins(12, 12, 12, 12)
        trigger_layout.setSpacing(8)
        header = QHBoxLayout()
        header.addWidget(QLabel("Detection Rules / Triggers"))
        header.addStretch(1)
        self.add_trigger_button = QPushButton("Add Trigger")
        style_button(self.add_trigger_button)
        self.add_trigger_button.clicked.connect(lambda: self._add_trigger({}))
        header.addWidget(self.add_trigger_button)
        trigger_layout.addLayout(header)
        self.trigger_container = QWidget()
        self.trigger_layout = QVBoxLayout(self.trigger_container)
        self.trigger_layout.setContentsMargins(0, 0, 0, 0)
        self.trigger_layout.setSpacing(6)
        trigger_layout.addWidget(self.trigger_container)
        root.addWidget(trigger_panel, 1)

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

        self.load_definition(definition or default_finding_definition())

    def _text_edit(self, height: int) -> QPlainTextEdit:
        editor = configure_scroll_surface(QPlainTextEdit())
        editor.setMinimumHeight(height)
        editor.setWordWrapMode(editor.wordWrapMode())
        return editor

    def _add_trigger(self, trigger: dict[str, Any]) -> None:
        widget = TriggerEditorWidget(trigger, self)
        widget.delete_button.clicked.connect(lambda _checked=False, selected=widget: self._delete_trigger(selected))
        self._trigger_widgets.append(widget)
        self.trigger_layout.addWidget(widget)

    def _delete_trigger(self, widget: TriggerEditorWidget) -> None:
        if widget in self._trigger_widgets:
            self._trigger_widgets.remove(widget)
        self.trigger_layout.removeWidget(widget)
        widget.deleteLater()

    def load_definition(self, definition: dict[str, Any]) -> None:
        normalized = normalize_definition(definition)
        self.id_edit.setText(str(normalized.get("id") or ""))
        self.enabled_checkbox.setChecked(bool(normalized.get("enabled", True)))
        self.title_edit.setText(str(normalized.get("title") or ""))
        self.severity_combo.setCurrentText(str(normalized.get("severity") or "low"))
        self.root_cause_edit.setText(str(normalized.get("root_cause") or ""))
        self.category_edit.setText(str(normalized.get("category") or "General"))
        self.description_edit.setPlainText(str(normalized.get("description") or ""))
        self.impact_edit.setPlainText(str(normalized.get("impact") or ""))
        self.likelihood_edit.setPlainText(str(normalized.get("likelihood") or ""))
        self.recommendations_edit.setPlainText("\n".join(normalized.get("recommendations", [])))
        self.references_edit.setPlainText("\n".join(normalized.get("references", [])))
        self.tags_edit.setText(", ".join(normalized.get("tags", [])))
        detection = normalized.get("detection", {}) if isinstance(normalized.get("detection"), dict) else {}
        self.logic_combo.setCurrentText(str(detection.get("logic") or "any"))
        for widget in list(self._trigger_widgets):
            self._delete_trigger(widget)
        for trigger in detection.get("triggers", []) if isinstance(detection.get("triggers"), list) else []:
            self._add_trigger(trigger)

    def definition(self) -> dict[str, Any]:
        definition = default_finding_definition()
        definition.update(
            {
                "id": self.id_edit.text().strip(),
                "enabled": self.enabled_checkbox.isChecked(),
                "title": self.title_edit.text().strip(),
                "severity": self.severity_combo.currentText(),
                "root_cause": self.root_cause_edit.text().strip(),
                "category": self.category_edit.text().strip() or "General",
                "description": self.description_edit.toPlainText(),
                "impact": self.impact_edit.toPlainText(),
                "likelihood": self.likelihood_edit.toPlainText(),
                "recommendations": [line.strip() for line in self.recommendations_edit.toPlainText().splitlines() if line.strip()],
                "references": [line.strip() for line in self.references_edit.toPlainText().splitlines() if line.strip()],
                "tags": [item.strip() for item in self.tags_edit.text().split(",") if item.strip()],
                "detection": {
                    "logic": self.logic_combo.currentText(),
                    "triggers": [widget.trigger(index) for index, widget in enumerate(self._trigger_widgets, start=1)],
                },
            }
        )
        return normalize_definition(definition)

    def accept(self) -> None:
        definition = self.definition()
        if not definition.get("id"):
            QMessageBox.warning(self, "Finding Definition", "Finding id is required.")
            return
        issues = validate_detection(definition)
        if issues:
            QMessageBox.warning(self, "Detection Rules", "\n".join(issues))
            return
        super().accept()


class FindingsEditorTab(QWidget):
    def __init__(self, store: FindingLibraryStore | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.store = store or FindingLibraryStore()
        self._definitions: list[dict[str, Any]] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)
        splitter = apply_responsive_splitter(QSplitter(Qt.Horizontal), (1, 2))
        root.addWidget(splitter, 1)

        left = QFrame()
        left.setObjectName("sidebarPanel")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)
        self.definition_list = QListWidget()
        self.definition_list.setObjectName("sidebarList")
        self.definition_list.currentRowChanged.connect(self._definition_selected)
        actions = QHBoxLayout()
        self.add_button = QPushButton("+")
        self.edit_button = QPushButton("Edit")
        self.delete_button = QPushButton("Delete")
        self.reload_button = QPushButton("Reload")
        for button, role in (
            (self.add_button, "primary"),
            (self.edit_button, "secondary"),
            (self.delete_button, "danger"),
            (self.reload_button, "secondary"),
        ):
            style_button(button, role=role)
            actions.addWidget(button)
        self.add_button.clicked.connect(self._add_definition)
        self.edit_button.clicked.connect(self._edit_selected_definition)
        self.delete_button.clicked.connect(self._delete_selected_definition)
        self.reload_button.clicked.connect(self.reload_definitions)
        left_layout.addWidget(QLabel("Findings Library"))
        left_layout.addWidget(self.definition_list, 1)
        left_layout.addLayout(actions)
        splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("settingsContent")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("helperText")
        self.summary_label.setWordWrap(True)
        self.trigger_table = QTableWidget(0, 5)
        self.trigger_table.setHorizontalHeaderLabels(["Enabled", "Tool", "When", "Scope", "Value"])
        self.trigger_table.setObjectName("dataGrid")
        self.raw_preview = configure_scroll_surface(QPlainTextEdit())
        self.raw_preview.setReadOnly(True)
        tabs = QFrame()
        tabs_layout = QVBoxLayout(tabs)
        tabs_layout.setContentsMargins(0, 0, 0, 0)
        self.preview_tabs = configure_tab_widget(QTabWidget(), role="group")
        self.preview_tabs.addTab(self.trigger_table, "Triggers")
        self.preview_tabs.addTab(self.raw_preview, "JSON")
        tabs_layout.addWidget(self.preview_tabs)
        right_layout.addWidget(self.summary_label)
        right_layout.addWidget(tabs, 1)
        splitter.addWidget(right)

        self.reload_definitions()

    def reload_definitions(self) -> None:
        result = self.store.load_definitions()
        self._definitions = result.definitions
        self.definition_list.clear()
        for definition in self._definitions:
            label = f"{definition.get('title') or definition.get('id')} ({definition.get('severity', 'info')})"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, definition.get("id"))
            self.definition_list.addItem(item)
        if self._definitions:
            self.definition_list.setCurrentRow(0)
        if result.warnings:
            self.summary_label.setText("Library loaded with warnings: " + "; ".join(result.warnings[:3]))

    def _selected_definition(self) -> dict[str, Any] | None:
        row = self.definition_list.currentRow()
        if 0 <= row < len(self._definitions):
            return self._definitions[row]
        return None

    def _definition_selected(self, _row: int) -> None:
        definition = self._selected_definition()
        if definition is None:
            self.summary_label.setText("No finding selected.")
            self.trigger_table.setRowCount(0)
            self.raw_preview.clear()
            return
        state = "enabled" if definition.get("enabled", True) else "disabled"
        self.summary_label.setText(f"{definition.get('id')} is {state}. User library: {self.store.user_dir}")
        triggers = definition.get("detection", {}).get("triggers", []) if isinstance(definition.get("detection"), dict) else []
        self.trigger_table.setRowCount(len(triggers))
        for row, trigger in enumerate(triggers):
            values = [
                "Yes" if trigger.get("enabled", True) else "No",
                str(trigger.get("tool") or ""),
                str(trigger.get("operator") or ""),
                str(trigger.get("scope") or ""),
                ", ".join(str(item) for item in trigger.get("value", [])) if isinstance(trigger.get("value"), list) else str(trigger.get("value") or ""),
            ]
            for column, value in enumerate(values):
                self.trigger_table.setItem(row, column, QTableWidgetItem(value))
        import json

        self.raw_preview.setPlainText(json.dumps(definition, indent=2, sort_keys=True))

    def _add_definition(self) -> None:
        dialog = FindingDefinitionDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        self._save_definition(dialog.definition())

    def _edit_selected_definition(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        dialog = FindingDefinitionDialog(self, deepcopy(definition))
        if dialog.exec() != QDialog.Accepted:
            return
        self._save_definition(dialog.definition())

    def _save_definition(self, definition: dict[str, Any]) -> None:
        try:
            self.store.save_definition(definition)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Save Finding Definition Failed", str(exc))
            return
        self.reload_definitions()
        self._select_definition(str(definition.get("id") or ""))

    def _delete_selected_definition(self) -> None:
        definition = self._selected_definition()
        if definition is None:
            return
        definition_id = str(definition.get("id") or "")
        if not self.store.is_user_definition(definition_id):
            QMessageBox.information(self, "Findings Library", "Built-in definitions cannot be deleted here. Disable or override them instead.")
            return
        if QMessageBox.question(self, "Delete Finding Definition", f"Delete '{definition_id}' from the user library?") != QMessageBox.Yes:
            return
        self.store.delete_definition(definition_id)
        self.reload_definitions()

    def _select_definition(self, definition_id: str) -> None:
        for row in range(self.definition_list.count()):
            item = self.definition_list.item(row)
            if str(item.data(Qt.UserRole) or "") == definition_id:
                self.definition_list.setCurrentRow(row)
                return
