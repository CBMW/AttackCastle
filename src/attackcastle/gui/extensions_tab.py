from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    FlowButtonRow,
    PAGE_SECTION_SPACING,
    PersistentSplitterController,
    apply_responsive_splitter,
    configure_scroll_surface,
    refresh_widget_style,
    set_tooltips,
    style_button,
    title_case_label,
)
from attackcastle.gui.extensions import ExtensionManifest, ExtensionValidationError
from attackcastle.gui.extensions_store import GuiExtensionStore


class ExtensionsTab(QWidget):
    def __init__(
        self,
        store: GuiExtensionStore,
        on_theme_applied: Callable[[ExtensionManifest], None],
        open_path: Callable[[str], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.on_theme_applied = on_theme_applied
        self.open_path = open_path
        self._records = []
        self._selected_extension_id = ""
        self._loaded_text = ""
        self._dirty = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)

        splitter = apply_responsive_splitter(QSplitter(), (2, 3, 5))
        self.splitter = splitter
        self._splitter_controller = PersistentSplitterController(
            self.splitter,
            "extensions_split",
            layout_loader,
            layout_saver,
            self,
        )

        rail = QFrame()
        rail.setObjectName("sidebarPanel")
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(16, 16, 16, 16)
        rail_layout.setSpacing(12)
        rail_title = QLabel("Extension Library")
        rail_title.setObjectName("sectionTitle")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search extensions")
        self.search_edit.textChanged.connect(self._reload_list)
        self.extension_list = configure_scroll_surface(QListWidget())
        self.extension_list.setObjectName("sidebarList")
        self.extension_list.currentRowChanged.connect(self._extension_selected)
        rail_layout.addWidget(rail_title)
        rail_layout.addWidget(self.search_edit)
        rail_layout.addWidget(self.extension_list, 1)
        splitter.addWidget(rail)

        status_panel = QFrame()
        status_panel.setObjectName("toolbarPanel")
        status_layout = QVBoxLayout(status_panel)
        status_layout.setContentsMargins(16, 16, 16, 16)
        status_layout.setSpacing(12)
        status_title = QLabel("Manifest Status")
        status_title.setObjectName("sectionTitle")
        self.meta_label = QLabel("Select an extension to inspect its manifest and state.")
        self.meta_label.setObjectName("infoBanner")
        self.meta_label.setWordWrap(True)
        self.path_label = QLabel("")
        self.path_label.setObjectName("helperText")
        self.path_label.setWordWrap(True)
        self.state_label = QLabel("No extension selected.")
        self.state_label.setObjectName("attentionBanner")
        self.state_label.setProperty("tone", "neutral")
        self.state_label.setWordWrap(True)

        primary_actions = FlowButtonRow()
        self.new_button = QPushButton("New")
        self.duplicate_button = QPushButton("Duplicate")
        self.save_button = QPushButton("Save")
        self.reload_button = QPushButton("Reload")
        style_button(self.new_button, role="secondary")
        style_button(self.duplicate_button, role="secondary")
        style_button(self.save_button)
        style_button(self.reload_button, role="secondary")
        self.new_button.clicked.connect(self._create_extension)
        self.duplicate_button.clicked.connect(self._duplicate_selected)
        self.save_button.clicked.connect(self._save_current)
        self.reload_button.clicked.connect(self.reload_extensions)
        for button in (self.new_button, self.duplicate_button, self.save_button, self.reload_button):
            primary_actions.addWidget(button)

        secondary_actions = FlowButtonRow()
        self.toggle_enabled_button = QPushButton("Enable")
        self.apply_theme_button = QPushButton("Apply Theme")
        self.open_folder_button = QPushButton("Open Folder")
        style_button(self.toggle_enabled_button, role="secondary")
        style_button(self.apply_theme_button, role="secondary")
        style_button(self.open_folder_button, role="secondary")
        self.toggle_enabled_button.clicked.connect(self._toggle_enabled)
        self.apply_theme_button.clicked.connect(self._apply_theme)
        self.open_folder_button.clicked.connect(self._open_folder)
        for button in (self.toggle_enabled_button, self.apply_theme_button, self.open_folder_button):
            secondary_actions.addWidget(button)
        set_tooltips(
            (
                (self.search_edit, "Filter the extension list by name, ID, or capability."),
                (self.extension_list, "Select an extension to inspect its manifest and runtime state."),
                (self.new_button, "Create a new command hook extension scaffold."),
                (self.duplicate_button, "Duplicate the selected extension into a new manifest."),
                (self.save_button, "Save the manifest currently open in the editor."),
                (self.reload_button, "Rediscover extensions from disk and refresh the page."),
                (self.toggle_enabled_button, "Enable or disable the selected extension without deleting it."),
                (self.apply_theme_button, "Apply the selected theme extension to the GUI immediately."),
                (self.open_folder_button, "Open the selected extension folder in the file manager."),
            )
        )

        status_layout.addWidget(status_title)
        status_layout.addWidget(self.meta_label)
        status_layout.addWidget(self.path_label)
        status_layout.addWidget(self.state_label)
        status_layout.addWidget(primary_actions)
        status_layout.addWidget(secondary_actions)
        status_layout.addStretch(1)
        splitter.addWidget(status_panel)

        editor_panel = QFrame()
        editor_panel.setObjectName("toolbarPanel")
        editor_layout = QVBoxLayout(editor_panel)
        editor_layout.setContentsMargins(16, 16, 16, 16)
        editor_layout.setSpacing(10)
        editor_title = QLabel("Raw Manifest Editor")
        editor_title.setObjectName("sectionTitle")
        self.editor_status_label = QLabel("JSON editor ready.")
        self.editor_status_label.setObjectName("helperText")
        self.editor_status_label.setWordWrap(True)
        self.editor = configure_scroll_surface(QPlainTextEdit())
        self.editor.setObjectName("extensionEditor")
        self.editor.textChanged.connect(self._editor_text_changed)
        set_tooltips(
            (
                (self.editor, "Edit the raw JSON manifest for the selected extension. Use Ctrl+S to save."),
                (self.meta_label, "Shows the selected extension ID, capabilities, and enabled state."),
                (self.path_label, "Shows the manifest path for the selected extension."),
                (self.state_label, "Shows validation results and save state for the selected manifest."),
            )
        )
        editor_layout.addWidget(editor_title)
        editor_layout.addWidget(self.editor_status_label)
        editor_layout.addWidget(self.editor, 1)
        splitter.addWidget(editor_panel)

        splitter.setSizes([280, 360, 920])
        root.addWidget(splitter, 1)

        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._save_current)

        self.reload_extensions()
        self.sync_responsive_mode(self.width())

    def sync_responsive_mode(self, width: int) -> None:
        if width >= 1400:
            self.splitter.setOrientation(Qt.Horizontal)
            self._splitter_controller.apply([280, 340, max(width - 620, 860)])
            return
        if width >= 1120:
            self.splitter.setOrientation(Qt.Horizontal)
            self._splitter_controller.apply([240, 300, max(width - 540, 660)])
            return
        self.splitter.setOrientation(Qt.Vertical)
        self._splitter_controller.apply([220, 240, max(self.height() - 460, 360)])

    def reload_extensions(self) -> None:
        self._records = self.store.discover()
        self._reload_list()
        if self._selected_extension_id:
            self._select_extension_id(self._selected_extension_id)
            return
        state = self.store.load_state()
        preferred = state.last_opened_extension_id
        if preferred:
            self._select_extension_id(preferred)
        elif self.extension_list.count():
            self.extension_list.setCurrentRow(0)
        else:
            self._clear_editor_state()

    def _reload_list(self) -> None:
        current = self._selected_extension_id
        search = self.search_edit.text().strip().lower()
        self.extension_list.blockSignals(True)
        self.extension_list.clear()
        for record in self._records:
            haystack = f"{record.display_name} {record.extension_id} {' '.join(record.capabilities)}".lower()
            if search and search not in haystack:
                continue
            title = record.display_name
            if not record.is_valid:
                title += " [invalid]"
            elif record.active_theme:
                title += " [active theme]"
            item = QListWidgetItem(title)
            item.setData(0x0100, record.extension_id)
            self.extension_list.addItem(item)
        self.extension_list.blockSignals(False)
        if current:
            self._select_extension_id(current)
        elif self.extension_list.count():
            self.extension_list.setCurrentRow(0)

    def _select_extension_id(self, extension_id: str) -> None:
        for index in range(self.extension_list.count()):
            item = self.extension_list.item(index)
            if str(item.data(0x0100) or "") == extension_id:
                self.extension_list.setCurrentRow(index)
                return

    def _extension_selected(self, row: int) -> None:
        if row < 0:
            self._clear_editor_state()
            return
        item = self.extension_list.item(row)
        extension_id = str(item.data(0x0100) or "")
        record = next((candidate for candidate in self._records if candidate.extension_id == extension_id), None)
        if record is None:
            self._clear_editor_state()
            return
        self._selected_extension_id = extension_id
        self._loaded_text = record.raw_text or (json.dumps(record.manifest.to_dict(), indent=2, sort_keys=True) if record.manifest is not None else "")
        self.editor.blockSignals(True)
        self.editor.setPlainText(self._loaded_text)
        self.editor.blockSignals(False)
        self._dirty = False
        self.store.set_last_opened_extension(extension_id)
        self._refresh_record_status(record)

    def _refresh_record_status(self, record) -> None:
        capabilities = ", ".join(title_case_label(item) for item in record.capabilities) or "Unknown"
        self.meta_label.setText(
            f"{record.display_name} | ID: {record.extension_id} | Capabilities: {capabilities} | Enabled: {'Yes' if record.enabled else 'No'}"
        )
        self.path_label.setText(str(record.manifest_path))
        if record.is_valid:
            tone = "ok" if not self._dirty else "warning"
            state = "Dirty changes pending save." if self._dirty else "Manifest is valid and ready."
            if record.active_theme:
                state += " This is the active GUI theme."
        else:
            tone = "alert"
            state = f"Manifest diagnostics: {record.load_error}"
        self.state_label.setText(state)
        self.state_label.setProperty("tone", tone)
        refresh_widget_style(self.state_label)
        self.editor_status_label.setText(
            "Ctrl+S saves the current manifest. Use Format JSON before saving if you want canonical ordering."
        )
        self.toggle_enabled_button.setText("Disable" if record.enabled else "Enable")
        self.apply_theme_button.setEnabled(bool(record.manifest and record.manifest.is_theme))
        self.toggle_enabled_button.setEnabled(True)
        self.duplicate_button.setEnabled(record.manifest is not None)
        self.save_button.setEnabled(True)
        self.open_folder_button.setEnabled(True)

    def _clear_editor_state(self) -> None:
        self._selected_extension_id = ""
        self._loaded_text = ""
        self._dirty = False
        self.editor.blockSignals(True)
        self.editor.clear()
        self.editor.blockSignals(False)
        self.meta_label.setText("Select an extension to inspect its manifest and state.")
        self.path_label.setText("")
        self.state_label.setText("No extension selected.")
        self.state_label.setProperty("tone", "neutral")
        refresh_widget_style(self.state_label)
        self.editor_status_label.setText("JSON editor ready.")

    def _editor_text_changed(self) -> None:
        current = self.editor.toPlainText()
        self._dirty = current != self._loaded_text
        record = next((candidate for candidate in self._records if candidate.extension_id == self._selected_extension_id), None)
        if record is not None:
            self._refresh_record_status(record)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_responsive_mode(self.width())

    def _create_extension(self) -> None:
        manifest = self.store.create_command_hook_extension()
        self.reload_extensions()
        self._select_extension_id(manifest.extension_id)

    def _duplicate_selected(self) -> None:
        if not self._selected_extension_id:
            return
        try:
            manifest = self.store.duplicate_extension(self._selected_extension_id)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Duplicate Failed", f"AttackCastle could not duplicate this extension.\n\n{exc}")
            return
        self.reload_extensions()
        self._select_extension_id(manifest.extension_id)

    def _save_current(self) -> None:
        text = self.editor.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Save Failed", "Extension manifests cannot be blank.")
            return
        record = next((candidate for candidate in self._records if candidate.extension_id == self._selected_extension_id), None)
        preferred_directory = record.directory.name if record is not None else None
        try:
            manifest = self.store.save_raw_text(text, preferred_directory_name=preferred_directory)
        except ExtensionValidationError as exc:
            self.editor_status_label.setText(str(exc))
            self.state_label.setText(str(exc))
            self.state_label.setProperty("tone", "alert")
            refresh_widget_style(self.state_label)
            return
        self._selected_extension_id = manifest.extension_id
        self.reload_extensions()
        self._select_extension_id(manifest.extension_id)

    def _toggle_enabled(self) -> None:
        if not self._selected_extension_id:
            return
        record = next((candidate for candidate in self._records if candidate.extension_id == self._selected_extension_id), None)
        if record is None:
            return
        self.store.set_extension_enabled(self._selected_extension_id, not record.enabled)
        self.reload_extensions()
        self._select_extension_id(self._selected_extension_id)

    def _apply_theme(self) -> None:
        if not self._selected_extension_id:
            return
        try:
            manifest = parse_current_manifest(self.editor.toPlainText())
        except ExtensionValidationError as exc:
            self.editor_status_label.setText(str(exc))
            QMessageBox.warning(self, "Apply Theme Failed", f"AttackCastle could not apply this theme.\n\n{exc}")
            return
        if not manifest.is_theme:
            QMessageBox.information(self, "Not A Theme", "Only theme extensions can be applied to the GUI.")
            return
        try:
            self.store.set_active_theme(manifest.extension_id)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Apply Theme Failed", f"AttackCastle could not mark this theme active.\n\n{exc}")
            return
        self.on_theme_applied(manifest)
        self.reload_extensions()
        self._select_extension_id(manifest.extension_id)

    def _open_folder(self) -> None:
        record = next((candidate for candidate in self._records if candidate.extension_id == self._selected_extension_id), None)
        if record is None:
            return
        self.open_path(str(record.directory))


def parse_current_manifest(text: str) -> ExtensionManifest:
    from attackcastle.gui.extensions import parse_extension_text

    return parse_extension_text(text)
