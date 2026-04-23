from __future__ import annotations

import json
from typing import Callable

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QStyle,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    PAGE_CARD_SPACING,
    PANEL_CONTENT_PADDING,
    PAGE_SECTION_SPACING,
    PersistentSplitterController,
    apply_responsive_splitter,
    configure_scroll_surface,
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
        on_extensions_changed: Callable[[], None] | None = None,
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.on_theme_applied = on_theme_applied
        self.open_path = open_path
        self.on_extensions_changed = on_extensions_changed
        self._records = []
        self._selected_extension_id = ""
        self._loaded_text = ""
        self._dirty = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)

        splitter = apply_responsive_splitter(QSplitter(), (1, 4))
        self.splitter = splitter
        self._splitter_controller = PersistentSplitterController(
            self.splitter,
            "extensions_split",
            layout_loader,
            layout_saver,
            self,
        )

        action_panel = QFrame()
        action_panel.setObjectName("toolbarPanel")
        action_panel.setProperty("surface", "primary")
        self.action_panel = action_panel
        action_layout = QHBoxLayout(action_panel)
        action_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        action_layout.setSpacing(PAGE_CARD_SPACING)

        self.new_button = self._build_icon_button(
            "New Extension",
            QStyle.SP_FileDialogNewFolder,
            self._create_extension,
            "Create a new command hook extension scaffold.",
        )
        self.duplicate_button = self._build_icon_button(
            "Duplicate Extension",
            QStyle.SP_FileLinkIcon,
            self._duplicate_selected,
            "Duplicate the selected extension into a new manifest.",
        )
        self.save_button = self._build_icon_button(
            "Save Manifest",
            QStyle.SP_DialogSaveButton,
            self._save_current,
            "Save the manifest currently open in the editor.",
            role="primary",
        )
        self.reload_button = self._build_icon_button(
            "Reload Extensions",
            QStyle.SP_BrowserReload,
            self.reload_extensions,
            "Rediscover extensions from disk and refresh the page.",
        )
        self.toggle_enabled_button = self._build_icon_button(
            "Enable Extension",
            QStyle.SP_MediaPlay,
            self._toggle_enabled,
            "Enable or disable the selected extension without deleting it.",
        )
        self.apply_theme_button = self._build_icon_button(
            "Apply Theme",
            QStyle.SP_DialogApplyButton,
            self._apply_theme,
            "Apply the selected theme extension to the GUI immediately.",
        )
        self.open_folder_button = self._build_icon_button(
            "Open Folder",
            QStyle.SP_DirOpenIcon,
            self._open_folder,
            "Open the selected extension folder in the file manager.",
        )

        for button in (
            self.new_button,
            self.duplicate_button,
            self.save_button,
            self.reload_button,
            self.toggle_enabled_button,
            self.apply_theme_button,
            self.open_folder_button,
        ):
            action_layout.addWidget(button, 0, Qt.AlignVCenter)
        action_layout.addStretch(1)
        root.addWidget(action_panel, 0)

        rail = QFrame()
        rail.setObjectName("sidebarPanel")
        self.library_panel = rail
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        rail_layout.setSpacing(PAGE_SECTION_SPACING)
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

        editor_panel = QFrame()
        editor_panel.setObjectName("toolbarPanel")
        editor_panel.setProperty("surface", "primary")
        editor_layout = QVBoxLayout(editor_panel)
        editor_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        editor_layout.setSpacing(PAGE_SECTION_SPACING)
        editor_title = QLabel("Raw Manifest Editor")
        editor_title.setObjectName("sectionTitle")
        self.editor_status_label = QLabel("JSON editor ready.")
        self.meta_label = self.editor_status_label
        self.editor_status_label.setObjectName("helperText")
        self.editor_status_label.setWordWrap(True)
        self.editor = configure_scroll_surface(QPlainTextEdit())
        self.editor.setObjectName("extensionEditor")
        self.editor.textChanged.connect(self._editor_text_changed)
        set_tooltips(
            (
                (self.editor, "Edit the raw JSON manifest for the selected extension. Use Ctrl+S to save."),
            )
        )
        editor_layout.addWidget(editor_title)
        editor_layout.addWidget(self.editor, 1)
        editor_layout.addWidget(self.editor_status_label)
        splitter.addWidget(editor_panel)

        splitter.setSizes([320, 960])
        root.addWidget(splitter, 1)

        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._save_current)

        self.reload_extensions()
        self.sync_responsive_mode(self.width())

    def sync_responsive_mode(self, width: int) -> None:
        if width >= 1400:
            self.splitter.setOrientation(Qt.Horizontal)
            self._splitter_controller.apply([320, max(width - 320, 960)])
            return
        if width >= 1120:
            self.splitter.setOrientation(Qt.Horizontal)
            self._splitter_controller.apply([280, max(width - 280, 720)])
            return
        self.splitter.setOrientation(Qt.Vertical)
        self._splitter_controller.apply([220, max(self.height() - 220, 420)])

    def _build_icon_button(
        self,
        label: str,
        icon: QStyle.StandardPixmap,
        handler: Callable[[], None],
        tooltip: str,
        *,
        role: str = "secondary",
    ) -> QToolButton:
        button = QToolButton()
        button.setText(label)
        button.setToolButtonStyle(Qt.ToolButtonIconOnly)
        button.setIcon(self.style().standardIcon(icon))
        button.setIconSize(QSize(16, 16))
        button.setFixedSize(32, 32)
        style_button(button, role=role, min_height=32)
        button.clicked.connect(handler)
        button.setToolTip(tooltip)
        button.setStatusTip(tooltip)
        button.setWhatsThis(tooltip)
        return button

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
        if record.is_valid:
            state = "Dirty changes pending save." if self._dirty else "Manifest is valid and ready."
            if record.active_theme:
                state += " This is the active GUI theme."
        else:
            state = f"Manifest diagnostics: {record.load_error}"
        self.editor_status_label.setText(
            f"{record.display_name} | ID: {record.extension_id} | Capabilities: {capabilities} | Enabled: {'Yes' if record.enabled else 'No'}\n"
            f"{state} Ctrl+S saves the current manifest."
        )
        self.toggle_enabled_button.setText("Disable" if record.enabled else "Enable")
        self.toggle_enabled_button.setIcon(
            self.style().standardIcon(QStyle.SP_MediaPause if record.enabled else QStyle.SP_MediaPlay)
        )
        self.toggle_enabled_button.setToolTip(
            "Disable the selected extension without deleting it."
            if record.enabled
            else "Enable the selected extension without deleting it."
        )
        self.toggle_enabled_button.setStatusTip(self.toggle_enabled_button.toolTip())
        self.toggle_enabled_button.setWhatsThis(self.toggle_enabled_button.toolTip())
        self.apply_theme_button.setEnabled(bool(record.manifest and record.manifest.is_theme))
        self.toggle_enabled_button.setEnabled(True)
        self.duplicate_button.setEnabled(record.manifest is not None)
        self.save_button.setEnabled(True)
        self.open_folder_button.setEnabled(True)
        self.open_folder_button.setToolTip(
            f"Open the selected extension folder in the file manager.\n{record.directory}"
        )
        self.open_folder_button.setStatusTip(self.open_folder_button.toolTip())
        self.open_folder_button.setWhatsThis(self.open_folder_button.toolTip())
        self.action_panel.setToolTip(
            f"{record.display_name}\nID: {record.extension_id}\nEnabled: {'Yes' if record.enabled else 'No'}\n{state}"
        )

    def _clear_editor_state(self) -> None:
        self._selected_extension_id = ""
        self._loaded_text = ""
        self._dirty = False
        self.editor.blockSignals(True)
        self.editor.clear()
        self.editor.blockSignals(False)
        self.editor_status_label.setText("JSON editor ready.")
        self.toggle_enabled_button.setText("Enable")
        self.toggle_enabled_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.toggle_enabled_button.setEnabled(False)
        self.apply_theme_button.setEnabled(False)
        self.duplicate_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.open_folder_button.setEnabled(False)
        self.open_folder_button.setToolTip("Open the selected extension folder in the file manager.")
        self.open_folder_button.setStatusTip(self.open_folder_button.toolTip())
        self.open_folder_button.setWhatsThis(self.open_folder_button.toolTip())
        self.action_panel.setToolTip("Extension actions")

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
            self.action_panel.setToolTip(str(exc))
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
        if self.on_extensions_changed is not None:
            self.on_extensions_changed()

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
