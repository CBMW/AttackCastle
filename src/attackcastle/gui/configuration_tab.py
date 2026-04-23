from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    PAGE_CARD_SPACING,
    PANEL_CONTENT_PADDING,
    PAGE_SECTION_SPACING,
    PersistentSplitterController,
    apply_responsive_splitter,
    set_tooltips,
    style_button,
)
from attackcastle.gui.forms import ProfileFieldsMixin
from attackcastle.gui.models import GuiProfile
from attackcastle.gui.profile_store import GuiProfileStore


class ConfigurationTab(QWidget, ProfileFieldsMixin):
    def __init__(
        self,
        store: GuiProfileStore,
        on_profiles_changed: Callable[[list[GuiProfile]], None],
        parent: QWidget | None = None,
        layout_loader: Callable[[str, str], list[int] | None] | None = None,
        layout_saver: Callable[[str, str, list[int]], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.on_profiles_changed = on_profiles_changed
        self._profiles = self.store.load()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(PAGE_SECTION_SPACING)
        self.splitter = apply_responsive_splitter(QSplitter(Qt.Horizontal), (2, 5))
        self._splitter_controller = PersistentSplitterController(
            self.splitter,
            "profiles_split",
            layout_loader,
            layout_saver,
            self,
        )
        root.addWidget(self.splitter, 1)

        rail = QFrame()
        rail.setObjectName("sidebarPanel")
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        rail_layout.setSpacing(PAGE_SECTION_SPACING)
        rail_title = QLabel("Profile Library")
        rail_title.setObjectName("sectionTitle")
        self.profile_list = QListWidget()
        self.profile_list.setObjectName("sidebarList")
        self.profile_list.currentRowChanged.connect(self._load_selected_profile)
        rail_layout.addWidget(rail_title)
        rail_layout.addWidget(self.profile_list, 1)
        library_actions = QFrame()
        library_actions.setObjectName("profileLibraryActions")
        library_action_layout = QHBoxLayout(library_actions)
        library_action_layout.setContentsMargins(0, 0, 0, 0)
        library_action_layout.setSpacing(PAGE_CARD_SPACING)
        self.new_button = self._library_action_button(
            QStyle.StandardPixmap.SP_FileIcon,
            "New Profile",
            role="secondary",
        )
        self.duplicate_button = self._library_action_button(
            QStyle.StandardPixmap.SP_FileDialogDetailedView,
            "Duplicate",
            role="secondary",
        )
        self.save_button = self._library_action_button(
            QStyle.StandardPixmap.SP_DialogSaveButton,
            "Save Profile",
            role="primary",
        )
        self.delete_button = self._library_action_button(
            QStyle.StandardPixmap.SP_DialogCloseButton,
            "Delete",
            role="danger",
        )
        self.delete_button.setIcon(QIcon())
        self.delete_button.setText("X")
        self.save_button.setObjectName("profilePrimaryAction")
        self.delete_button.setObjectName("profileDangerAction")
        self.new_button.clicked.connect(self._new_profile)
        self.duplicate_button.clicked.connect(self._duplicate_profile)
        self.save_button.clicked.connect(self._save_profile)
        self.delete_button.clicked.connect(self._delete_profile)
        library_action_layout.addStretch(1)
        library_action_layout.addWidget(self.new_button)
        library_action_layout.addWidget(self.duplicate_button)
        library_action_layout.addWidget(self.save_button)
        library_action_layout.addWidget(self.delete_button)
        library_action_layout.addStretch(1)
        rail_layout.addWidget(library_actions)

        self.status_label = QLabel("Profiles are stored as JSON and translated into engine overrides at launch time.")
        self.status_label.setObjectName("helperText")
        self.status_label.setWordWrap(True)
        rail_layout.addWidget(self.status_label)
        self.splitter.addWidget(rail)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        self.profile_form = (
            self._profile_form(
                include_identity=True,
                collapsible_sections=False,
            )
        )

        set_tooltips(
            (
                (self.profile_list, "Browse saved GUI profiles and load one into the editor."),
                (self.new_button, "Start a new profile draft using the default form values."),
                (self.duplicate_button, "Duplicate the currently loaded profile so you can make a variant safely."),
                (self.save_button, "Save the current profile form back into the profile library."),
                (self.delete_button, "Delete the currently loaded profile from the profile library."),
            )
        )
        right_layout.addWidget(self.profile_form, 1)
        self.splitter.addWidget(right)

        self.reload_profiles()
        self.sync_profile_form_width(self.width())
        self._sync_responsive_mode(self.width())

    def _library_action_button(
        self,
        icon: QStyle.StandardPixmap,
        accessible_name: str,
        *,
        role: str,
    ) -> QPushButton:
        button = QPushButton("")
        button.setAccessibleName(accessible_name)
        button.setIcon(self.style().standardIcon(icon))
        button.setIconSize(QSize(16, 16))
        button.setFixedSize(36, 32)
        button.setProperty("libraryAction", True)
        style_button(button, role=role)
        return button

    def _sync_responsive_mode(self, width: int) -> None:
        if width >= 1280:
            self.splitter.setOrientation(Qt.Horizontal)
            fallback = [320, max(width - 320, 760)]
            self._splitter_controller.apply(fallback)
            return
        if width >= 1040:
            self.splitter.setOrientation(Qt.Horizontal)
            fallback = [280, max(width - 280, 660)]
            self._splitter_controller.apply(fallback)
            return
        self.splitter.setOrientation(Qt.Vertical)
        self._splitter_controller.apply([240, max(self.height() - 240, 480)])

    def reload_profiles(self, preferred_profile_name: str | None = None) -> None:
        current_name = preferred_profile_name or self._selected_profile_name()
        try:
            self._profiles = self.store.load()
        except Exception as exc:  # noqa: BLE001
            self.status_label.setText(f"Failed to reload profiles: {exc}")
            QMessageBox.warning(self, "Reload Profiles Failed", f"AttackCastle could not reload GUI profiles.\n\n{exc}")
            return
        self.profile_list.blockSignals(True)
        self.profile_list.clear()
        for profile in self._profiles:
            self.profile_list.addItem(QListWidgetItem(profile.name))
        self.profile_list.blockSignals(False)
        if self._profiles:
            names = [item.name for item in self._profiles]
            selected_name = current_name if current_name in names else self._profiles[0].name
            self.profile_list.setCurrentRow(names.index(selected_name))
        else:
            self._load_selected_profile(-1)
        self.on_profiles_changed(self._profiles)

    def _load_selected_profile(self, row: int) -> None:
        if 0 <= row < len(self._profiles):
            profile = self._profiles[row]
            self._apply_profile_to_form(profile)

    def _selected_profile_name(self) -> str:
        item = self.profile_list.currentItem()
        if item is None:
            return self.profile_name_edit.text().strip()
        return item.text().strip()

    def _new_profile(self) -> None:
        self._apply_profile_to_form(GuiProfile(name="New Profile"))
        self.profile_list.clearSelection()
        self.status_label.setText("Creating a new profile draft.")
        self.profile_name_edit.selectAll()
        self.profile_name_edit.setFocus()

    def _duplicate_profile(self) -> None:
        profile = self._profile_from_form()
        profile.name = f"{profile.name} Copy"
        self._apply_profile_to_form(profile)
        self.status_label.setText("Profile duplicated. Adjust the name and save when ready.")

    def _save_profile(self) -> None:
        profile = self._profile_from_form()
        try:
            self.store.save_profile(profile)
        except Exception as exc:  # noqa: BLE001
            self.status_label.setText(f"Failed to save profile: {profile.name}")
            QMessageBox.warning(self, "Save Profile Failed", f"AttackCastle could not save '{profile.name}'.\n\n{exc}")
            return
        self.status_label.setText(f"Saved profile: {profile.name}")
        self.reload_profiles(preferred_profile_name=profile.name)

    def _delete_profile(self) -> None:
        profile_name = self.profile_name_edit.text().strip()
        if not profile_name:
            return
        decision = QMessageBox.question(self, "Delete Profile", f"Delete profile '{profile_name}'?")
        if decision != QMessageBox.Yes:
            self.status_label.setText(f"Delete cancelled: {profile_name}")
            return
        replacement_name = ""
        names = [item.name for item in self._profiles]
        if profile_name in names and len(names) > 1:
            index = names.index(profile_name)
            replacement_name = names[index - 1] if index > 0 else names[1]
        try:
            self.store.delete_profile(profile_name)
        except Exception as exc:  # noqa: BLE001
            self.status_label.setText(f"Failed to delete profile: {profile_name}")
            QMessageBox.warning(self, "Delete Profile Failed", f"AttackCastle could not delete '{profile_name}'.\n\n{exc}")
            return
        self.status_label.setText(f"Deleted profile: {profile_name}")
        self.reload_profiles(preferred_profile_name=replacement_name)

    def _import_profiles(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(self, "Import Profiles", "", "JSON Files (*.json)")
        if not selected:
            return
        try:
            self.store.import_from_path(Path(selected))
        except Exception as exc:  # noqa: BLE001
            self.status_label.setText(f"Import failed: {selected}")
            QMessageBox.warning(self, "Import Profiles Failed", f"AttackCastle could not import profiles from:\n{selected}\n\n{exc}")
            return
        self.status_label.setText(f"Imported profiles from {selected}")
        self.reload_profiles()

    def _export_profiles(self) -> None:
        selected, _ = QFileDialog.getSaveFileName(self, "Export Profiles", "attackcastle-profiles.json", "JSON Files (*.json)")
        if not selected:
            return
        try:
            self.store.export_to_path(Path(selected))
        except Exception as exc:  # noqa: BLE001
            self.status_label.setText(f"Export failed: {selected}")
            QMessageBox.warning(self, "Export Profiles Failed", f"AttackCastle could not export profiles to:\n{selected}\n\n{exc}")
            return
        self.status_label.setText(f"Exported profiles to {selected}")

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.sync_profile_form_width(self.width())
        self._sync_responsive_mode(self.width())
