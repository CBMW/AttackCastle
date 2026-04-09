from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
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
    set_tooltips,
    style_button,
    title_case_label,
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
        rail_layout.setContentsMargins(16, 16, 16, 16)
        rail_layout.setSpacing(12)
        rail_title = QLabel("Profile Library")
        rail_title.setObjectName("sectionTitle")
        rail_helper = QLabel("Save operator presets, duplicate them for new engagements, and keep launch defaults tidy.")
        rail_helper.setObjectName("helperText")
        rail_helper.setWordWrap(True)
        self.profile_list = QListWidget()
        self.profile_list.setObjectName("sidebarList")
        self.profile_list.currentRowChanged.connect(self._load_selected_profile)
        rail_layout.addWidget(rail_title)
        rail_layout.addWidget(rail_helper)
        rail_layout.addWidget(self.profile_list, 1)
        self.splitter.addWidget(rail)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        scroll = configure_scroll_surface(QScrollArea())
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        self.scroll_area = scroll
        scroll_container = QWidget()
        scroll_layout = QVBoxLayout(scroll_container)
        scroll_layout.setContentsMargins(0, 0, 8, 0)
        scroll_layout.setSpacing(14)

        helper = QLabel("Profiles define launch defaults, stored posture, tool coverage, and guardrails. They are stored as JSON and translated at launch time.")
        helper.setWordWrap(True)
        helper.setObjectName("helperText")
        scroll_layout.addWidget(helper)

        self.profile_blurb_label = QLabel("")
        self.profile_blurb_label.setObjectName("infoBanner")
        self.profile_blurb_label.setWordWrap(True)
        scroll_layout.addWidget(self.profile_blurb_label)

        self.profile_posture_label = QLabel("")
        self.profile_posture_label.setObjectName("attentionBanner")
        self.profile_posture_label.setProperty("tone", "neutral")
        self.profile_posture_label.setWordWrap(True)
        scroll_layout.addWidget(self.profile_posture_label)

        scroll_layout.addWidget(
            self._profile_form(
                include_identity=True,
                collapsible_sections=False,
                preset_header="Profile Presets",
                preset_helper="Apply a workstation preset, then save the result as a reusable profile for future engagements.",
            )
        )

        action_panel = QFrame()
        action_panel.setObjectName("toolbarPanel")
        action_layout = QVBoxLayout(action_panel)
        action_layout.setContentsMargins(16, 16, 16, 16)
        action_layout.setSpacing(12)
        button_row = FlowButtonRow()
        self.new_button = QPushButton("New Profile")
        self.duplicate_button = QPushButton("Duplicate")
        self.save_button = QPushButton("Save Profile")
        self.delete_button = QPushButton("Delete")
        self.import_button = QPushButton("Import")
        self.export_button = QPushButton("Export")
        self.reload_button = QPushButton("Reload")
        self.new_button.clicked.connect(self._new_profile)
        self.duplicate_button.clicked.connect(self._duplicate_profile)
        self.save_button.clicked.connect(self._save_profile)
        self.delete_button.clicked.connect(self._delete_profile)
        self.import_button.clicked.connect(self._import_profiles)
        self.export_button.clicked.connect(self._export_profiles)
        self.reload_button.clicked.connect(self.reload_profiles)
        style_button(self.new_button, role="secondary")
        style_button(self.save_button)
        for button in (self.duplicate_button,):
            style_button(button, role="secondary")
        for button in (self.delete_button, self.import_button, self.export_button, self.reload_button):
            style_button(button, role="secondary")
        set_tooltips(
            (
                (self.profile_list, "Browse saved GUI profiles and load one into the editor."),
                (self.new_button, "Start a new profile draft using the default form values."),
                (self.duplicate_button, "Duplicate the currently loaded profile so you can make a variant safely."),
                (self.save_button, "Save the current profile form back into the profile library."),
                (self.delete_button, "Delete the currently loaded profile from the profile library."),
                (self.import_button, "Import one or more profiles from a JSON file."),
                (self.export_button, "Export the current profile library to a JSON file."),
                (self.reload_button, "Reload profiles from disk and refresh the editor."),
            )
        )
        button_row.addWidget(self.new_button)
        button_row.addWidget(self.duplicate_button)
        button_row.addWidget(self.save_button)
        button_row.addWidget(self.delete_button)
        button_row.addWidget(self.import_button)
        button_row.addWidget(self.export_button)
        button_row.addWidget(self.reload_button)
        action_layout.addWidget(button_row)

        self.status_label = QLabel("Profiles are stored as JSON and translated into engine overrides at launch time.")
        self.status_label.setObjectName("helperText")
        self.status_label.setWordWrap(True)
        action_layout.addWidget(self.status_label)
        scroll_layout.addWidget(action_panel)
        scroll_layout.addStretch(1)
        scroll.setWidget(scroll_container)
        right_layout.addWidget(scroll)
        self.splitter.addWidget(right)

        self.reload_profiles()
        self.sync_profile_form_width(self.width())
        self._sync_responsive_mode(self.width())

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
            enabled_tools = sum(
                int(flag)
                for flag in (
                    profile.enable_nmap,
                    profile.enable_web_probe,
                    profile.enable_whatweb,
                    profile.enable_nikto,
                    profile.enable_nuclei,
                    profile.enable_wpscan,
                    profile.enable_sqlmap,
                )
            )
            self.profile_blurb_label.setText(
                f"{profile.name}: {profile.description or 'No description yet.'} | Base posture: {title_case_label(profile.base_profile)} | Stored profile posture with {enabled_tools} tools enabled"
            )
            self.profile_posture_label.setText(
                f"Stored risk mode: {title_case_label(profile.risk_mode)} | Validation: {title_case_label(profile.active_validation_mode)} | Rate mode: {title_case_label(profile.rate_limit_mode)} | Output: {profile.output_directory}"
            )
            self.profile_posture_label.setProperty(
                "tone",
                "alert"
                if profile.risk_mode == "aggressive"
                or profile.active_validation_mode == "aggressive"
                or profile.enable_sqlmap
                else "neutral",
            )
        else:
            self.profile_blurb_label.setText("Select a profile to review its stored posture, launch defaults, and tool coverage.")
            self.profile_posture_label.setText("Stored risk mode, validation posture, rate mode, and output defaults will appear here once a profile is selected.")
            self.profile_posture_label.setProperty("tone", "neutral")
        self.profile_posture_label.style().unpolish(self.profile_posture_label)
        self.profile_posture_label.style().polish(self.profile_posture_label)
        self.profile_posture_label.update()

    def _selected_profile_name(self) -> str:
        item = self.profile_list.currentItem()
        if item is None:
            return self.profile_name_edit.text().strip()
        return item.text().strip()

    def _new_profile(self) -> None:
        self._apply_profile_to_form(GuiProfile(name="New Profile"))
        self.profile_list.clearSelection()
        self.profile_blurb_label.setText("New profile draft. Name it clearly before saving so operators can find it later.")
        self.profile_posture_label.setText("Start from a preset, then save the stored posture and launch defaults as a reusable operator profile.")
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
