from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QLabel, QMessageBox

from attackcastle.gui.configuration_tab import ConfigurationTab
from attackcastle.gui.models import GuiProfile
from attackcastle.gui.profile_store import GuiProfileStore


def _make_tab(tmp_path: Path, store: GuiProfileStore | None = None) -> ConfigurationTab:
    app = QApplication.instance() or QApplication([])
    _ = app
    return ConfigurationTab(store or GuiProfileStore(tmp_path / "profiles.json"), lambda profiles: None)


def test_reload_profiles_preserves_current_selection(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_profile(GuiProfile(name="Zeta"))
    tab = _make_tab(tmp_path, store=store)

    try:
        names = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        tab.profile_list.setCurrentRow(names.index("Standard"))

        tab.reload_profiles()

        assert tab.profile_list.currentItem() is not None
        assert tab.profile_list.currentItem().text() == "Standard"
    finally:
        tab.close()


def test_profile_presets_drive_tool_posture_without_hiding_expert_controls(tmp_path: Path) -> None:
    tab = _make_tab(tmp_path)

    try:
        tab._apply_profile_recipe("WordPress")

        assert tab.enable_wpscan.isChecked() is True
        assert tab.enable_sqlmap.isChecked() is False
        assert tab.expert_tool_panel.isHidden()
        tab.expert_toggle_button.click()
        assert not tab.expert_tool_panel.isHidden()
    finally:
        tab.close()


def test_profile_form_reflows_tool_cards_for_narrow_widths(tmp_path: Path) -> None:
    tab = _make_tab(tmp_path)

    try:
        tab.resize(900, 800)
        tab.sync_profile_form_width(tab.width())

        assert tab.tool_family_grid.itemAtPosition(1, 0) is not None

        tab.resize(1400, 800)
        tab.sync_profile_form_width(tab.width())

        assert tab.tool_family_grid.itemAtPosition(0, 1) is not None
    finally:
        tab.close()


def test_configuration_tab_stacks_library_above_editor_on_narrow_widths(tmp_path: Path) -> None:
    tab = _make_tab(tmp_path)

    try:
        tab.resize(920, 900)
        tab.sync_profile_form_width(tab.width())
        tab._sync_responsive_mode(tab.width())
        assert tab.splitter.orientation() == Qt.Vertical

        tab.resize(1400, 900)
        tab.sync_profile_form_width(tab.width())
        tab._sync_responsive_mode(tab.width())
        assert tab.splitter.orientation() == Qt.Horizontal
    finally:
        tab.close()


def test_selected_profile_updates_posture_banner(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_profile(GuiProfile(name="Aggro", risk_mode="aggressive", enable_sqlmap=True))
    tab = _make_tab(tmp_path, store=store)

    try:
        names = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        tab.profile_list.setCurrentRow(names.index("Aggro"))

        assert "Stored risk mode: Aggressive" in tab.profile_posture_label.text()
        assert tab.profile_posture_label.property("tone") == "alert"
    finally:
        tab.close()


def test_profile_form_merges_risk_controls_into_profile_posture_section(tmp_path: Path) -> None:
    tab = _make_tab(tmp_path)

    try:
        section_titles = {
            label.text()
            for label in tab.findChildren(QLabel, "sectionTitle")
        }
        assert "Profile Posture" in section_titles
        assert "Safety" not in section_titles
    finally:
        tab.close()


def test_configuration_tab_exposes_tooltips_for_profile_actions(tmp_path: Path) -> None:
    tab = _make_tab(tmp_path)

    try:
        assert "profile library" not in tab.profile_list.toolTip().lower()
        assert "saved gui profiles" in tab.profile_list.toolTip().lower()
        assert "new profile draft" in tab.new_button.toolTip().lower()
        assert "duplicate the currently loaded profile" in tab.duplicate_button.toolTip().lower()
        assert "save the current profile form" in tab.save_button.toolTip().lower()
        assert "delete the currently loaded profile" in tab.delete_button.toolTip().lower()
        assert not hasattr(tab, "import_button")
        assert not hasattr(tab, "export_button")
        assert not hasattr(tab, "reload_button")
    finally:
        tab.close()


def test_delete_profile_confirms_and_selects_neighbor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_profile(GuiProfile(name="Blue Team"))
    store.save_profile(GuiProfile(name="Red Team"))
    tab = _make_tab(tmp_path, store=store)

    try:
        names = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        red_index = names.index("Red Team")
        expected_neighbor = names[red_index - 1] if red_index > 0 else names[1]
        tab.profile_list.setCurrentRow(red_index)
        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)

        tab._delete_profile()

        remaining = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        assert "Red Team" not in remaining
        assert tab.profile_list.currentItem() is not None
        assert tab.profile_list.currentItem().text() == expected_neighbor
        assert tab.status_label.text() == "Deleted profile: Red Team"
    finally:
        tab.close()


def test_import_profiles_failure_surfaces_warning_without_changing_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    tab = _make_tab(tmp_path, store=store)
    invalid_import = tmp_path / "invalid-profiles.json"
    invalid_import.write_text('{"profiles":"bad"}', encoding="utf-8")
    warnings: list[str] = []

    try:
        names = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        tab.profile_list.setCurrentRow(names.index("Prototype"))
        monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args, **kwargs: (str(invalid_import), "JSON Files (*.json)"))
        monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(str(args[2])) or QMessageBox.Ok)

        tab._import_profiles()

        assert warnings
        assert "could not import profiles" in warnings[0].lower()
        assert tab.profile_list.currentItem() is not None
        assert tab.profile_list.currentItem().text() == "Prototype"
        assert tab.status_label.text() == f"Import failed: {invalid_import}"
    finally:
        tab.close()


def test_delete_last_profile_surfaces_warning_and_keeps_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_all([GuiProfile(name="Only Profile")])
    tab = _make_tab(tmp_path, store=store)
    warnings: list[str] = []

    try:
        tab.profile_list.setCurrentRow(0)
        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
        monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(str(args[2])) or QMessageBox.Ok)

        tab._delete_profile()

        remaining = [tab.profile_list.item(idx).text() for idx in range(tab.profile_list.count())]
        assert remaining == ["Only Profile"]
        assert tab.profile_list.currentItem() is not None
        assert tab.profile_list.currentItem().text() == "Only Profile"
        assert tab.status_label.text() == "Failed to delete profile: Only Profile"
        assert warnings
        assert "could not delete 'Only Profile'" in warnings[0]
        assert "at least one profile" in warnings[0]
    finally:
        tab.close()
