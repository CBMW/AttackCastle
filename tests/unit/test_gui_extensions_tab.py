from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QToolButton

from attackcastle.gui.extensions import build_starter_command_hook_manifest
from attackcastle.gui.extensions_store import GuiExtensionStore
from attackcastle.gui.extensions_tab import ExtensionsTab


def _make_tab(tmp_path: Path) -> tuple[ExtensionsTab, list[str], list[str]]:
    app = QApplication.instance() or QApplication([])
    _ = app
    opened_paths: list[str] = []
    applied_themes: list[str] = []
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    store.save_manifest(build_starter_command_hook_manifest("Status Rail Test"))
    tab = ExtensionsTab(
        store=store,
        on_theme_applied=lambda manifest: applied_themes.append(manifest.extension_id),
        open_path=lambda path: opened_paths.append(path),
    )
    tab.resize(1500, 900)
    tab.show()
    app.processEvents()
    return tab, opened_paths, applied_themes


def test_extensions_tab_moves_actions_into_compact_top_toolbar(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _opened_paths, _applied_themes = _make_tab(tmp_path)

    try:
        tab.sync_responsive_mode(tab.width())
        app.processEvents()

        assert tab.splitter.orientation() == Qt.Horizontal
        assert tab.splitter.count() == 2
        assert tab.splitter.widget(0) is tab.library_panel
        assert tab.action_panel.parentWidget() is tab
        assert not tab.splitter.isAncestorOf(tab.action_panel)
        assert tab.action_panel.height() < tab.library_panel.height()
        assert "Manifest Status" not in [label.text() for label in tab.findChildren(QLabel)]

        for button in (
            tab.new_button,
            tab.duplicate_button,
            tab.save_button,
            tab.reload_button,
            tab.toggle_enabled_button,
            tab.apply_theme_button,
            tab.open_folder_button,
        ):
            assert isinstance(button, QToolButton)
            assert button.toolButtonStyle() == Qt.ToolButtonIconOnly
    finally:
        tab.close()


def test_extensions_tab_stacks_library_and_editor_at_narrow_width(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _opened_paths, _applied_themes = _make_tab(tmp_path)

    try:
        tab.resize(980, 760)
        tab.sync_responsive_mode(tab.width())
        app.processEvents()

        assert tab.splitter.orientation() == Qt.Vertical
        assert tab.splitter.count() == 2
        assert tab.action_panel.parentWidget() is tab
        assert tab.splitter.widget(0) is tab.library_panel
    finally:
        tab.close()


def test_extensions_tab_selection_updates_editor_status_and_action_tooltips(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    _ = app
    tab, _opened_paths, _applied_themes = _make_tab(tmp_path)

    try:
        names = [tab.extension_list.item(index).text() for index in range(tab.extension_list.count())]
        target_index = next(index for index, name in enumerate(names) if "Status Rail Test" in name)
        tab.extension_list.setCurrentRow(target_index)
        app.processEvents()

        assert "Status Rail Test" in tab.editor_status_label.text()
        assert "Manifest is valid and ready." in tab.editor_status_label.text()
        assert tab.toggle_enabled_button.text() == "Disable"
        assert "Disable the selected extension" in tab.toggle_enabled_button.toolTip()
        assert str(tmp_path / "extensions") in tab.open_folder_button.toolTip()
    finally:
        tab.close()
