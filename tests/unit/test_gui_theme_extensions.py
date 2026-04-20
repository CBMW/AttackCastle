from __future__ import annotations

import pytest
from attackcastle.gui.extensions import (
    DEFAULT_THEME_TOKENS,
    ExtensionValidationError,
    build_asset_graph_stylesheet,
    build_starter_theme_manifest,
    build_theme_stylesheet,
)
from attackcastle.gui.extensions_store import GuiExtensionStore


def test_build_theme_stylesheet_uses_theme_token_overrides() -> None:
    stylesheet = build_theme_stylesheet(
        tokens={
            "palette": {
                "window_bg": "#010203",
                "accent_primary": "#112233",
                "accent_border": "#445566",
                "scanner_start_hover_bg": "rgba(1, 2, 3, 0.4)",
                "splitter_handle": "rgba(4, 5, 6, 0.7)",
            }
        },
        qss_append="QLabel#themeProbe { color: #abcdef; }",
    )

    assert "#010203" in stylesheet
    assert "#112233" in stylesheet
    assert "border-bottom-color: #445566;" in stylesheet
    assert "background: rgba(1, 2, 3, 0.4);" in stylesheet
    assert "background: rgba(4, 5, 6, 0.7);" not in stylesheet
    assert "QLabel#themeProbe { color: #abcdef; }" in stylesheet


def test_asset_graph_stylesheet_uses_theme_token_overrides() -> None:
    stylesheet = build_asset_graph_stylesheet(
        {"palette": {"graph_bg": "#101010", "graph_text": "#eeeeee", "graph_line": "#444444"}}
    )

    assert "--graph-bg: #101010;" in stylesheet
    assert "--graph-text: #eeeeee;" in stylesheet
    assert "--graph-line: #444444;" in stylesheet


def test_default_theme_uses_neutral_compact_density_and_tab_roles() -> None:
    stylesheet = build_theme_stylesheet()

    assert DEFAULT_THEME_TOKENS["palette"]["window_bg"] == "#060606"
    assert DEFAULT_THEME_TOKENS["palette"]["accent_primary"] == "#e3e3e3"
    assert DEFAULT_THEME_TOKENS["palette"]["accent_border"] == "#d0d0d0"
    assert DEFAULT_THEME_TOKENS["gradients"]["panel"]["start"] == "#1b1b1b"
    assert DEFAULT_THEME_TOKENS["radii"]["panel"] == "3px"
    assert DEFAULT_THEME_TOKENS["radii"]["surface"] == "3px"
    assert DEFAULT_THEME_TOKENS["radii"]["input"] == "3px"
    assert DEFAULT_THEME_TOKENS["radii"]["button"] == "3px"
    assert DEFAULT_THEME_TOKENS["radii"]["badge"] == "4px"
    assert DEFAULT_THEME_TOKENS["spacing"]["button_padding"] == "5px 9px"
    assert "#73a2ff" not in DEFAULT_THEME_TOKENS["palette"].values()
    assert "#78a6ff" not in DEFAULT_THEME_TOKENS["palette"].values()
    assert "#4e84ff" not in DEFAULT_THEME_TOKENS["palette"].values()
    assert "#68d1ff" not in DEFAULT_THEME_TOKENS["palette"].values()
    assert "QWidget {\n        background: transparent;" in stylesheet
    assert "QWidget#appRoot" in stylesheet
    assert "qlineargradient" in stylesheet
    assert "padding: 5px 9px;" in stylesheet
    assert "QTabBar#masterTabBar::tab" in stylesheet
    assert "QTabBar#groupTabBar::tab" in stylesheet
    assert "QTabBar#inspectorTabBar::tab" in stylesheet
    assert "border-bottom: 2px solid transparent;" in stylesheet
    assert "QTabBar#masterTabBar::tab:selected" in stylesheet
    assert "border-bottom-color: #d0d0d0;" in stylesheet
    assert "border-radius: 0;" in stylesheet
    assert "QSplitter::handle:horizontal:hover { background: transparent; }" in stylesheet
    assert "QSplitter::handle:vertical:pressed { background: transparent; }" in stylesheet
    assert "border-radius: 999px" not in stylesheet
    assert "border-radius: 22px" not in stylesheet
    assert "margin: 4px 1px;" in stylesheet
    assert "margin: 1px 4px;" in stylesheet


def test_default_splitter_handles_are_slim() -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QSplitter

    from attackcastle.gui.common import apply_responsive_splitter

    app = QApplication.instance() or QApplication([])
    _ = app
    splitter = apply_responsive_splitter(QSplitter(Qt.Horizontal), (1, 1))

    assert splitter.handleWidth() == 3


def test_invalid_theme_save_does_not_replace_last_good_active_theme(tmp_path) -> None:
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    theme = build_starter_theme_manifest("Ocean Theme")
    theme.theme.tokens["palette"]["window_bg"] = "#03131f"
    store.save_manifest(theme)
    store.set_active_theme(theme.extension_id)

    invalid_payload = """{
  "schema_version": "extensions/v1",
  "id": "ocean-theme",
  "version": "1.0.1",
  "capabilities": ["theme"],
  "theme": {}
}"""

    try:
        store.save_raw_text(invalid_payload, preferred_directory_name="ocean-theme")
    except ExtensionValidationError:
        pass
    else:
        raise AssertionError("Expected invalid theme payload to fail validation.")

    active = store.get_active_theme_manifest()
    assert active is not None
    assert active.extension_id == theme.extension_id
    assert active.theme is not None
    assert active.theme.tokens["palette"]["window_bg"] == "#03131f"
