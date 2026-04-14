from __future__ import annotations

import pytest
from attackcastle.gui.extensions import DEFAULT_THEME_TOKENS, ExtensionValidationError, build_starter_theme_manifest, build_theme_stylesheet
from attackcastle.gui.extensions_store import GuiExtensionStore


def test_build_theme_stylesheet_uses_theme_token_overrides() -> None:
    stylesheet = build_theme_stylesheet(
        tokens={"palette": {"window_bg": "#010203", "accent_primary": "#112233"}},
        qss_append="QLabel#themeProbe { color: #abcdef; }",
    )

    assert "#010203" in stylesheet
    assert "#112233" in stylesheet
    assert "QLabel#themeProbe { color: #abcdef; }" in stylesheet


def test_default_theme_uses_compact_density_and_clearer_panel_contrast() -> None:
    stylesheet = build_theme_stylesheet()

    assert DEFAULT_THEME_TOKENS["palette"]["window_bg"] == "#05070b"
    assert DEFAULT_THEME_TOKENS["gradients"]["panel"]["start"] == "#1a2330"
    assert DEFAULT_THEME_TOKENS["radii"]["panel"] == "8px"
    assert "QWidget#appRoot" in stylesheet
    assert "qlineargradient" in stylesheet
    assert "padding: 6px 10px;" in stylesheet
    assert "margin: 8px 1px;" in stylesheet
    assert "margin: 1px 8px;" in stylesheet


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
