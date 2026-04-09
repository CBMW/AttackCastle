from __future__ import annotations

import json

from attackcastle.gui.extensions import (
    DEFAULT_THEME_EXTENSION_ID,
    DEFAULT_THEME_EXTENSION_NAME,
    ExtensionValidationError,
    LEGACY_DEFAULT_THEME_EXTENSION_ID,
    build_starter_command_hook_manifest,
)
from attackcastle.gui.extensions_store import GuiExtensionStore


def test_extension_store_bootstraps_default_theme(tmp_path) -> None:
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")

    records = store.discover()

    assert any(record.extension_id == DEFAULT_THEME_EXTENSION_ID for record in records)
    active = store.get_active_theme_manifest()
    assert active is not None
    assert active.extension_id == DEFAULT_THEME_EXTENSION_ID
    assert active.name == DEFAULT_THEME_EXTENSION_NAME
    assert active.description == "Modern graphite AttackCastle theme with premium blue-violet accents and cleaner contrast."
    assert active.theme is not None
    assert active.theme.tokens["palette"]["accent_primary"] == "#78a6ff"


def test_extension_store_migrates_legacy_default_theme_state(tmp_path) -> None:
    state_path = tmp_path / "extensions_state.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "active_theme_id": LEGACY_DEFAULT_THEME_EXTENSION_ID,
                "enabled_extensions": {LEGACY_DEFAULT_THEME_EXTENSION_ID: True},
                "last_opened_extension_id": LEGACY_DEFAULT_THEME_EXTENSION_ID,
            }
        ),
        encoding="utf-8",
    )

    store = GuiExtensionStore(tmp_path / "extensions", state_path)
    state = store.load_state()

    assert state.active_theme_id == DEFAULT_THEME_EXTENSION_ID
    assert state.last_opened_extension_id == DEFAULT_THEME_EXTENSION_ID
    assert state.enabled_extensions[DEFAULT_THEME_EXTENSION_ID] is True


def test_extension_store_rejects_invalid_manifest_save(tmp_path) -> None:
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")

    try:
        store.save_raw_text('{"schema_version":"extensions/v1","id":"broken"}')
    except ExtensionValidationError as exc:
        assert "name" in str(exc) or "required" in str(exc)
    else:
        raise AssertionError("Expected invalid manifest save to fail.")


def test_extension_store_rejects_duplicate_ids(tmp_path) -> None:
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    manifest = build_starter_command_hook_manifest("Sample Extension")
    store.save_manifest(manifest)
    duplicate = build_starter_command_hook_manifest("Different Name")
    duplicate.extension_id = manifest.extension_id

    try:
        store.save_manifest(duplicate)
    except ValueError as exc:
        assert manifest.extension_id in str(exc)
    else:
        raise AssertionError("Expected duplicate id save to fail.")


def test_extension_store_persists_enabled_and_last_opened_state(tmp_path) -> None:
    store = GuiExtensionStore(tmp_path / "extensions", tmp_path / "extensions_state.json")
    manifest = build_starter_command_hook_manifest("Selectable Extension")
    store.save_manifest(manifest)

    store.set_extension_enabled(manifest.extension_id, False)
    store.set_last_opened_extension(manifest.extension_id)

    payload = json.loads((tmp_path / "extensions_state.json").read_text(encoding="utf-8"))
    assert payload["enabled_extensions"][manifest.extension_id] is False
    assert payload["last_opened_extension_id"] == manifest.extension_id
