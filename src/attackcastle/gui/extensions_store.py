from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackcastle.gui.extensions import (
    DEFAULT_THEME_EXTENSION_ID,
    ExtensionManifest,
    ExtensionRecord,
    ExtensionValidationError,
    LEGACY_DEFAULT_THEME_EXTENSION_ID,
    build_default_theme_manifest,
    build_starter_command_hook_manifest,
    build_starter_theme_manifest,
    default_extensions_root,
    default_extensions_state_path,
    extension_folder_name,
    parse_extension_text,
)

EXTENSION_STATE_VERSION = 1


@dataclass(slots=True)
class ExtensionStateStore:
    active_theme_id: str = DEFAULT_THEME_EXTENSION_ID
    enabled_extensions: dict[str, bool] = field(default_factory=dict)
    last_opened_extension_id: str = DEFAULT_THEME_EXTENSION_ID

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": EXTENSION_STATE_VERSION,
            "active_theme_id": self.active_theme_id,
            "enabled_extensions": dict(self.enabled_extensions),
            "last_opened_extension_id": self.last_opened_extension_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExtensionStateStore":
        enabled = payload.get("enabled_extensions", {})
        return cls(
            active_theme_id=str(payload.get("active_theme_id") or DEFAULT_THEME_EXTENSION_ID),
            enabled_extensions={str(key): bool(value) for key, value in enabled.items()}
            if isinstance(enabled, dict)
            else {},
            last_opened_extension_id=str(payload.get("last_opened_extension_id") or DEFAULT_THEME_EXTENSION_ID),
        )


class GuiExtensionStore:
    def __init__(self, root_path: Path | None = None, state_path: Path | None = None) -> None:
        self.root_path = root_path or default_extensions_root()
        self.state_path = state_path or default_extensions_state_path()
        self.root_path.mkdir(parents=True, exist_ok=True)
        self.ensure_bootstrapped()

    def ensure_bootstrapped(self) -> None:
        default_manifest = build_default_theme_manifest()
        default_manifest_path = self.root_path / extension_folder_name(default_manifest) / "extension.json"
        if not default_manifest_path.exists():
            self.save_manifest(default_manifest)
        state = self.load_state()
        state.enabled_extensions.setdefault(DEFAULT_THEME_EXTENSION_ID, True)
        if not state.active_theme_id or state.active_theme_id == LEGACY_DEFAULT_THEME_EXTENSION_ID:
            state.active_theme_id = DEFAULT_THEME_EXTENSION_ID
        if not state.last_opened_extension_id or state.last_opened_extension_id == LEGACY_DEFAULT_THEME_EXTENSION_ID:
            state.last_opened_extension_id = DEFAULT_THEME_EXTENSION_ID
        self.save_state(state)

    def load_state(self) -> ExtensionStateStore:
        if not self.state_path.exists():
            return ExtensionStateStore()
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return ExtensionStateStore()
        if not isinstance(payload, dict):
            return ExtensionStateStore()
        return ExtensionStateStore.from_dict(payload)

    def save_state(self, state: ExtensionStateStore) -> Path:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return self.state_path

    def discover(self) -> list[ExtensionRecord]:
        state = self.load_state()
        records: list[ExtensionRecord] = []
        for extension_dir in sorted(
            [path for path in self.root_path.iterdir() if path.is_dir()],
            key=lambda item: item.name.lower(),
        ):
            manifest_path = extension_dir / "extension.json"
            raw_text = ""
            manifest = None
            error = ""
            if manifest_path.exists():
                try:
                    raw_text = manifest_path.read_text(encoding="utf-8")
                except OSError as exc:
                    error = str(exc)
                else:
                    try:
                        manifest = parse_extension_text(raw_text)
                    except ExtensionValidationError as exc:
                        error = str(exc)
            else:
                error = "Missing extension.json manifest."
            extension_id = manifest.extension_id if manifest is not None else extension_dir.name
            records.append(
                ExtensionRecord(
                    directory=extension_dir,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    raw_text=raw_text,
                    load_error=error,
                    enabled=state.enabled_extensions.get(extension_id, True),
                    active_theme=state.active_theme_id == extension_id,
                )
            )
        duplicate_counts: dict[str, int] = {}
        for record in records:
            duplicate_counts[record.extension_id] = duplicate_counts.get(record.extension_id, 0) + 1
        for record in records:
            if duplicate_counts.get(record.extension_id, 0) > 1:
                record.load_error = f"Duplicate extension id detected: {record.extension_id}"
                record.manifest = None
        records.sort(key=lambda item: (not item.active_theme, item.display_name.lower()))
        return records

    def list_command_hook_extensions(self) -> list[ExtensionRecord]:
        return [
            item
            for item in self.discover()
            if item.is_valid and item.enabled and item.manifest is not None and item.manifest.is_command_hook
        ]

    def get_record(self, extension_id: str) -> ExtensionRecord | None:
        for record in self.discover():
            if record.extension_id == extension_id:
                return record
        return None

    def get_active_theme_record(self) -> ExtensionRecord | None:
        state = self.load_state()
        record = self.get_record(state.active_theme_id)
        if record is not None and record.is_valid and record.manifest is not None and record.manifest.is_theme:
            return record
        return self.get_record(DEFAULT_THEME_EXTENSION_ID)

    def get_active_theme_manifest(self) -> ExtensionManifest | None:
        record = self.get_active_theme_record()
        return record.manifest if record is not None else None

    def set_last_opened_extension(self, extension_id: str) -> Path:
        state = self.load_state()
        state.last_opened_extension_id = extension_id
        return self.save_state(state)

    def set_extension_enabled(self, extension_id: str, enabled: bool) -> Path:
        state = self.load_state()
        state.enabled_extensions[extension_id] = bool(enabled)
        return self.save_state(state)

    def set_active_theme(self, extension_id: str) -> Path:
        record = self.get_record(extension_id)
        if record is None or not record.is_valid or record.manifest is None or not record.manifest.is_theme:
            raise ValueError(f"Extension '{extension_id}' is not a valid theme.")
        state = self.load_state()
        state.active_theme_id = extension_id
        state.last_opened_extension_id = extension_id
        return self.save_state(state)

    def load_raw_text(self, extension_id: str) -> str:
        record = self.get_record(extension_id)
        if record is None:
            raise FileNotFoundError(extension_id)
        if record.manifest_path.exists():
            return record.manifest_path.read_text(encoding="utf-8")
        return record.raw_text

    def save_raw_text(self, text: str, *, preferred_directory_name: str | None = None) -> ExtensionManifest:
        manifest = parse_extension_text(text)
        return self.save_manifest(manifest, raw_text=text, preferred_directory_name=preferred_directory_name)

    def save_manifest(
        self,
        manifest: ExtensionManifest,
        *,
        raw_text: str | None = None,
        preferred_directory_name: str | None = None,
    ) -> ExtensionManifest:
        directory_name = preferred_directory_name or extension_folder_name(manifest)
        existing_records = [record for record in self.discover() if record.extension_id == manifest.extension_id]
        if preferred_directory_name is None and existing_records:
            raise ValueError(f"Duplicate extension id: {manifest.extension_id}")
        for existing in existing_records:
            if existing.directory.name != directory_name:
                raise ValueError(f"Duplicate extension id: {manifest.extension_id}")
        manifest_dir = self.root_path / directory_name
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = manifest_dir / "extension.json"
        payload = raw_text
        if payload is None:
            payload = json.dumps(manifest.to_dict(), indent=2, sort_keys=True)
        manifest_path.write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
        state = self.load_state()
        state.enabled_extensions.setdefault(manifest.extension_id, True)
        state.last_opened_extension_id = manifest.extension_id
        self.save_state(state)
        return manifest

    def create_theme_extension(self, name: str = "New Theme Extension") -> ExtensionManifest:
        manifest = build_starter_theme_manifest(name)
        self.save_manifest(manifest)
        return manifest

    def create_command_hook_extension(self, name: str = "New Command Hook Extension") -> ExtensionManifest:
        manifest = build_starter_command_hook_manifest(name)
        self.save_manifest(manifest)
        return manifest

    def duplicate_extension(self, extension_id: str) -> ExtensionManifest:
        record = self.get_record(extension_id)
        if record is None or record.manifest is None:
            raise FileNotFoundError(extension_id)
        cloned = ExtensionManifest.from_dict(record.manifest.to_dict())
        cloned.extension_id = f"{cloned.extension_id}-copy"
        cloned.name = f"{cloned.name} Copy"
        cloned.version = "1.0.0"
        self.save_manifest(cloned)
        return cloned
