from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from attackcastle.tools.schema import normalize_tool_definition, tool_filename, validate_tool_definition


def builtin_tools_definition_dir() -> Path:
    return Path(__file__).resolve().parent / "definitions"


def default_global_tools_dir() -> Path:
    return Path.home() / ".attackcastle" / "tools" / "global"


def default_profile_tools_dir(profile_slug: str) -> Path:
    return Path.home() / ".attackcastle" / "tools" / "profiles" / profile_slug


def default_workspace_tools_dir(workspace_id: str) -> Path:
    return Path.home() / ".attackcastle" / "workspaces" / workspace_id / "tools"


def default_tool_logs_dir() -> Path:
    return Path.home() / ".attackcastle" / "tools" / "logs"


def profile_slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip().lower())
    return cleaned.strip("._-") or "default"


@dataclass(slots=True)
class ToolLibraryResult:
    definitions: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


class ToolLibraryStore:
    def __init__(
        self,
        *,
        builtin_dir: Path | None = None,
        global_dir: Path | None = None,
        profile_name_provider: Callable[[], str] | None = None,
        workspace_id_provider: Callable[[], str] | None = None,
        workspace_home_provider: Callable[[], str] | None = None,
    ) -> None:
        self.builtin_dir = builtin_dir or builtin_tools_definition_dir()
        self.global_dir = global_dir or default_global_tools_dir()
        self.profile_name_provider = profile_name_provider or (lambda: "")
        self.workspace_id_provider = workspace_id_provider or (lambda: "")
        self.workspace_home_provider = workspace_home_provider or (lambda: "")

    def profile_dir(self) -> Path:
        return default_profile_tools_dir(profile_slug(self.profile_name_provider()))

    def workspace_dir(self) -> Path:
        workspace_home = str(self.workspace_home_provider() or "").strip()
        if workspace_home:
            return Path(workspace_home).expanduser().resolve() / ".attackcastle" / "tools"
        workspace_id = str(self.workspace_id_provider() or "").strip()
        return default_workspace_tools_dir(workspace_id or "__no_workspace__")

    def scope_dir(self, scope: str) -> Path:
        if scope == "workspace":
            return self.workspace_dir()
        if scope == "profile":
            return self.profile_dir()
        return self.global_dir

    def _load_dir(self, directory: Path, scope: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
        definitions: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        if not directory.exists():
            return definitions, warnings
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{path.name}: invalid JSON: {exc}")
                continue
            if not isinstance(payload, dict):
                warnings.append(f"{path.name}: definition must be a JSON object")
                continue
            normalized = normalize_tool_definition(payload)
            issues = validate_tool_definition(normalized)
            if issues:
                warnings.append(f"{path.name}: {'; '.join(issues)}")
                continue
            normalized["save_scope"] = scope if scope != "builtin" else normalized.get("save_scope", "global")
            metadata = dict(normalized.get("metadata", {}))
            metadata["source"] = scope
            normalized["metadata"] = metadata
            definitions[normalized["id"]] = normalized
        return definitions, warnings

    def load_definitions(self) -> ToolLibraryResult:
        merged: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        for scope, directory in (
            ("builtin", self.builtin_dir),
            ("global", self.global_dir),
            ("profile", self.profile_dir()),
            ("workspace", self.workspace_dir()),
        ):
            rows, scope_warnings = self._load_dir(directory, scope)
            warnings.extend(scope_warnings)
            for tool_id, definition in rows.items():
                if tool_id in merged:
                    base = dict(merged[tool_id])
                    base.update(definition)
                    definition = normalize_tool_definition(base)
                merged[tool_id] = definition
        return ToolLibraryResult(
            definitions=sorted(merged.values(), key=lambda item: (str(item.get("category")), str(item.get("display_name")).lower())),
            warnings=warnings,
        )

    def definition_path(self, definition_id: str, scope: str = "global") -> Path:
        return self.scope_dir(scope) / tool_filename(definition_id)

    def save_definition(self, definition: dict[str, Any], scope: str | None = None) -> Path:
        normalized = normalize_tool_definition(definition)
        issues = validate_tool_definition(normalized)
        if issues:
            raise ValueError("; ".join(issues))
        target_scope = scope or str(normalized.get("save_scope") or "global")
        if target_scope not in {"global", "profile", "workspace"}:
            target_scope = "global"
        normalized["save_scope"] = target_scope
        target_dir = self.scope_dir(target_scope)
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / tool_filename(str(normalized["id"]))
        path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def delete_definition(self, definition_id: str, scope: str | None = None) -> bool:
        scopes = [scope] if scope else ["workspace", "profile", "global"]
        deleted = False
        for candidate_scope in scopes:
            if candidate_scope not in {"workspace", "profile", "global"}:
                continue
            path = self.definition_path(definition_id, candidate_scope)
            if path.exists():
                path.unlink()
                deleted = True
        return deleted

    def duplicate_definition(self, definition: dict[str, Any], scope: str = "global") -> dict[str, Any]:
        base = normalize_tool_definition(definition)
        root_id = str(base["id"]).strip() or "tool"
        candidate = f"{root_id}-copy"
        existing = {str(item.get("id")) for item in self.load_definitions().definitions}
        counter = 2
        while candidate in existing:
            candidate = f"{root_id}-copy-{counter}"
            counter += 1
        base["id"] = candidate
        base["display_name"] = f"{base['display_name']} Copy"
        base["save_scope"] = scope
        self.save_definition(base, scope)
        return base

    def is_user_definition(self, definition_id: str) -> bool:
        return any(self.definition_path(definition_id, scope).exists() for scope in ("global", "profile", "workspace"))
