from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

SCHEMA_VERSION = "1.0"
SAVE_SCOPES = ("global", "profile", "workspace")
PLATFORMS = ("linux", "windows", "darwin")
CATEGORIES = (
    "network",
    "dns",
    "web",
    "tls",
    "cms",
    "vulnerability",
    "content",
    "utility",
    "internal",
)
REQUIRED_INPUTS = ("host", "url", "ip", "file", "wordlist")
OUTPUT_TYPES = ("raw", "headers", "json", "xml", "grep", "regex")
FIELD_TYPES = ("string", "number", "boolean", "list", "object")


def default_tool_definition() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "id": "new-tool",
        "display_name": "New Tool",
        "description": "",
        "category": "utility",
        "platforms": list(PLATFORMS),
        "enabled": True,
        "install_path": "",
        "executable_name": "",
        "detection_command": "",
        "install_command": "",
        "version_command": "",
        "command_template": "",
        "default_arguments": [],
        "timeout_seconds": 300,
        "required_inputs": [],
        "output": {"type": "raw", "primary_artifact": "stdout", "parser": "", "regex": ""},
        "produced_fields": [],
        "save_scope": "global",
        "metadata": {"source": "user", "capabilities": [], "task_keys": []},
    }


def _string_list(value: Any, *, allowed: tuple[str, ...] | None = None) -> list[str]:
    if isinstance(value, str):
        candidates = [item.strip() for item in value.replace(";", ",").split(",")]
    elif isinstance(value, list):
        candidates = [str(item).strip() for item in value]
    else:
        candidates = []
    result: list[str] = []
    for item in candidates:
        if not item:
            continue
        normalized = item.lower() if allowed is not None else item
        if allowed is not None and normalized not in allowed:
            continue
        if normalized not in result:
            result.append(normalized)
    return result


def tool_filename(tool_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(tool_id or "").strip())
    cleaned = cleaned.strip("._-") or "tool"
    return f"{cleaned}.json"


def normalize_tool_definition(definition: dict[str, Any]) -> dict[str, Any]:
    normalized = default_tool_definition()
    normalized.update(deepcopy(definition))
    normalized["schema_version"] = str(normalized.get("schema_version") or SCHEMA_VERSION)
    normalized["id"] = str(normalized.get("id") or "").strip()
    normalized["display_name"] = str(normalized.get("display_name") or normalized["id"] or "Untitled Tool").strip()
    normalized["description"] = str(normalized.get("description") or "")
    category = str(normalized.get("category") or "utility").strip().lower()
    normalized["category"] = category if category in CATEGORIES else "utility"
    platforms = _string_list(normalized.get("platforms"), allowed=PLATFORMS)
    normalized["platforms"] = platforms or list(PLATFORMS)
    normalized["enabled"] = bool(normalized.get("enabled", True))
    for key in (
        "install_path",
        "executable_name",
        "detection_command",
        "install_command",
        "version_command",
        "command_template",
    ):
        normalized[key] = str(normalized.get(key) or "").strip()
    try:
        normalized["timeout_seconds"] = max(0, int(normalized.get("timeout_seconds") or 0))
    except (TypeError, ValueError):
        normalized["timeout_seconds"] = 300
    if normalized["timeout_seconds"] == 0:
        normalized["timeout_seconds"] = 300
    normalized["default_arguments"] = _string_list(normalized.get("default_arguments"))
    normalized["required_inputs"] = _string_list(normalized.get("required_inputs"), allowed=REQUIRED_INPUTS)
    output = normalized.get("output") if isinstance(normalized.get("output"), dict) else {}
    output_type = str(output.get("type") or "raw").strip().lower()
    normalized["output"] = {
        "type": output_type if output_type in OUTPUT_TYPES else "raw",
        "primary_artifact": str(output.get("primary_artifact") or "stdout").strip() or "stdout",
        "parser": str(output.get("parser") or "").strip(),
        "regex": str(output.get("regex") or ""),
    }
    fields: list[dict[str, str]] = []
    for row in normalized.get("produced_fields", []) if isinstance(normalized.get("produced_fields"), list) else []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        field_type = str(row.get("type") or "string").strip().lower()
        fields.append(
            {
                "name": name,
                "type": field_type if field_type in FIELD_TYPES else "string",
                "description": str(row.get("description") or ""),
            }
        )
    normalized["produced_fields"] = fields
    save_scope = str(normalized.get("save_scope") or "global").strip().lower()
    normalized["save_scope"] = save_scope if save_scope in SAVE_SCOPES else "global"
    metadata = normalized.get("metadata") if isinstance(normalized.get("metadata"), dict) else {}
    normalized["metadata"] = {
        "source": str(metadata.get("source") or "user"),
        "capabilities": _string_list(metadata.get("capabilities")),
        "task_keys": _string_list(metadata.get("task_keys")),
    }
    return normalized


def validate_tool_definition(definition: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    normalized = normalize_tool_definition(definition)
    if not normalized["id"]:
        issues.append("tool id is required")
    if not re.match(r"^[A-Za-z0-9_.-]+$", normalized["id"]):
        issues.append("tool id may only contain letters, numbers, dot, underscore, and dash")
    if not normalized["display_name"]:
        issues.append("display name is required")
    if not normalized["executable_name"] and not normalized["install_path"] and not normalized["detection_command"]:
        issues.append("executable name, install path, or detection command is required")
    if normalized["output"]["type"] == "regex":
        pattern = normalized["output"].get("regex", "")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                issues.append(f"output regex is invalid: {exc}")
    return issues
