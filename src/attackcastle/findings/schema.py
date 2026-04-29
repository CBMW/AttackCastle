from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

TEMPLATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "id",
        "version",
        "title",
        "severity",
        "category",
        "description",
        "impact",
        "likelihood",
        "recommendations",
        "references",
        "tags",
        "trigger",
        "evidence_requirements",
        "corroboration",
        "plextrac",
    ],
    "properties": {
        "id": {"type": "string"},
        "abstract": {"type": "boolean"},
        "enabled": {"type": "boolean"},
        "extends": {"type": "string"},
        "version": {"type": "string"},
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "root_cause": {"type": "string"},
        "category": {"type": "string"},
        "description": {"type": "string"},
        "impact": {"type": "string"},
        "likelihood": {"type": "string"},
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "references": {"type": "array", "items": {"type": "string"}},
        "tags": {"type": "array", "items": {"type": "string"}},
        "trigger": {
            "type": "object",
            "required": ["entity_type", "logic", "conditions"],
            "properties": {
                "entity_type": {"type": "string"},
                "logic": {"type": "string", "enum": ["all", "any"]},
                "conditions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["key", "op"],
                        "properties": {
                            "key": {"type": "string"},
                            "op": {"type": "string"},
                            "value": {},
                        },
                    },
                },
            },
        },
        "detection": {
            "type": "object",
            "properties": {
                "logic": {"type": "string", "enum": ["all", "any"]},
                "triggers": {"type": "array", "items": {"type": "object"}},
            },
        },
        "evidence_requirements": {
            "type": "object",
            "properties": {
                "min_items": {"type": "integer", "minimum": 0},
                "keys": {"type": "array", "items": {"type": "string"}},
            },
        },
        "corroboration": {
            "type": "object",
            "properties": {
                "min_observations": {"type": "integer", "minimum": 0},
                "min_distinct_sources": {"type": "integer", "minimum": 1},
                "min_confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "required_assertions": {"type": "array", "items": {"type": "string"}},
            },
        },
        "plextrac": {"type": "object"},
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        elif (
            key in merged
            and isinstance(merged[key], list)
            and isinstance(value, list)
            and key in {"tags", "recommendations", "references"}
        ):
            combined = list(merged[key])
            for item in value:
                if item not in combined:
                    combined.append(item)
            merged[key] = combined
        else:
            merged[key] = value
    return merged


def _load_raw_templates(template_dir: Path) -> dict[str, dict[str, Any]]:
    templates: dict[str, dict[str, Any]] = {}
    if not template_dir.exists():
        return templates
    for template_path in sorted(template_dir.glob("*.json")):
        try:
            with template_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if "id" not in data:
            continue
        templates[data["id"]] = data
    return templates


def _load_raw_templates_from_dirs(template_dirs: list[Path]) -> dict[str, dict[str, Any]]:
    templates: dict[str, dict[str, Any]] = {}
    for template_dir in template_dirs:
        templates.update(_load_raw_templates(template_dir))
    return templates


def _resolve_template(
    template_id: str,
    raw_templates: dict[str, dict[str, Any]],
    resolving: set[str],
) -> dict[str, Any]:
    if template_id not in raw_templates:
        raise KeyError(f"Template '{template_id}' not found")
    if template_id in resolving:
        raise ValueError(f"Circular template inheritance detected for '{template_id}'")
    resolving.add(template_id)
    current = dict(raw_templates[template_id])
    parent_id = current.get("extends")
    if parent_id:
        parent = _resolve_template(parent_id, raw_templates, resolving)
        merged = _deep_merge(parent, current)
        if "abstract" not in current:
            merged["abstract"] = False
    else:
        merged = current
    resolving.remove(template_id)
    merged.pop("extends", None)
    merged.setdefault("evidence_requirements", {"min_items": 0, "keys": []})
    merged.setdefault(
        "corroboration",
        {
            "min_observations": 1,
            "min_distinct_sources": 1,
            "min_confidence": 0.6,
            "required_assertions": [],
        },
    )
    return merged


def load_templates(template_dir: Path) -> list[dict[str, Any]]:
    raw_templates = _load_raw_templates(template_dir)
    return _resolve_templates(raw_templates)


def load_templates_from_dirs(template_dirs: list[Path]) -> list[dict[str, Any]]:
    raw_templates = _load_raw_templates_from_dirs(template_dirs)
    return _resolve_templates(raw_templates)


def _resolve_templates(raw_templates: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    for template_id in sorted(raw_templates.keys()):
        resolved.append(_resolve_template(template_id, raw_templates, set()))
    return resolved


def validate_template(template: dict[str, Any]) -> None:
    jsonschema.validate(instance=template, schema=TEMPLATE_SCHEMA)


def lint_templates(template_dir: Path) -> list[str]:
    issues: list[str] = []
    try:
        templates = load_templates(template_dir)
    except Exception as exc:  # noqa: BLE001
        return [str(exc)]
    seen_ids: set[str] = set()
    for template in templates:
        template_id = template.get("id", "<unknown>")
        if template_id in seen_ids:
            issues.append(f"Duplicate template id: {template_id}")
        seen_ids.add(template_id)
        try:
            validate_template(template)
        except Exception as exc:  # noqa: BLE001
            issues.append(f"{template_id}: {exc}")
    return issues
