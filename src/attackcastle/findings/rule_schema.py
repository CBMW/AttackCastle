from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
DETECTION_LOGICS = ("any", "all")
TRIGGER_OPERATORS = (
    "output contains",
    "output does not contain",
    "output matches regex",
    "header exists",
    "header missing",
    "header equals",
    "status code equals",
    "status code in list",
    "exit code equals",
    "tool succeeded",
    "tool failed",
    "timeout occurred",
)
OPERATOR_SCOPES: dict[str, tuple[str, ...]] = {
    "output contains": ("stdout", "stderr", "combined_output"),
    "output does not contain": ("stdout", "stderr", "combined_output"),
    "output matches regex": ("stdout", "stderr", "combined_output"),
    "header exists": ("response_headers",),
    "header missing": ("response_headers",),
    "header equals": ("response_headers",),
    "status code equals": ("response_status",),
    "status code in list": ("response_status",),
    "exit code equals": ("tool_execution",),
    "tool succeeded": ("tool_execution",),
    "tool failed": ("tool_execution",),
    "timeout occurred": ("tool_execution",),
}


DETECTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["logic", "triggers"],
    "properties": {
        "logic": {"type": "string", "enum": list(DETECTION_LOGICS)},
        "triggers": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "tool", "operator", "scope"],
                "properties": {
                    "id": {"type": "string"},
                    "enabled": {"type": "boolean"},
                    "tool": {"type": "string"},
                    "operator": {"type": "string", "enum": list(TRIGGER_OPERATORS)},
                    "scope": {"type": "string"},
                    "value": {},
                },
            },
        },
    },
}


def default_finding_definition() -> dict[str, Any]:
    return {
        "id": "NEW_FINDING",
        "version": "1.0.0",
        "enabled": True,
        "title": "New Finding",
        "severity": "low",
        "root_cause": "",
        "category": "General",
        "description": "",
        "impact": "",
        "likelihood": "",
        "recommendations": [],
        "references": [],
        "tags": [],
        "detection": {"logic": "any", "triggers": []},
        "trigger": {
            "entity_type": "asset",
            "logic": "all",
            "conditions": [{"key": "entity.detected", "op": "exists"}],
        },
        "evidence_requirements": {"min_items": 0, "keys": []},
        "corroboration": {
            "min_observations": 1,
            "min_distinct_sources": 1,
            "min_confidence": 0.6,
            "required_assertions": [],
        },
        "plextrac": {},
    }


def normalize_definition(definition: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(definition)
    normalized["id"] = str(normalized.get("id") or "").strip()
    normalized["title"] = str(normalized.get("title") or normalized["id"] or "Untitled Finding")
    severity = str(normalized.get("severity") or "info").strip().lower()
    normalized["severity"] = severity if severity in SEVERITIES else "info"
    normalized["enabled"] = bool(normalized.get("enabled", True))
    for key in ("recommendations", "references", "tags"):
        value = normalized.get(key, [])
        if isinstance(value, str):
            normalized[key] = [line.strip() for line in value.splitlines() if line.strip()]
        elif isinstance(value, list):
            normalized[key] = [str(item) for item in value if str(item).strip()]
        else:
            normalized[key] = []
    detection = normalized.get("detection")
    if isinstance(detection, dict):
        detection["logic"] = str(detection.get("logic") or "any").lower()
        if detection["logic"] not in DETECTION_LOGICS:
            detection["logic"] = "any"
        triggers = detection.get("triggers", [])
        detection["triggers"] = [normalize_trigger(item) for item in triggers if isinstance(item, dict)]
        normalized["detection"] = detection
    return normalized


def normalize_trigger(trigger: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(trigger)
    normalized["id"] = str(normalized.get("id") or "").strip()
    normalized["tool"] = str(normalized.get("tool") or "").strip()
    operator = str(normalized.get("operator") or "").strip().lower()
    normalized["operator"] = operator
    scopes = OPERATOR_SCOPES.get(operator, ())
    scope = str(normalized.get("scope") or "").strip()
    normalized["scope"] = scope if scope in scopes else (scopes[0] if scopes else scope)
    normalized["enabled"] = bool(normalized.get("enabled", True))
    if operator == "status code in list":
        normalized["value"] = parse_int_list(normalized.get("value"))
    elif operator in {"status code equals", "exit code equals"}:
        try:
            normalized["value"] = int(normalized.get("value"))
        except (TypeError, ValueError):
            normalized["value"] = None
    return normalized


def parse_int_list(value: Any) -> list[int]:
    if isinstance(value, list):
        candidates = value
    else:
        candidates = str(value or "").replace(";", ",").split(",")
    parsed: list[int] = []
    for item in candidates:
        try:
            number = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if number not in parsed:
            parsed.append(number)
    return parsed


def validate_detection(definition: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    detection = definition.get("detection")
    if detection in (None, {}):
        return issues
    if not isinstance(detection, dict):
        return ["detection must be an object"]
    logic = str(detection.get("logic") or "").lower()
    if logic not in DETECTION_LOGICS:
        issues.append("detection.logic must be 'any' or 'all'")
    triggers = detection.get("triggers", [])
    if not isinstance(triggers, list):
        return [*issues, "detection.triggers must be a list"]
    seen_ids: set[str] = set()
    for index, trigger in enumerate(triggers, start=1):
        if not isinstance(trigger, dict):
            issues.append(f"trigger {index} must be an object")
            continue
        trigger_id = str(trigger.get("id") or "").strip()
        if not trigger_id:
            issues.append(f"trigger {index} is missing id")
        elif trigger_id in seen_ids:
            issues.append(f"duplicate trigger id: {trigger_id}")
        seen_ids.add(trigger_id)
        tool = str(trigger.get("tool") or "").strip()
        if not tool:
            issues.append(f"trigger {trigger_id or index} is missing tool")
        operator = str(trigger.get("operator") or "").strip().lower()
        if operator not in TRIGGER_OPERATORS:
            issues.append(f"trigger {trigger_id or index} has unsupported operator: {operator}")
            continue
        scope = str(trigger.get("scope") or "").strip()
        if scope not in OPERATOR_SCOPES[operator]:
            issues.append(f"trigger {trigger_id or index} has invalid scope '{scope}' for {operator}")
        if operator == "output matches regex":
            try:
                re.compile(str(trigger.get("value") or ""))
            except re.error as exc:
                issues.append(f"trigger {trigger_id or index} has invalid regex: {exc}")
    return issues

