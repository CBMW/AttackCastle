from __future__ import annotations

from typing import Any

import jsonschema

VIEW_MODEL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["metadata", "summary", "sections", "severity_counts", "service_distribution"],
    "properties": {
        "metadata": {"type": "object"},
        "summary": {"type": "object"},
        "sections": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "title", "template", "context"],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "template": {"type": "string"},
                    "context": {"type": "object"},
                },
            },
        },
        "severity_counts": {"type": "object"},
        "service_distribution": {"type": "array"},
    },
}


def validate_view_model(view_model: dict[str, Any]) -> None:
    jsonschema.validate(instance=view_model, schema=VIEW_MODEL_SCHEMA)

