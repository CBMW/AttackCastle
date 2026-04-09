from __future__ import annotations

from pathlib import Path
from typing import Any

from attackcastle.core.models import to_serializable


def emit_runtime_event(context: Any, event: str, payload: dict[str, Any]) -> None:
    emitter = getattr(context, "event_emitter", None)
    if not callable(emitter):
        return
    emitter(event, to_serializable(payload))


def emit_entity_event(
    context: Any,
    entity_type: str,
    entity: Any,
    *,
    action: str = "upsert",
    source: str | None = None,
) -> None:
    emit_runtime_event(
        context,
        "entity.upserted",
        {
            "entity_type": entity_type,
            "action": action,
            "source": source,
            "entity": to_serializable(entity),
        },
    )


def emit_artifact_event(
    context: Any,
    *,
    artifact_path: str | Path,
    kind: str,
    source_tool: str,
    caption: str | None = None,
) -> None:
    emit_runtime_event(
        context,
        "artifact.available",
        {
            "artifact_path": str(artifact_path),
            "kind": kind,
            "source_tool": source_tool,
            "caption": caption or "",
        },
    )
