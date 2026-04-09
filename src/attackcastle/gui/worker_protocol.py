from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class WorkerEvent:
    event: str
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps({"event": self.event, "payload": self.payload}, sort_keys=True)

    @classmethod
    def from_line(cls, line: str) -> "WorkerEvent | None":
        text = line.strip()
        if not text:
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        event = payload.get("event")
        body = payload.get("payload", {})
        if not isinstance(event, str) or not isinstance(body, dict):
            return None
        return cls(event=event, payload=body)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_event(event: str, **payload: Any) -> str:
    return WorkerEvent(event=event, payload=payload).to_json()
