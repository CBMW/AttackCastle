from __future__ import annotations

import hashlib
import json
from datetime import timezone
from pathlib import Path
from typing import Any

from attackcastle.core.models import now_utc, to_serializable


def _hash_event(timestamp: str, event_type: str, payload: dict[str, Any], previous_hash: str) -> str:
    material = json.dumps(
        {
            "timestamp": timestamp,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _tail_event_hash(audit_file: Path) -> str:
    if not audit_file.exists():
        return "GENESIS"
    try:
        lines = audit_file.read_text(encoding="utf-8").splitlines()
    except Exception:
        return "GENESIS"
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            loaded = json.loads(stripped)
        except Exception:
            continue
        if isinstance(loaded, dict):
            value = loaded.get("event_hash")
            if isinstance(value, str) and value:
                return value
    return "GENESIS"


class AuditLogger:
    def __init__(self, audit_file: Path, mirror_event_file: Path | None = None) -> None:
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        self.mirror_event_file = mirror_event_file
        if self.mirror_event_file:
            self.mirror_event_file.parent.mkdir(parents=True, exist_ok=True)
        self._previous_hash = _tail_event_hash(self.audit_file)

    def write(self, event_type: str, payload: dict[str, Any]) -> None:
        timestamp = now_utc().astimezone(timezone.utc).isoformat()
        event_hash = _hash_event(timestamp, event_type, payload, self._previous_hash)
        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": self._previous_hash,
            "event_hash": event_hash,
        }
        serialized = json.dumps(to_serializable(event))
        with self.audit_file.open("a", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\n")
        if self.mirror_event_file:
            with self.mirror_event_file.open("a", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.write("\n")
        self._previous_hash = event_hash


def verify_audit_chain(audit_file: Path) -> dict[str, Any]:
    if not audit_file.exists():
        return {"valid": True, "event_count": 0, "errors": [], "format": "missing"}
    errors: list[str] = []
    previous_hash = "GENESIS"
    event_count = 0
    hashed_events = 0
    unhashed_events = 0
    loaded_events: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in enumerate(audit_file.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        event_count += 1
        try:
            loaded = json.loads(stripped)
        except Exception:
            errors.append(f"line {line_number}: invalid JSON")
            continue
        if not isinstance(loaded, dict):
            errors.append(f"line {line_number}: event must be an object")
            continue
        has_hash_fields = "previous_hash" in loaded or "event_hash" in loaded
        if has_hash_fields:
            hashed_events += 1
        else:
            unhashed_events += 1
        loaded_events.append((line_number, loaded))

    if errors:
        return {"valid": False, "event_count": event_count, "errors": errors, "format": "invalid"}
    if not loaded_events:
        return {"valid": True, "event_count": 0, "errors": [], "format": "missing"}
    if hashed_events == 0:
        return {"valid": True, "event_count": event_count, "errors": [], "format": "legacy_unhashed"}
    if unhashed_events > 0:
        return {
            "valid": False,
            "event_count": event_count,
            "errors": ["audit log mixed hashed and unhashed events"],
            "format": "invalid",
        }

    for line_number, loaded in loaded_events:
        timestamp = str(loaded.get("timestamp", ""))
        event_type = str(loaded.get("event_type", ""))
        payload = loaded.get("payload", {})
        recorded_previous = str(loaded.get("previous_hash", ""))
        recorded_hash = str(loaded.get("event_hash", ""))
        if recorded_previous != previous_hash:
            errors.append(f"line {line_number}: previous hash mismatch")
        if not isinstance(payload, dict):
            payload = {}
        expected_hash = _hash_event(timestamp, event_type, payload, recorded_previous)
        if recorded_hash != expected_hash:
            errors.append(f"line {line_number}: event hash mismatch")
        previous_hash = recorded_hash or previous_hash
    return {
        "valid": len(errors) == 0,
        "event_count": event_count,
        "errors": errors,
        "format": "hashed",
    }
