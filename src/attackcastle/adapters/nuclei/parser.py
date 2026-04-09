from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_nuclei_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(loaded, dict):
            continue
        info = loaded.get("info", {}) if isinstance(loaded.get("info"), dict) else {}
        rows.append(
            {
                "template_id": str(loaded.get("template-id") or loaded.get("templateID") or ""),
                "name": str(info.get("name") or loaded.get("matcher-name") or "Nuclei finding"),
                "severity": str(info.get("severity") or "info").lower(),
                "matched_at": str(loaded.get("matched-at") or loaded.get("host") or ""),
                "type": str(loaded.get("type") or ""),
            }
        )
    return rows
