from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _flatten_candidate_messages(value: Any) -> list[str]:
    messages: list[str] = []
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            messages.append(cleaned)
        return messages
    if isinstance(value, list):
        for item in value:
            messages.extend(_flatten_candidate_messages(item))
        return messages
    if isinstance(value, dict):
        for key in ("msg", "message", "description", "title", "id", "osvdb"):
            if key in value:
                messages.extend(_flatten_candidate_messages(value[key]))
        return messages
    return messages


def parse_nikto_json(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"issues": [], "raw": {}}
    if not path.exists():
        return result

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return result

    result["raw"] = payload
    issue_candidates: list[Any] = []
    if isinstance(payload, dict):
        for key in (
            "vulnerabilities",
            "findings",
            "issues",
            "alerts",
            "items",
        ):
            if key in payload:
                issue_candidates.append(payload[key])
        if not issue_candidates:
            issue_candidates.append(payload)
    elif isinstance(payload, list):
        issue_candidates.extend(payload)

    issues: list[str] = []
    for candidate in issue_candidates:
        issues.extend(_flatten_candidate_messages(candidate))
    result["issues"] = sorted({issue for issue in issues if issue})
    return result


def parse_nikto_text(stdout_text: str) -> list[str]:
    issues: list[str] = []
    for line in stdout_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("+"):
            issues.append(stripped.lstrip("+").strip())
    return issues

