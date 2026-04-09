from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _collect_vulnerability_titles(value: Any) -> list[str]:
    titles: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "vulnerabilities" and isinstance(item, list):
                for vuln in item:
                    if isinstance(vuln, dict):
                        title = vuln.get("title") or vuln.get("id")
                        if title:
                            titles.append(str(title))
            else:
                titles.extend(_collect_vulnerability_titles(item))
    elif isinstance(value, list):
        for item in value:
            titles.extend(_collect_vulnerability_titles(item))
    return titles


def parse_wpscan_json(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "wordpress_version": None,
        "vulnerability_titles": [],
        "interesting_findings": 0,
        "raw": {},
    }
    if not path.exists():
        return result

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return result

    result["raw"] = payload
    if not isinstance(payload, dict):
        return result

    version = payload.get("version")
    if isinstance(version, dict):
        number = version.get("number") or version.get("release_date")
        if number:
            result["wordpress_version"] = str(number)
    elif isinstance(version, str):
        result["wordpress_version"] = version

    titles = _collect_vulnerability_titles(payload)
    result["vulnerability_titles"] = sorted({title for title in titles if title})

    findings = payload.get("interesting_findings", [])
    if isinstance(findings, list):
        result["interesting_findings"] = len(findings)
    return result

