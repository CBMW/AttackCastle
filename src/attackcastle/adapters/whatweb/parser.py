from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PLUGIN_TOKEN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_ .+\-/]+?)(?:\[(?P<version>[^\]]+)\])?(?:,|$)"
)
FRAMEWORK_TOKENS = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "laravel": "laravel",
    "next.js": "nextjs",
    "nextjs": "nextjs",
}


def _extract_version(value: Any) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, list):
        for item in value:
            version = _extract_version(item)
            if version:
                return version
        return None
    if isinstance(value, dict):
        if "version" in value:
            return _extract_version(value.get("version"))
        if "string" in value:
            return _extract_version(value.get("string"))
    return None


def _iter_json_entries(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        loaded = json.loads(stripped)
    except json.JSONDecodeError:
        loaded = None

    if isinstance(loaded, list):
        return [item for item in loaded if isinstance(item, dict)]
    if isinstance(loaded, dict):
        return [loaded]

    entries: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        candidate = line.strip().rstrip(",")
        if not candidate:
            continue
        try:
            loaded_line = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded_line, dict):
            entries.append(loaded_line)
    return entries


def parse_whatweb_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries = _iter_json_entries(path.read_text(encoding="utf-8", errors="ignore"))
    parsed: list[dict[str, Any]] = []
    for entry in entries:
        url = str(entry.get("target") or entry.get("url") or "").strip()
        plugins = entry.get("plugins", {})
        if not isinstance(plugins, dict):
            plugins = {}

        technologies: list[tuple[str, str | None, float]] = []
        wordpress_detected = False
        wordpress_version: str | None = None
        framework_detections: list[tuple[str, str | None]] = []
        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_name, str):
                continue
            version = _extract_version(plugin_data)
            technologies.append((plugin_name, version, 0.85))
            lowered = plugin_name.lower()
            if "wordpress" in lowered:
                wordpress_detected = True
                wordpress_version = wordpress_version or version
            for token, normalized in FRAMEWORK_TOKENS.items():
                if token in lowered:
                    pair = (normalized, version)
                    if pair not in framework_detections:
                        framework_detections.append(pair)

        parsed.append(
            {
                "url": url,
                "technologies": technologies,
                "wordpress_detected": wordpress_detected,
                "wordpress_version": wordpress_version,
                "framework_detections": framework_detections,
            }
        )
    return parsed


def parse_whatweb_text(line: str) -> dict[str, Any]:
    cleaned = line.strip()
    if not cleaned:
        return {
            "url": "",
            "technologies": [],
            "wordpress_detected": False,
            "wordpress_version": None,
        }
    pieces = cleaned.split(" ", maxsplit=1)
    url = pieces[0]
    tail = pieces[1] if len(pieces) > 1 else ""

    technologies: list[tuple[str, str | None, float]] = []
    wordpress_detected = False
    wordpress_version: str | None = None
    framework_detections: list[tuple[str, str | None]] = []
    for match in PLUGIN_TOKEN_RE.finditer(tail):
        name = (match.group("name") or "").strip().strip("[]")
        if not name or name.startswith("["):
            continue
        version = (match.group("version") or "").strip() or None
        technologies.append((name, version, 0.7))
        lowered = name.lower()
        if "wordpress" in lowered:
            wordpress_detected = True
            wordpress_version = wordpress_version or version
        for token, normalized in FRAMEWORK_TOKENS.items():
            if token in lowered:
                pair = (normalized, version)
                if pair not in framework_detections:
                    framework_detections.append(pair)

    return {
        "url": url,
        "technologies": technologies,
        "wordpress_detected": wordpress_detected,
        "wordpress_version": wordpress_version,
        "framework_detections": framework_detections,
    }
