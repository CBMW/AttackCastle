from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlparse

from attackcastle.core.interfaces import AdapterContext


def normalize_url_key(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if not parsed.scheme or not host:
        return raw
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    return f"{parsed.scheme.lower()}://{netloc}{path}" + (f"?{parsed.query}" if parsed.query else "")


def normalized_task_inputs(context: AdapterContext) -> list[str]:
    inputs: list[str] = []
    seen: set[str] = set()
    for item in getattr(context, "task_inputs", []) or []:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        inputs.append(text)
    return inputs


def filter_url_targets_for_task_inputs(
    context: AdapterContext,
    targets: Iterable[dict[str, Any]],
    *,
    url_key: str = "url",
) -> list[dict[str, Any]]:
    rows = list(targets)
    inputs = normalized_task_inputs(context)
    if not inputs:
        return rows
    allowed = {normalize_url_key(item) for item in inputs if normalize_url_key(item)}
    if not allowed:
        return []
    return [
        row
        for row in rows
        if normalize_url_key(str(row.get(url_key) or "")) in allowed
    ]
