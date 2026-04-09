from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from attackcastle.proxy import open_url


def fetch_cve_candidates(
    keyword: str,
    timeout_seconds: int = 8,
    max_items: int = 10,
    proxy_url: str | None = None,
) -> list[str]:
    term = (keyword or "").strip()
    if not term:
        return []
    encoded = urllib.parse.quote(term)
    url = f"https://cve.circl.lu/api/search/{encoded}"
    request = urllib.request.Request(url, headers={"User-Agent": "AttackCastle/0.1"})
    try:
        with open_url(request, timeout=timeout_seconds, proxy_url=proxy_url) as response:  # noqa: S310
            payload = response.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError):
        return []
    except Exception:
        return []
    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError:
        return []

    candidates: list[str] = []
    if isinstance(loaded, dict):
        results = loaded.get("results")
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                cve_id = item.get("id") or item.get("cve")
                if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                    candidates.append(cve_id.upper())
    elif isinstance(loaded, list):
        for item in loaded:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("id") or item.get("cve")
            if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                candidates.append(cve_id.upper())

    unique: list[str] = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique[: max(1, int(max_items))]
