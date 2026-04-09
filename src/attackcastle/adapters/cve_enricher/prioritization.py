from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from attackcastle.proxy import open_url


def fetch_epss_score(cve_id: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> float | None:
    normalized = str(cve_id or "").strip().upper()
    if not normalized.startswith("CVE-"):
        return None
    query = urllib.parse.quote(normalized)
    url = f"https://api.first.org/data/v1/epss?cve={query}"
    request = urllib.request.Request(url, headers={"User-Agent": "AttackCastle/0.1"})
    try:
        with open_url(request, timeout=timeout_seconds, proxy_url=proxy_url) as response:  # noqa: S310
            payload = response.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError):
        return None
    except Exception:
        return None
    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(loaded, dict):
        return None
    data = loaded.get("data", [])
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict):
        return None
    try:
        return float(first.get("epss"))
    except (TypeError, ValueError):
        return None


def fetch_kev_set(kev_feed_url: str, timeout_seconds: int = 8, proxy_url: str | None = None) -> set[str]:
    url = str(kev_feed_url or "").strip()
    if not url:
        return set()
    request = urllib.request.Request(url, headers={"User-Agent": "AttackCastle/0.1"})
    try:
        with open_url(request, timeout=timeout_seconds, proxy_url=proxy_url) as response:  # noqa: S310
            payload = response.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError):
        return set()
    except Exception:
        return set()
    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError:
        return set()
    vulnerabilities = loaded.get("vulnerabilities", []) if isinstance(loaded, dict) else []
    if not isinstance(vulnerabilities, list):
        return set()
    kev_set: set[str] = set()
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            kev_set.add(cve_id.upper())
    return kev_set


def exploitability_hint(epss: float | None, kev: bool) -> tuple[str, str]:
    if kev:
        return "critical", "Known exploited vulnerability (KEV-listed). Prioritize immediate validation."
    if epss is None:
        return "medium", "No EPSS score available. Validate exploitability through manual analysis."
    if epss >= 0.7:
        return "high", "High EPSS probability. Validate attack path early."
    if epss >= 0.3:
        return "medium", "Moderate EPSS probability. Prioritize if exposed and reachable."
    return "low", "Lower EPSS probability. Keep in remediation queue with other context."


def prioritize_cves(cve_ids: list[str], epss_map: dict[str, float | None], kev_set: set[str]) -> list[dict[str, Any]]:
    prioritized: list[dict[str, Any]] = []
    for cve_id in cve_ids:
        normalized = str(cve_id or "").strip().upper()
        if not normalized.startswith("CVE-"):
            continue
        epss = epss_map.get(normalized)
        kev = normalized in kev_set
        priority, hint = exploitability_hint(epss, kev)
        prioritized.append(
            {
                "cve": normalized,
                "epss": epss,
                "kev": kev,
                "priority": priority,
                "exploitability_hint": hint,
            }
        )
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    prioritized.sort(
        key=lambda item: (
            priority_rank.get(str(item["priority"]), 99),
            -(float(item["epss"]) if item["epss"] is not None else -1.0),
            str(item["cve"]),
        )
    )
    return prioritized
