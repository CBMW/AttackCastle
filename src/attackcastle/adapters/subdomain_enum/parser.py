from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from attackcastle.proxy import open_url

HOST_RE = re.compile(r"^(?:\*\.)?([a-z0-9][a-z0-9\-.]{0,252})$", re.IGNORECASE)


def _normalize_host(value: str, root_domain: str) -> str | None:
    cleaned = (value or "").strip().lower()
    if not cleaned:
        return None
    cleaned = cleaned.replace("\n", "").replace("\r", "")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    match = HOST_RE.match(cleaned)
    if not match:
        return None
    normalized = match.group(1).rstrip(".")
    if normalized == root_domain:
        return normalized
    if normalized.endswith("." + root_domain):
        return normalized
    return None


def query_crtsh(root_domain: str, timeout_seconds: int = 15, proxy_url: str | None = None) -> list[str]:
    query = urllib.parse.quote(f"%.{root_domain}")
    url = f"https://crt.sh/?q={query}&output=json"
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
    if not isinstance(loaded, list):
        return []

    candidates: set[str] = set()
    for item in loaded:
        if not isinstance(item, dict):
            continue
        for key in ("name_value", "common_name"):
            raw_name = item.get(key)
            if not isinstance(raw_name, str):
                continue
            for token in raw_name.splitlines():
                normalized = _normalize_host(token, root_domain)
                if normalized:
                    candidates.add(normalized)
    return sorted(candidates)


def query_certspotter(root_domain: str, timeout_seconds: int = 15, proxy_url: str | None = None) -> list[str]:
    query = urllib.parse.urlencode(
        {
            "domain": root_domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
    )
    url = f"https://api.certspotter.com/v1/issuances?{query}"
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
    if not isinstance(loaded, list):
        return []

    candidates: set[str] = set()
    for item in loaded:
        if not isinstance(item, dict):
            continue
        dns_names = item.get("dns_names", [])
        if not isinstance(dns_names, list):
            continue
        for raw_name in dns_names:
            if not isinstance(raw_name, str):
                continue
            normalized = _normalize_host(raw_name, root_domain)
            if normalized:
                candidates.add(normalized)
    return sorted(candidates)


def query_securitytrails(
    root_domain: str,
    api_key: str,
    timeout_seconds: int = 15,
    proxy_url: str | None = None,
) -> list[str]:
    token = (api_key or "").strip()
    if not token:
        return []
    encoded_domain = urllib.parse.quote(root_domain)
    url = f"https://api.securitytrails.com/v1/domain/{encoded_domain}/subdomains"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AttackCastle/0.1",
            "APIKEY": token,
            "Accept": "application/json",
        },
    )
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
    if not isinstance(loaded, dict):
        return []
    raw_subdomains = loaded.get("subdomains", [])
    if not isinstance(raw_subdomains, list):
        return []

    candidates: set[str] = set()
    for label in raw_subdomains:
        if not isinstance(label, str):
            continue
        normalized = _normalize_host(f"{label}.{root_domain}", root_domain)
        if normalized:
            candidates.add(normalized)
    return sorted(candidates)
