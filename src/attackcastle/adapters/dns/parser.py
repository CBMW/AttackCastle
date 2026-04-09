from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request

from attackcastle.proxy import open_url

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    ips = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_value = sockaddr[0]
        if ip_value not in ips:
            ips.append(ip_value)
    return ips


def _doh_request(host: str, record_type: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> list[str]:
    query = urllib.parse.urlencode({"name": host, "type": record_type})
    request = urllib.request.Request(
        f"{DOH_ENDPOINT}?{query}",
        headers={"accept": "application/dns-json", "user-agent": "AttackCastle/0.1"},
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
    answers = loaded.get("Answer", []) if isinstance(loaded, dict) else []
    if not isinstance(answers, list):
        return []
    results: list[str] = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        data = answer.get("data")
        if isinstance(data, str) and data not in results:
            results.append(data)
    return results


def resolve_txt(host: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> list[str]:
    return [item.strip().strip('"') for item in _doh_request(host, "TXT", timeout_seconds=timeout_seconds, proxy_url=proxy_url)]


def resolve_mx(host: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> list[str]:
    return _doh_request(host, "MX", timeout_seconds=timeout_seconds, proxy_url=proxy_url)


def resolve_ns(host: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> list[str]:
    return _doh_request(host, "NS", timeout_seconds=timeout_seconds, proxy_url=proxy_url)


def resolve_cname(host: str, timeout_seconds: int = 6, proxy_url: str | None = None) -> list[str]:
    return _doh_request(host, "CNAME", timeout_seconds=timeout_seconds, proxy_url=proxy_url)
