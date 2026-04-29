from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from attackcastle.core.models import RunData


@dataclass(slots=True)
class HostProbeContext:
    target: str
    original_hostname: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    probe_mode: str = "raw_ip"

    @property
    def is_hostname_asset(self) -> bool:
        return bool(self.original_hostname)

    @property
    def primary_resolved_ip(self) -> str | None:
        return self.resolved_ips[0] if self.resolved_ips else None

    def metadata(self, *, protocol: str | None = None, port: int | None = None) -> dict[str, Any]:
        return {
            "original_hostname": self.original_hostname,
            "resolved_ip": self.primary_resolved_ip,
            "resolved_ips": list(self.resolved_ips),
            "protocol": protocol,
            "port": port,
            "probe_mode": self.probe_mode,
            "is_hostname_asset": self.is_hostname_asset,
        }


def is_ip_literal(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def normalize_hostname(value: str | None) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    return host if host and not is_ip_literal(host) else ""


def _asset_hostname(asset: Any) -> str:
    for candidate in (getattr(asset, "name", None), *list(getattr(asset, "aliases", []))):
        hostname = normalize_hostname(candidate)
        if hostname:
            return hostname
    return ""


def hostname_by_resolved_ip(run_data: RunData) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for asset in run_data.assets:
        hostname = _asset_hostname(asset)
        if not hostname:
            continue
        for candidate in (getattr(asset, "ip", None), *list(getattr(asset, "resolved_ips", []))):
            ip_value = str(candidate or "").strip()
            if ip_value and is_ip_literal(ip_value):
                mapping.setdefault(ip_value, hostname)
    return mapping


def resolved_ips_for_hostname(run_data: RunData, hostname: str | None) -> list[str]:
    normalized = normalize_hostname(hostname)
    if not normalized:
        return []
    ips: list[str] = []
    seen: set[str] = set()
    for asset in run_data.assets:
        candidates = {
            normalize_hostname(getattr(asset, "name", None)),
            *(normalize_hostname(alias) for alias in list(getattr(asset, "aliases", []))),
        }
        if normalized not in candidates:
            continue
        for ip_candidate in (getattr(asset, "ip", None), *list(getattr(asset, "resolved_ips", []))):
            ip_value = str(ip_candidate or "").strip()
            if ip_value and is_ip_literal(ip_value) and ip_value not in seen:
                seen.add(ip_value)
                ips.append(ip_value)
    return ips


def host_probe_context(run_data: RunData, target: str) -> HostProbeContext:
    raw = str(target or "").strip().lower().rstrip(".")
    if not raw:
        return HostProbeContext(target=raw, probe_mode="unknown")
    if is_ip_literal(raw):
        hostname = hostname_by_resolved_ip(run_data).get(raw)
        if hostname:
            return HostProbeContext(
                target=hostname,
                original_hostname=hostname,
                resolved_ips=[raw],
                probe_mode="hostname_first",
            )
        return HostProbeContext(target=raw, probe_mode="raw_ip")
    return HostProbeContext(
        target=raw,
        original_hostname=raw,
        resolved_ips=resolved_ips_for_hostname(run_data, raw),
        probe_mode="hostname_first",
    )


def url_probe_context(run_data: RunData, url: str) -> HostProbeContext:
    parsed = urlparse(str(url or "").strip())
    host = parsed.hostname or ""
    return host_probe_context(run_data, host)


def prefer_hostname_url(run_data: RunData, url: str) -> tuple[str, HostProbeContext]:
    parsed = urlparse(str(url or "").strip())
    host = parsed.hostname or ""
    context = host_probe_context(run_data, host)
    if not parsed.hostname or not context.is_hostname_asset or context.target == parsed.hostname:
        return url, context
    netloc = context.target
    if parsed.port is not None:
        netloc = f"{context.target}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl(), context


def curl_resolve_args(hostname: str, port: int, ip: str | None) -> list[str]:
    if not hostname or not ip:
        return []
    return ["--resolve", f"{hostname}:{port}:{ip}"]
