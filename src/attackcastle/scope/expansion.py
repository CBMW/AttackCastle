from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from attackcastle.core.enums import TargetType
from attackcastle.core.models import RunData, ScanTarget


def is_ip_literal(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_target_for_host_scan(target: ScanTarget) -> str | None:
    if target.target_type == TargetType.ASN:
        return None
    if target.target_type == TargetType.URL:
        return target.host
    if target.target_type == TargetType.HOST_PORT:
        return target.host
    if target.target_type == TargetType.WILDCARD_DOMAIN:
        # Scanners cannot resolve wildcard tokens directly.
        return target.host
    return target.value


def normalize_host_scan_value(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    candidate = text
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    elif "/" in candidate or " " in candidate:
        return None
    candidate = candidate.strip().lower().rstrip(".")
    if not candidate:
        return None
    return candidate


def collect_host_scan_targets(run_data: RunData) -> list[str]:
    targets: set[str] = set()
    for target in run_data.scope:
        normalized = normalize_host_scan_value(normalize_target_for_host_scan(target))
        if normalized:
            targets.add(normalized)
    for asset in run_data.assets:
        for candidate in (asset.ip, asset.name, *list(asset.aliases)):
            normalized = normalize_host_scan_value(candidate)
            if normalized:
                targets.add(normalized)
    discovered_hosts = run_data.facts.get("subdomain_enum.discovered_hosts", [])
    if isinstance(discovered_hosts, list):
        for candidate in discovered_hosts:
            normalized = normalize_host_scan_value(str(candidate or ""))
            if normalized:
                targets.add(normalized)
    return sorted(targets)


def collect_resolved_host_scan_targets(run_data: RunData) -> list[str]:
    targets: set[str] = set()
    resolved_names: set[str] = set()

    for asset in run_data.assets:
        resolved_ips = {
            normalize_host_scan_value(asset.ip),
            *(normalize_host_scan_value(item) for item in list(getattr(asset, "resolved_ips", []))),
        }
        resolved_ips = {item for item in resolved_ips if item and is_ip_literal(item)}
        if not resolved_ips:
            continue
        for candidate in (asset.name, *list(asset.aliases)):
            normalized = normalize_host_scan_value(candidate)
            if normalized:
                resolved_names.add(normalized)
        targets.update(resolved_ips)

    for target in run_data.scope:
        normalized = normalize_host_scan_value(normalize_target_for_host_scan(target))
        if not normalized:
            continue
        if is_ip_literal(normalized) or normalized in resolved_names:
            targets.add(normalized)

    discovered_hosts = run_data.facts.get("subdomain_enum.discovered_hosts", [])
    if isinstance(discovered_hosts, list):
        for candidate in discovered_hosts:
            normalized = normalize_host_scan_value(str(candidate or ""))
            if normalized and normalized in resolved_names:
                targets.add(normalized)

    return sorted(targets)


def collect_network_targets(run_data: RunData) -> list[str]:
    targets: set[str] = set()
    for target in run_data.scope:
        if target.target_type in {TargetType.SINGLE_IP, TargetType.CIDR, TargetType.IP_RANGE}:
            targets.add(target.value)
            continue
        if target.target_type == TargetType.HOST_PORT and target.host and is_ip_literal(target.host):
            targets.add(target.host)

    for asset in run_data.assets:
        if asset.ip and is_ip_literal(asset.ip):
            targets.add(asset.ip)

    return sorted(targets)
