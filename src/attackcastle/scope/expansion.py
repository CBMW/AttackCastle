from __future__ import annotations

import ipaddress

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


def collect_host_scan_targets(run_data: RunData) -> list[str]:
    targets: set[str] = set()
    for target in run_data.scope:
        normalized = normalize_target_for_host_scan(target)
        if normalized:
            targets.add(normalized)
    if targets:
        return sorted(targets)

    fallback: set[str] = set()
    for asset in run_data.assets:
        if asset.ip:
            fallback.add(asset.ip)
        elif asset.name:
            fallback.add(asset.name)
    return sorted(fallback)


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
