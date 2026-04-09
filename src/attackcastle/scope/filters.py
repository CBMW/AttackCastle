from __future__ import annotations

import ipaddress
from pathlib import Path

from attackcastle.core.enums import TargetType
from attackcastle.core.models import ScanTarget


def load_targets_from_scope_file(path_value: str) -> str:
    path = Path(path_value).expanduser().resolve()
    return path.read_text(encoding="utf-8")


def apply_allow_deny(
    targets: list[ScanTarget],
    allow_tokens: list[str] | None,
    deny_tokens: list[str] | None,
) -> list[ScanTarget]:
    filtered = targets
    allow_tokens = [token.strip().lower() for token in (allow_tokens or []) if token.strip()]
    deny_tokens = [token.strip().lower() for token in (deny_tokens or []) if token.strip()]

    if allow_tokens:
        filtered = [
            target
            for target in filtered
            if any(token in target.value.lower() or token in target.raw.lower() for token in allow_tokens)
        ]
    if deny_tokens:
        filtered = [
            target
            for target in filtered
            if not any(token in target.value.lower() or token in target.raw.lower() for token in deny_tokens)
        ]
    return filtered


def estimate_target_host_count(target: ScanTarget) -> int:
    if target.target_type in {TargetType.SINGLE_IP, TargetType.DOMAIN, TargetType.URL, TargetType.HOST_PORT}:
        return 1
    if target.target_type == TargetType.WILDCARD_DOMAIN:
        return 50
    if target.target_type == TargetType.CIDR:
        try:
            network = ipaddress.ip_network(target.value, strict=False)
            return int(network.num_addresses)
        except ValueError:
            return 0
    if target.target_type == TargetType.IP_RANGE:
        left, right = target.value.split("-", maxsplit=1)
        left_ip = int(ipaddress.ip_address(left.strip()))
        right_ip = int(ipaddress.ip_address(right.strip()))
        return max(0, right_ip - left_ip + 1)
    if target.target_type == TargetType.ASN:
        # Conservative estimate before ASN expansion happens in scope compiler.
        return 256
    return 0
