from __future__ import annotations

import ipaddress
from pathlib import Path

from attackcastle.core.enums import TargetType
from attackcastle.core.errors import ValidationError
from attackcastle.core.models import ScanTarget
from attackcastle.scope.filters import estimate_target_host_count


def _ip_is_non_public(value: str) -> bool:
    ip_value = ipaddress.ip_address(value)
    return not ip_value.is_global


def _target_is_non_public(target: ScanTarget) -> bool:
    if target.target_type == TargetType.SINGLE_IP:
        return _ip_is_non_public(target.value)
    if target.target_type == TargetType.CIDR:
        network = ipaddress.ip_network(target.value, strict=False)
        return not network.is_global
    if target.target_type == TargetType.IP_RANGE:
        left, right = target.value.split("-", maxsplit=1)
        return _ip_is_non_public(left.strip()) or _ip_is_non_public(right.strip())
    if target.target_type == TargetType.HOST_PORT and target.host:
        try:
            return _ip_is_non_public(target.host)
        except ValueError:
            return False
    return False


def validate_targets(targets: list[ScanTarget], allow_private_scope: bool = True) -> None:
    if not targets:
        raise ValidationError("No valid target was provided.")
    for target in targets:
        if target.target_type == TargetType.UNKNOWN:
            raise ValidationError(f"Unsupported target format: '{target.raw}'")
        if not allow_private_scope and _target_is_non_public(target):
            raise ValidationError(
                f"Target '{target.raw}' resolves to non-public scope. "
                "Set scan.allow_private_scope=true only for explicitly authorized internal testing."
            )


def validate_scope_limits(
    targets: list[ScanTarget],
    max_hosts: int | None = None,
) -> None:
    if max_hosts is None:
        return
    estimated = sum(estimate_target_host_count(target) for target in targets)
    if estimated > max_hosts:
        raise ValidationError(
            f"Estimated host count {estimated} exceeds configured max hosts limit {max_hosts}."
        )


def ensure_output_directory(path_value: str) -> Path:
    output_path = Path(path_value).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    if not output_path.is_dir():
        raise ValidationError(f"Output path is not a directory: {output_path}")
    return output_path
