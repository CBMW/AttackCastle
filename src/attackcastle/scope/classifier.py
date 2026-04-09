from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from attackcastle.core.enums import TargetType
from attackcastle.core.models import ScanTarget, new_id

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
ASN_RE = re.compile(r"^AS(?P<num>\d{1,10})$", re.IGNORECASE)
TARGET_TYPE_ALIASES: dict[str, TargetType] = {
    "ip": TargetType.SINGLE_IP,
    "single_ip": TargetType.SINGLE_IP,
    "cidr": TargetType.CIDR,
    "ip_range": TargetType.IP_RANGE,
    "range": TargetType.IP_RANGE,
    "asn": TargetType.ASN,
    "domain": TargetType.DOMAIN,
    "wildcard": TargetType.WILDCARD_DOMAIN,
    "wildcard_domain": TargetType.WILDCARD_DOMAIN,
    "url": TargetType.URL,
    "host_port": TargetType.HOST_PORT,
    "host:port": TargetType.HOST_PORT,
}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    if "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_ip_range(value: str) -> bool:
    if "-" not in value:
        return False
    parts = value.split("-", maxsplit=1)
    if len(parts) != 2:
        return False
    left, right = parts[0].strip(), parts[1].strip()
    return _is_ip(left) and _is_ip(right)


def _is_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value))


def _normalize_asn(value: str) -> str | None:
    match = ASN_RE.match(value.strip())
    if not match:
        return None
    number = int(match.group("num"))
    if number <= 0:
        return None
    return f"AS{number}"


def _parse_host_port(value: str) -> tuple[str, int] | None:
    if value.startswith("[") and "]:" in value:
        host, port_part = value.split("]:", maxsplit=1)
        host = host.lstrip("[")
        if port_part.isdigit():
            return host, int(port_part)
        return None
    if value.count(":") == 1:
        host, port_part = value.rsplit(":", maxsplit=1)
        if host and port_part.isdigit():
            return host, int(port_part)
    return None


def coerce_target_type(value: str | TargetType | None) -> TargetType | None:
    if value is None:
        return None
    if isinstance(value, TargetType):
        return value
    normalized = value.strip().lower()
    if normalized in TARGET_TYPE_ALIASES:
        return TARGET_TYPE_ALIASES[normalized]
    try:
        return TargetType(normalized)
    except ValueError as exc:
        raise ValueError(f"Unsupported target type '{value}'.") from exc


def _build_forced_target(raw: str, forced_type: TargetType) -> ScanTarget:
    cleaned = raw.strip()
    if forced_type == TargetType.URL:
        parsed_url = urlparse(cleaned)
        if not (parsed_url.scheme and parsed_url.netloc):
            raise ValueError(f"Value '{raw}' is not a valid URL.")
        host = parsed_url.hostname
        if host and host.startswith("*."):
            host = host[2:]
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.URL,
            value=cleaned,
            host=host,
            port=parsed_url.port,
            scheme=parsed_url.scheme.lower(),
        )

    if forced_type == TargetType.WILDCARD_DOMAIN:
        candidate = cleaned[2:] if cleaned.startswith("*.") else cleaned
        if not _is_domain(candidate):
            raise ValueError(f"Value '{raw}' is not a valid wildcard domain.")
        normalized = candidate.lower()
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.WILDCARD_DOMAIN,
            value=f"*.{normalized}",
            host=normalized,
        )

    if forced_type == TargetType.DOMAIN:
        candidate = cleaned[2:] if cleaned.startswith("*.") else cleaned
        if not _is_domain(candidate):
            raise ValueError(f"Value '{raw}' is not a valid domain.")
        normalized = candidate.lower()
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.DOMAIN,
            value=normalized,
            host=normalized,
        )

    if forced_type == TargetType.SINGLE_IP:
        if not _is_ip(cleaned):
            raise ValueError(f"Value '{raw}' is not a valid IP address.")
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.SINGLE_IP,
            value=cleaned,
            host=cleaned,
        )

    if forced_type == TargetType.CIDR:
        if not _is_cidr(cleaned):
            raise ValueError(f"Value '{raw}' is not a valid CIDR.")
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.CIDR,
            value=cleaned,
        )

    if forced_type == TargetType.IP_RANGE:
        if not _is_ip_range(cleaned):
            raise ValueError(f"Value '{raw}' is not a valid IP range.")
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.IP_RANGE,
            value=cleaned,
        )

    if forced_type == TargetType.ASN:
        normalized_asn = _normalize_asn(cleaned)
        if normalized_asn is None:
            raise ValueError(f"Value '{raw}' is not a valid ASN.")
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.ASN,
            value=normalized_asn,
            host=None,
        )

    if forced_type == TargetType.HOST_PORT:
        host_port = _parse_host_port(cleaned)
        if host_port is None:
            raise ValueError(f"Value '{raw}' is not a valid host:port target.")
        host, port = host_port
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.HOST_PORT,
            value=cleaned,
            host=host,
            port=port,
        )

    if forced_type == TargetType.UNKNOWN:
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.UNKNOWN,
            value=cleaned,
        )

    raise ValueError(f"Forced target type '{forced_type.value}' is not supported.")


def classify_target(raw: str, forced_type: str | TargetType | None = None) -> ScanTarget:
    coerced_type = coerce_target_type(forced_type)
    if coerced_type is not None:
        return _build_forced_target(raw, coerced_type)

    cleaned = raw.strip()

    parsed_url = urlparse(cleaned)
    if parsed_url.scheme and parsed_url.netloc:
        host = parsed_url.hostname
        if host and host.startswith("*."):
            host = host[2:]
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.URL,
            value=cleaned,
            host=host,
            port=parsed_url.port,
            scheme=parsed_url.scheme.lower(),
        )

    if cleaned.startswith("*.") and _is_domain(cleaned[2:]):
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.WILDCARD_DOMAIN,
            value=cleaned.lower(),
            host=cleaned[2:].lower(),
        )

    if _is_cidr(cleaned):
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.CIDR,
            value=cleaned,
        )

    if _is_ip_range(cleaned):
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.IP_RANGE,
            value=cleaned,
        )

    if _is_ip(cleaned):
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.SINGLE_IP,
            value=cleaned,
            host=cleaned,
        )

    normalized_asn = _normalize_asn(cleaned)
    if normalized_asn:
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.ASN,
            value=normalized_asn,
            host=None,
        )

    host_port = _parse_host_port(cleaned)
    if host_port is not None:
        host, port = host_port
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.HOST_PORT,
            value=cleaned,
            host=host,
            port=port,
        )

    if _is_domain(cleaned):
        return ScanTarget(
            target_id=new_id("target"),
            raw=raw,
            target_type=TargetType.DOMAIN,
            value=cleaned.lower(),
            host=cleaned.lower(),
        )

    return ScanTarget(
        target_id=new_id("target"),
        raw=raw,
        target_type=TargetType.UNKNOWN,
        value=cleaned,
    )
