from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from attackcastle.core.enums import TargetType
from attackcastle.core.models import RunData
from attackcastle.normalization.correlator import (
    collect_confirmed_web_targets,
    collect_sqlmap_targets,
    collect_tls_targets,
    collect_web_targets,
    collect_wordpress_targets,
)
from attackcastle.scope.domains import canonical_hostname, registrable_domain
from attackcastle.scope.expansion import collect_host_scan_targets, collect_resolved_host_scan_targets, is_ip_literal


def condition_always(_: RunData) -> tuple[bool, str]:
    return True, "always"


def has_domain_like_targets(run_data: RunData) -> tuple[bool, str]:
    allowed = {
        TargetType.DOMAIN,
        TargetType.WILDCARD_DOMAIN,
        TargetType.URL,
        TargetType.HOST_PORT,
    }
    matched = any(target.target_type in allowed for target in run_data.scope)
    return matched, "domain-like targets detected" if matched else "no domain-like targets"


def has_scannable_targets(run_data: RunData) -> tuple[bool, str]:
    matched = any(target.target_type != TargetType.ASN for target in run_data.scope)
    return matched, "scope contains scannable targets" if matched else "no non-ASN targets available"


def has_pingable_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(_pending_reachability_targets(run_data))
    return matched, "pingable targets detected" if matched else "no pingable targets available"


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_host_target(value: str) -> str:
    item = str(value or "").strip()
    if not item:
        return ""
    return item if _looks_like_ip(item) else item.lower()


def _signature(values: list[str]) -> str:
    normalized = sorted({str(item).strip() for item in values if str(item).strip()})
    return "|".join(normalized)


def _host_key(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = urlsplit(text).hostname or ""
    elif "/" in text or " " in text:
        return ""
    return text.strip().lower().rstrip(".")


def _filter_reachable(values: list[str], run_data: RunData) -> list[str]:
    checked = {_host_key(item) for item in run_data.facts.get("target_reachability.checked_targets", [])}
    unreachable = {_host_key(item) for item in run_data.facts.get("target_reachability.unreachable_targets", [])}
    reachable = {_host_key(item) for item in run_data.facts.get("target_reachability.reachable_targets", [])}
    checked.discard("")
    unreachable.discard("")
    reachable.discard("")
    if not checked:
        return values
    filtered: list[str] = []
    for value in values:
        key = _host_key(value)
        if key and key in checked and key in unreachable and key not in reachable:
            continue
        filtered.append(value)
    return filtered


def _subdomain_enum_targets(run_data: RunData) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for target in run_data.scope:
        host = canonical_hostname(target.host)
        root: str | None = None
        if target.target_type in {TargetType.DOMAIN, TargetType.WILDCARD_DOMAIN} and host:
            root = registrable_domain(host) or host
        elif target.target_type in {TargetType.URL, TargetType.HOST_PORT} and host and not is_ip_literal(host):
            root = registrable_domain(host) or host
        if root and target.value not in seen:
            seen.add(target.value)
            targets.append(target.value)
    return targets


def _frontier_completed_values(run_data: RunData, legacy_fact_key: str) -> list[str]:
    prefix = legacy_fact_key.rsplit(".", 1)[0]
    completed_key = f"{prefix}.completed_urls" if legacy_fact_key.endswith("_urls") else f"{prefix}.completed_targets"
    completed = run_data.facts.get(completed_key)
    if isinstance(completed, list):
        return [str(item).strip() for item in completed if str(item).strip()]
    legacy = run_data.facts.get(legacy_fact_key, [])
    return [str(item).strip() for item in legacy if str(item).strip()]


def _pending_host_signature(run_data: RunData) -> str:
    scanned = {
        _normalize_host_target(item)
        for item in _frontier_completed_values(run_data, "nmap.scanned_targets")
        if str(item).strip()
    }
    pending = [
        _normalize_host_target(item)
        for item in collect_resolved_host_scan_targets(run_data)
        if _normalize_host_target(item) and _normalize_host_target(item) not in scanned
    ]
    pending = _filter_reachable(pending, run_data)
    return _signature(pending)


def _pending_host_targets(run_data: RunData) -> list[str]:
    scanned = {
        _normalize_host_target(item)
        for item in _frontier_completed_values(run_data, "nmap.scanned_targets")
        if str(item).strip()
    }
    pending = [
        _normalize_host_target(item)
        for item in collect_resolved_host_scan_targets(run_data)
        if _normalize_host_target(item) and _normalize_host_target(item) not in scanned
    ]
    return _filter_reachable(pending, run_data)


def _pending_candidate_web_signature(run_data: RunData, fact_key: str) -> str:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, fact_key) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    pending = _filter_reachable(pending, run_data)
    return _signature(pending)


def _pending_candidate_web_targets(run_data: RunData, fact_key: str) -> list[str]:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, fact_key) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _filter_reachable(pending, run_data)


def _pending_confirmed_web_signature(run_data: RunData, fact_key: str) -> str:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, fact_key) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_confirmed_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    pending = _filter_reachable(pending, run_data)
    return _signature(pending)


def _pending_confirmed_web_targets(run_data: RunData, fact_key: str) -> list[str]:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, fact_key) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_confirmed_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _filter_reachable(pending, run_data)


def _pending_wordpress_signature(run_data: RunData) -> str:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, "wpscan.scanned_urls") if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_wordpress_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    pending = _filter_reachable(pending, run_data)
    return _signature(pending)


def _pending_wordpress_targets(run_data: RunData) -> list[str]:
    scanned = {str(item).strip() for item in _frontier_completed_values(run_data, "wpscan.scanned_urls") if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_wordpress_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _filter_reachable(pending, run_data)


def _pending_reachability_signature(run_data: RunData) -> str:
    return _signature(_pending_reachability_targets(run_data))


def _pending_reachability_targets(run_data: RunData) -> list[str]:
    checked = {_host_key(item) for item in run_data.facts.get("target_reachability.checked_targets", [])}
    targets: set[str] = set()
    for target in run_data.scope:
        if target.target_type == TargetType.ASN:
            continue
        key = _host_key(target.host or target.value)
        if key and key not in checked:
            targets.add(key)
    for candidate in collect_host_scan_targets(run_data):
        key = _host_key(candidate)
        if key and key not in checked:
            targets.add(key)
    return sorted(targets)


def has_network_scan_targets(run_data: RunData) -> tuple[bool, str]:
    ip_like_types = {TargetType.SINGLE_IP, TargetType.CIDR, TargetType.IP_RANGE}
    for target in run_data.scope:
        if target.target_type in ip_like_types:
            return True, "ip-like scope targets detected"
        if target.target_type == TargetType.HOST_PORT and target.host and _looks_like_ip(target.host):
            return True, "host:port ip target detected"
    if any(asset.ip for asset in run_data.assets):
        return True, "resolved host assets available for network scan"
    return False, "no IP targets available yet"


def has_service_scan_targets(run_data: RunData) -> tuple[bool, str]:
    matched = has_scannable_targets(run_data)[0]
    if matched:
        return True, "scannable targets available for nmap service discovery"
    return False, "no scannable targets available for nmap"


def has_web_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(collect_web_targets(run_data))
    return matched, "http/https services detected" if matched else "no web services detected"


def has_tls_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(collect_tls_targets(run_data))
    return matched, "tls-capable endpoints detected" if matched else "no tls targets detected"


def has_wordpress_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(collect_wordpress_targets(run_data))
    return matched, "wordpress targets detected" if matched else "no wordpress targets detected"


def has_sqlmap_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(collect_sqlmap_targets(run_data))
    return matched, "sqlmap candidate targets detected" if matched else "no sqlmap targets detected"


def has_replay_targets(run_data: RunData) -> tuple[bool, str]:
    replay_requests = getattr(run_data, "replay_requests", []) or []
    if replay_requests:
        return True, "replayable requests captured"
    matched = bool(collect_web_targets(run_data))
    return matched, "web targets available for request capture" if matched else "no replayable web targets detected"


def has_service_targets(run_data: RunData) -> tuple[bool, str]:
    matched = bool(run_data.services)
    return matched, "services detected for exposure checks" if matched else "no services detected"


def has_framework_targets(run_data: RunData) -> tuple[bool, str]:
    tokens = {"drupal", "joomla", "laravel", "next.js", "nextjs", "wordpress"}
    for technology in run_data.technologies:
        name = str(technology.name or "").lower()
        if any(token in name for token in tokens):
            return True, "framework or CMS technologies detected"
    for observation in run_data.observations:
        if observation.entity_type != "web_app":
            continue
        if not observation.key.startswith("tech.") or not observation.key.endswith(".detected"):
            continue
        if observation.value is not True:
            continue
        token = observation.key[len("tech.") : -len(".detected")].replace("_", ".").lower()
        if token in tokens:
            return True, "framework or CMS observations detected"
    return False, "no framework or CMS targets detected"


def has_enrichment_targets(run_data: RunData) -> tuple[bool, str]:
    if run_data.services or run_data.technologies:
        return True, "service or technology fingerprints available for enrichment"
    return False, "no enrichment inputs available"


CONDITION_MAP = {
    "always": condition_always,
    "has_domain_like_targets": has_domain_like_targets,
    "has_scannable_targets": has_scannable_targets,
    "has_pingable_targets": has_pingable_targets,
    "has_network_scan_targets": has_network_scan_targets,
    "has_service_scan_targets": has_service_scan_targets,
    "has_web_targets": has_web_targets,
    "has_tls_targets": has_tls_targets,
    "has_wordpress_targets": has_wordpress_targets,
    "has_sqlmap_targets": has_sqlmap_targets,
    "has_replay_targets": has_replay_targets,
    "has_service_targets": has_service_targets,
    "has_framework_targets": has_framework_targets,
    "has_enrichment_targets": has_enrichment_targets,
}


INPUT_SIGNATURE_MAP = {
    "check-target-reachability": _pending_reachability_signature,
    "run-subdomain-enum": lambda run_data: _signature(_subdomain_enum_targets(run_data)),
    "run-nmap": _pending_host_signature,
    "check-websites": lambda run_data: _pending_candidate_web_signature(run_data, "web_probe.scanned_urls"),
    "discover-web": lambda run_data: _pending_confirmed_web_signature(run_data, "web_discovery.scanned_urls"),
    "fingerprint-web": lambda run_data: _pending_confirmed_web_signature(run_data, "whatweb.scanned_urls"),
    "assess-web": lambda run_data: _pending_confirmed_web_signature(run_data, "nikto.scanned_urls"),
    "run-nuclei": lambda run_data: _pending_confirmed_web_signature(run_data, "nuclei.scanned_urls"),
    "run-wpscan": _pending_wordpress_signature,
}

INPUT_ITEMS_MAP = {
    "check-target-reachability": _pending_reachability_targets,
    "run-subdomain-enum": _subdomain_enum_targets,
    "run-nmap": _pending_host_targets,
    "check-websites": lambda run_data: _pending_candidate_web_targets(run_data, "web_probe.scanned_urls"),
    "discover-web": lambda run_data: _pending_confirmed_web_targets(run_data, "web_discovery.scanned_urls"),
    "fingerprint-web": lambda run_data: _pending_confirmed_web_targets(run_data, "whatweb.scanned_urls"),
    "assess-web": lambda run_data: _pending_confirmed_web_targets(run_data, "nikto.scanned_urls"),
    "run-nuclei": lambda run_data: _pending_confirmed_web_targets(run_data, "nuclei.scanned_urls"),
    "run-wpscan": _pending_wordpress_targets,
}
