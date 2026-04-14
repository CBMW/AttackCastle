from __future__ import annotations

import ipaddress

from attackcastle.core.enums import TargetType
from attackcastle.core.models import RunData
from attackcastle.normalization.correlator import (
    collect_confirmed_web_targets,
    collect_sqlmap_targets,
    collect_tls_targets,
    collect_web_targets,
    collect_wordpress_targets,
)
from attackcastle.scope.expansion import collect_host_scan_targets, collect_resolved_host_scan_targets


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


def _pending_host_signature(run_data: RunData) -> str:
    scanned = {
        _normalize_host_target(item)
        for item in run_data.facts.get("nmap.scanned_targets", [])
        if str(item).strip()
    }
    pending = [
        _normalize_host_target(item)
        for item in collect_resolved_host_scan_targets(run_data)
        if _normalize_host_target(item) and _normalize_host_target(item) not in scanned
    ]
    return _signature(pending)


def _pending_host_targets(run_data: RunData) -> list[str]:
    scanned = {
        _normalize_host_target(item)
        for item in run_data.facts.get("nmap.scanned_targets", [])
        if str(item).strip()
    }
    return [
        _normalize_host_target(item)
        for item in collect_resolved_host_scan_targets(run_data)
        if _normalize_host_target(item) and _normalize_host_target(item) not in scanned
    ]


def _pending_candidate_web_signature(run_data: RunData, fact_key: str) -> str:
    scanned = {str(item).strip() for item in run_data.facts.get(fact_key, []) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _signature(pending)


def _pending_confirmed_web_signature(run_data: RunData, fact_key: str) -> str:
    scanned = {str(item).strip() for item in run_data.facts.get(fact_key, []) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_confirmed_web_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _signature(pending)


def _pending_wordpress_signature(run_data: RunData) -> str:
    scanned = {str(item).strip() for item in run_data.facts.get("wpscan.scanned_urls", []) if str(item).strip()}
    pending = [
        str(item.get("url") or "").strip()
        for item in collect_wordpress_targets(run_data)
        if str(item.get("url") or "").strip() and str(item.get("url") or "").strip() not in scanned
    ]
    return _signature(pending)


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
    "run-nmap": _pending_host_signature,
    "check-websites": lambda run_data: _pending_candidate_web_signature(run_data, "web_probe.scanned_urls"),
    "discover-web": lambda run_data: _pending_confirmed_web_signature(run_data, "web_discovery.scanned_urls"),
    "fingerprint-web": lambda run_data: _pending_confirmed_web_signature(run_data, "whatweb.scanned_urls"),
    "assess-web": lambda run_data: _pending_confirmed_web_signature(run_data, "nikto.scanned_urls"),
    "run-nuclei": lambda run_data: _pending_confirmed_web_signature(run_data, "nuclei.scanned_urls"),
    "run-wpscan": _pending_wordpress_signature,
}

INPUT_ITEMS_MAP = {
    "run-nmap": _pending_host_targets,
}
