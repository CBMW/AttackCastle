from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from hashlib import sha1
from typing import Any
from urllib.parse import urlparse

from attackcastle.core.enums import TargetType
from attackcastle.core.models import ScanTarget, new_id
from attackcastle.proxy import open_url

CLOUD_SUFFIXES: dict[str, str] = {
    "amazonaws.com": "aws",
    "cloudfront.net": "aws",
    "elb.amazonaws.com": "aws",
    "azurewebsites.net": "azure",
    "windows.net": "azure",
    "cloudapp.azure.com": "azure",
    "googleusercontent.com": "gcp",
    "appspot.com": "gcp",
    "run.app": "gcp",
    "herokuapp.com": "heroku",
    "vercel.app": "vercel",
    "netlify.app": "netlify",
}


@dataclass
class ScopeCompilation:
    targets: list[ScanTarget]
    graph: dict[str, Any]
    warnings: list[str]


def _node_id(kind: str, value: str) -> str:
    digest = sha1(f"{kind}:{value}".encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return f"{kind}_{digest}"


def _canonical_domain(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower().rstrip(".")


def classify_cloud_provider(host: str | None) -> str | None:
    normalized = _canonical_domain(host)
    if not normalized:
        return None
    for suffix, provider in CLOUD_SUFFIXES.items():
        if normalized == suffix or normalized.endswith(f".{suffix}"):
            return provider
    return None


def _parse_asn_number(value: str) -> int | None:
    cleaned = (value or "").strip().upper()
    if not cleaned.startswith("AS"):
        return None
    number = cleaned[2:]
    if not number.isdigit():
        return None
    parsed = int(number)
    if parsed <= 0:
        return None
    return parsed


def fetch_asn_prefixes(
    asn_value: str,
    timeout_seconds: int = 8,
    max_prefixes: int = 512,
    allow_ipv6: bool = False,
    proxy_url: str | None = None,
) -> list[str]:
    asn_number = _parse_asn_number(asn_value)
    if asn_number is None:
        return []
    url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
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
    if not isinstance(loaded, dict):
        return []
    data = loaded.get("data", {})
    if not isinstance(data, dict):
        return []
    ipv4 = data.get("ipv4_prefixes", [])
    ipv6 = data.get("ipv6_prefixes", []) if allow_ipv6 else []
    prefixes: list[str] = []
    for collection in (ipv4, ipv6):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            prefix = item.get("prefix")
            if isinstance(prefix, str) and prefix and prefix not in prefixes:
                prefixes.append(prefix)
            if len(prefixes) >= max(1, int(max_prefixes)):
                return prefixes
    return prefixes


def _target_host(target: ScanTarget) -> str | None:
    if target.target_type in {TargetType.DOMAIN, TargetType.WILDCARD_DOMAIN}:
        return _canonical_domain(target.host or target.value)
    if target.target_type == TargetType.URL:
        parsed = urlparse(target.value)
        return _canonical_domain(parsed.hostname or target.host)
    if target.target_type == TargetType.HOST_PORT:
        return _canonical_domain(target.host)
    return _canonical_domain(target.host)


def _dedupe_targets(targets: list[ScanTarget]) -> list[ScanTarget]:
    seen: set[tuple[str, str, str, int | None, str | None]] = set()
    merged: list[ScanTarget] = []
    for target in targets:
        key = (
            target.target_type.value,
            target.value,
            target.host or "",
            target.port,
            target.scheme,
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(target)
    return merged


def compile_scope(targets: list[ScanTarget], config: dict[str, Any]) -> ScopeCompilation:
    scope_config = config.get("scope", {}) if isinstance(config.get("scope"), dict) else {}
    asn_enabled = bool(scope_config.get("enable_asn_expansion", True))
    asn_timeout = int(scope_config.get("asn_timeout_seconds", 8))
    asn_max_prefixes = int(scope_config.get("asn_max_prefixes", 256))
    allow_ipv6 = bool(scope_config.get("allow_ipv6_prefixes", False))
    proxy_url = str(config.get("proxy", {}).get("url", "") or "").strip()

    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    warnings: list[str] = []
    compiled_targets: list[ScanTarget] = []
    cloud_hosts: list[dict[str, str]] = []
    asn_expansions = 0

    for target in targets:
        input_node_id = _node_id("input", target.value)
        nodes[input_node_id] = {
            "id": input_node_id,
            "kind": "input_target",
            "target_id": target.target_id,
            "target_type": target.target_type.value,
            "value": target.value,
            "raw": target.raw,
        }
        host = _target_host(target)
        provider = classify_cloud_provider(host)
        if host:
            host_node_id = _node_id("host", host)
            nodes[host_node_id] = {
                "id": host_node_id,
                "kind": "host",
                "host": host,
                "cloud_provider": provider,
            }
            edges.add((input_node_id, host_node_id, "resolves_to_host"))
            if provider:
                cloud_hosts.append({"host": host, "provider": provider})

        if target.target_type == TargetType.ASN:
            if not asn_enabled:
                warnings.append(f"ASN expansion disabled by policy: {target.value}")
                continue
            if proxy_url:
                prefixes = fetch_asn_prefixes(
                    asn_value=target.value,
                    timeout_seconds=asn_timeout,
                    max_prefixes=asn_max_prefixes,
                    allow_ipv6=allow_ipv6,
                    proxy_url=proxy_url,
                )
            else:
                prefixes = fetch_asn_prefixes(
                    asn_value=target.value,
                    timeout_seconds=asn_timeout,
                    max_prefixes=asn_max_prefixes,
                    allow_ipv6=allow_ipv6,
                )
            if not prefixes:
                warnings.append(f"No routable prefixes could be derived for {target.value}")
                continue
            asn_expansions += len(prefixes)
            asn_node_id = _node_id("asn", target.value)
            nodes[asn_node_id] = {
                "id": asn_node_id,
                "kind": "asn",
                "asn": target.value,
                "prefix_count": len(prefixes),
            }
            edges.add((input_node_id, asn_node_id, "asn_scope"))
            for prefix in prefixes:
                derived = ScanTarget(
                    target_id=new_id("target"),
                    raw=f"{target.raw} -> {prefix}",
                    target_type=TargetType.CIDR,
                    value=prefix,
                )
                compiled_targets.append(derived)
                cidr_node_id = _node_id("cidr", prefix)
                nodes[cidr_node_id] = {"id": cidr_node_id, "kind": "cidr", "value": prefix}
                edges.add((asn_node_id, cidr_node_id, "expands_to"))
            continue

        # Keep non-ASN scope items as part of compiled scope.
        compiled_targets.append(target)
        canonical_node_id = _node_id("canonical", f"{target.target_type.value}:{target.value}")
        nodes[canonical_node_id] = {
            "id": canonical_node_id,
            "kind": "canonical_target",
            "target_type": target.target_type.value,
            "value": target.value,
            "host": host,
            "port": target.port,
            "scheme": target.scheme,
            "cloud_provider": provider,
        }
        edges.add((input_node_id, canonical_node_id, "normalizes_to"))

    deduped_targets = _dedupe_targets(compiled_targets)
    deduped_cloud: list[dict[str, str]] = []
    seen_cloud: set[tuple[str, str]] = set()
    for item in cloud_hosts:
        key = (item["host"], item["provider"])
        if key in seen_cloud:
            continue
        seen_cloud.add(key)
        deduped_cloud.append(item)

    graph = {
        "summary": {
            "input_target_count": len(targets),
            "compiled_target_count": len(deduped_targets),
            "asn_expansion_count": asn_expansions,
            "cloud_host_count": len(deduped_cloud),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "nodes": list(nodes.values()),
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in sorted(edges)
        ],
        "cloud_hosts": deduped_cloud,
    }
    return ScopeCompilation(targets=deduped_targets, graph=graph, warnings=warnings)
