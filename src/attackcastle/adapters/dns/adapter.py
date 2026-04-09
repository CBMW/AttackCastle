from __future__ import annotations

import json
import re
from collections import defaultdict

from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.adapters.dns.parser import resolve_cname, resolve_mx, resolve_ns, resolve_txt
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Asset, Evidence, NormalizedEntity, Observation, RunData, new_id
from attackcastle.scan_policy import build_scan_policy
from attackcastle.scope.compiler import classify_cloud_provider

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
]

PROVIDER_HINTS = {
    "github.io": "github-pages",
    "herokudns.com": "heroku",
    "zendesk.com": "zendesk",
    "fastly.net": "fastly",
    "trafficmanager.net": "azure",
    "pages.dev": "cloudflare-pages",
    "pantheonsite.io": "pantheon",
}


def _canonical_host(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower().rstrip(".")


def _is_ip_literal(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _root_domain(host: str) -> str:
    parts = [item for item in host.split(".") if item]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _provider_from_records(values: list[str]) -> str | None:
    for item in values:
        normalized = _canonical_host(item)
        provider = classify_cloud_provider(normalized)
        if provider:
            return provider
        for suffix, label in PROVIDER_HINTS.items():
            if normalized and (normalized == suffix or normalized.endswith(f".{suffix}")):
                return label
    return None


def _common_dkim_selectors(config: dict[str, object]) -> list[str]:
    selectors = config.get("common_dkim_selectors", COMMON_DKIM_SELECTORS)
    if not isinstance(selectors, list):
        return list(COMMON_DKIM_SELECTORS)
    normalized = [str(item).strip() for item in selectors if str(item).strip()]
    return normalized or list(COMMON_DKIM_SELECTORS)


class DNSAdapter:
    name = "dns_resolver"
    capability = "dns_resolution"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        hosts = []
        for target in run_data.scope:
            if target.host and not _is_ip_literal(target.host):
                hosts.append(target.host)
        for asset in run_data.assets:
            if asset.kind == "domain" and asset.name and not _is_ip_literal(asset.name):
                hosts.append(asset.name)
        unique_hosts = sorted({_canonical_host(host) for host in hosts if _canonical_host(host)})
        return [f"dnsx -silent -resp -l hosts.txt  # includes {host}" for host in unique_hosts[:20]]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        config = context.config.get("dns", {})
        timeout_seconds = int(context.config.get("scan", {}).get("dns_timeout_seconds", 8))
        common_selectors = _common_dkim_selectors(config if isinstance(config, dict) else {})
        max_domains = int((config or {}).get("max_domains", 400)) if isinstance(config, dict) else 400
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip() or None
        policy = build_scan_policy(context.profile_name, context.config)

        hosts_to_resolve: set[str] = set()
        scope_domains: set[str] = set()
        for target in run_data.scope:
            host = _canonical_host(target.host)
            if target.target_type in {TargetType.DOMAIN, TargetType.URL, TargetType.HOST_PORT, TargetType.WILDCARD_DOMAIN}:
                if host and not _is_ip_literal(host):
                    hosts_to_resolve.add(host)
                    scope_domains.add(host)
        for asset in run_data.assets:
            host = _canonical_host(asset.name)
            if asset.kind == "domain" and host and not _is_ip_literal(host):
                hosts_to_resolve.add(host)

        sorted_hosts = sorted(hosts_to_resolve)[:max_domains]
        if sorted_hosts:
            input_path = context.run_store.artifact_path(self.name, "dnsx_hosts.txt")
            input_path.write_text("\n".join(sorted_hosts), encoding="utf-8")
            command_result = run_command_spec(
                context,
                CommandSpec(
                    tool_name="dnsx",
                    capability=self.capability,
                    task_type="ResolveHosts",
                    command=["dnsx", "-silent", "-resp", "-l", str(input_path)],
                    timeout_seconds=timeout_seconds,
                    artifact_prefix="dnsx_resolution",
                    extra_artifacts=[input_path],
                ),
                proxy_url=proxy_url,
            )
            result.tool_executions.append(command_result.execution)
            result.evidence_artifacts.extend(command_result.evidence_artifacts)
            result.task_results.append(command_result.task_result)
            if command_result.task_result.status == "skipped":
                result.warnings.extend(command_result.task_result.warnings)
                return result
            resolution_map: dict[str, dict[str, list[str]]] = {
                host: {"ips": [], "cnames": []} for host in sorted_hosts
            }
            parsed_entities: list[dict[str, object]] = []
            for line in command_result.stdout_text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                tokens = stripped.split()
                host = _canonical_host(tokens[0])
                if not host or host not in resolution_map:
                    continue
                ips = [item for item in IP_RE.findall(stripped) if item not in resolution_map[host]["ips"]]
                resolution_map[host]["ips"].extend(ips)
                lower_tokens = [token.lower().rstrip(".") for token in tokens[1:]]
                for token in lower_tokens:
                    if token == host or _is_ip_literal(token):
                        continue
                    if "." not in token:
                        continue
                    if token not in resolution_map[host]["cnames"]:
                        resolution_map[host]["cnames"].append(token)
                parsed_entities.append(
                    {
                        "type": "ResolvedHost",
                        "fqdn": host,
                        "ips": list(resolution_map[host]["ips"]),
                    }
                )
            command_result.task_result.parsed_entities = parsed_entities
            command_result.task_result.metrics = {
                "lines_parsed": len([line for line in command_result.stdout_text.splitlines() if line.strip()]),
                "entities_created": sum(len(item["ips"]) for item in resolution_map.values()),
                "entities_updated": 0,
            }
            execution_id = command_result.execution_id
        else:
            resolution_map = {}
            execution_id = new_id("exec")

        discovered_hosts = {
            _canonical_host(item)
            for item in run_data.facts.get("subdomain_enum.discovered_hosts", [])
            if _canonical_host(item)
        }
        root_ns_cache: dict[str, list[str]] = {}
        summary = defaultdict(int)

        for host in sorted_hosts:
            domain_asset = Asset(
                asset_id=new_id("asset"),
                kind="domain",
                name=host,
                source_tool=self.name,
                source_execution_id=execution_id,
                parser_version="dns_v3",
            )
            result.assets.append(domain_asset)

            ips = list(resolution_map.get(host, {}).get("ips", []))
            try:
                if proxy_url:
                    mx_records = resolve_mx(host, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    txt_records = resolve_txt(host, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    ns_records = resolve_ns(host, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    cname_records = resolve_cname(host, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    dmarc_records = resolve_txt(f"_dmarc.{host}", timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    mta_sts_records = resolve_txt(f"_mta-sts.{host}", timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                    tls_rpt_records = resolve_txt(
                        f"_smtp._tls.{host}",
                        timeout_seconds=timeout_seconds,
                        proxy_url=proxy_url,
                    )
                else:
                    mx_records = resolve_mx(host, timeout_seconds=timeout_seconds)
                    txt_records = resolve_txt(host, timeout_seconds=timeout_seconds)
                    ns_records = resolve_ns(host, timeout_seconds=timeout_seconds)
                    cname_records = resolve_cname(host, timeout_seconds=timeout_seconds)
                    dmarc_records = resolve_txt(f"_dmarc.{host}", timeout_seconds=timeout_seconds)
                    mta_sts_records = resolve_txt(f"_mta-sts.{host}", timeout_seconds=timeout_seconds)
                    tls_rpt_records = resolve_txt(f"_smtp._tls.{host}", timeout_seconds=timeout_seconds)
            except Exception as exc:  # noqa: BLE001
                result.warnings.append(f"DNS posture lookup failed for {host}: {exc}")
                continue

            for ip in ips:
                result.normalized_entities.append(
                    NormalizedEntity(
                        entity_id=new_id("entity"),
                        entity_type="IPAddress",
                        attributes={"address": ip, "version": 6 if ":" in ip else 4, "source": "dnsx"},
                        source_tool="dnsx",
                        source_task_id=result.task_results[-1].task_id if result.task_results else None,
                        source_execution_id=execution_id,
                        parser_version="dnsx_v1",
                    )
                )
                result.normalized_entities.append(
                    NormalizedEntity(
                        entity_id=new_id("entity"),
                        entity_type="ResolvedHost",
                        attributes={"fqdn": host, "ip": ip, "record_type": "A"},
                        source_tool="dnsx",
                        source_task_id=result.task_results[-1].task_id if result.task_results else None,
                        source_execution_id=execution_id,
                        parser_version="dnsx_v1",
                    )
                )
            result.normalized_entities.append(
                NormalizedEntity(
                    entity_id=new_id("entity"),
                    entity_type="Hostname",
                    attributes={"fqdn": host, "root_domain": _root_domain(host), "source": "dnsx"},
                    source_tool="dnsx",
                    source_task_id=result.task_results[-1].task_id if result.task_results else None,
                    source_execution_id=execution_id,
                    parser_version="dnsx_v1",
                )
            )

            dkim_hits: dict[str, list[str]] = {}
            for selector in common_selectors:
                selector_host = f"{selector}._domainkey.{host}"
                if proxy_url:
                    values = resolve_txt(selector_host, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                else:
                    values = resolve_txt(selector_host, timeout_seconds=timeout_seconds)
                if any("v=dkim1" in record.lower() for record in values):
                    dkim_hits[selector] = values

            spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
            has_dmarc = any("v=dmarc1" in record.lower() for record in dmarc_records)
            has_mta_sts = any("v=stsv1" in record.lower() for record in mta_sts_records)
            has_tls_rpt = any("v=tlsrptv1" in record.lower() for record in tls_rpt_records)
            provider = _provider_from_records(cname_records)
            takeover_candidate = bool(cname_records) and not ips and provider is not None
            root = _root_domain(host)
            if root not in root_ns_cache:
                if proxy_url:
                    root_ns_cache[root] = resolve_ns(root, timeout_seconds=timeout_seconds, proxy_url=proxy_url)
                else:
                    root_ns_cache[root] = resolve_ns(root, timeout_seconds=timeout_seconds)
            ns_drift = bool(ns_records) and host != root and set(ns_records) != set(root_ns_cache.get(root, []))
            ct_drift = host in discovered_hosts and host not in scope_domains

            artifact_path = context.run_store.artifact_path(
                self.name, f"dns_{host.replace('*', '_').replace(':', '_')}.json"
            )
            artifact_payload = {
                "host": host,
                "ips": ips,
                "mx": mx_records,
                "txt": txt_records,
                "ns": ns_records,
                "cname": cname_records,
                "spf": spf_records,
                "dmarc": dmarc_records,
                "mta_sts": mta_sts_records,
                "tls_rpt": tls_rpt_records,
                "dkim_hits": dkim_hits,
                "provider": provider,
                "takeover_candidate": takeover_candidate,
                "ns_drift": ns_drift,
                "ct_drift": ct_drift,
            }
            artifact_path.write_text(json.dumps(artifact_payload, indent=2), encoding="utf-8")

            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="dns_resolution",
                snippet=(
                    f"{host} ips={len(ips)} mx={len(mx_records)} ns={len(ns_records)} "
                    f"cname={len(cname_records)} takeover={takeover_candidate}"
                ),
                artifact_path=str(artifact_path),
                selector={"kind": "json", "keys": ["ips", "mx", "ns", "cname"]},
                source_execution_id=execution_id,
                parser_version="dns_v3",
                confidence=0.96,
            )
            result.evidence.append(evidence)

            for ip in ips:
                result.assets.append(
                    Asset(
                        asset_id=new_id("asset"),
                        kind="host",
                        name=ip,
                        ip=ip,
                        parent_asset_id=domain_asset.asset_id,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )

            observations = [
                Observation(
                    observation_id=new_id("obs"),
                    key="dns.resolved_ips",
                    value=ips,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=1.0 if ips else 0.7,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.mx.records",
                    value=mx_records,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.92 if mx_records else 0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.spf.present",
                    value=bool(spf_records),
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.dmarc.present",
                    value=has_dmarc,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.mta_sts.present",
                    value=has_mta_sts,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.88,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.tls_rpt.present",
                    value=has_tls_rpt,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.88,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.dkim.common_selector_present",
                    value=bool(dkim_hits),
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.7,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="mail.dkim.selector_hits",
                    value=sorted(dkim_hits.keys()),
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.75,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="dns.ns.records",
                    value=ns_records,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.92,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
                Observation(
                    observation_id=new_id("obs"),
                    key="dns.cname.records",
                    value=cname_records,
                    entity_type="asset",
                    entity_id=domain_asset.asset_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="dns_v3",
                ),
            ]

            if provider:
                observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="dns.cloud.provider",
                        value=provider,
                        entity_type="asset",
                        entity_id=domain_asset.asset_id,
                        source_tool=self.name,
                        confidence=0.82,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )
            if takeover_candidate:
                observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="dns.takeover.candidate",
                        value={"provider": provider, "cname": cname_records},
                        entity_type="asset",
                        entity_id=domain_asset.asset_id,
                        source_tool=self.name,
                        confidence=0.84,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )
                summary["takeover_candidates"] += 1
            if ns_drift:
                observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="dns.ns.drift",
                        value={"root_domain": root, "root_ns": root_ns_cache.get(root, []), "ns": ns_records},
                        entity_type="asset",
                        entity_id=domain_asset.asset_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )
                summary["ns_drift"] += 1
            if ct_drift:
                observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="dns.ct.drift.detected",
                        value=True,
                        entity_type="asset",
                        entity_id=domain_asset.asset_id,
                        source_tool=self.name,
                        confidence=0.78,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )
                summary["ct_drift"] += 1
            if mx_records and (not has_mta_sts or not has_tls_rpt):
                observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="mail.transport_policy.gap",
                        value={
                            "mta_sts": has_mta_sts,
                            "tls_rpt": has_tls_rpt,
                            "mx_records": len(mx_records),
                        },
                        entity_type="asset",
                        entity_id=domain_asset.asset_id,
                        source_tool=self.name,
                        confidence=0.9,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="dns_v3",
                    )
                )
                summary["mail_policy_gaps"] += 1

            result.observations.extend(observations)
            summary["resolved_hosts"] += 1 if ips else 0
            summary["mx_hosts"] += 1 if mx_records else 0
            summary["provider_backed"] += 1 if provider else 0

        result.facts["dns.resolved_hosts"] = int(summary["resolved_hosts"])
        result.facts["dns.internet_exposure.summary"] = dict(summary)

        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "domains_analyzed": len(sorted_hosts),
                "summary": dict(summary),
                "profile": policy.profile,
            },
        )
        return result
