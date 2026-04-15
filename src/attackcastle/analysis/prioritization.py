from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from attackcastle.core.models import EvidenceBundle, Lead, RunData

REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900}
SENSITIVE_DATA_PORTS = {1433, 3306, 5432, 6379, 9200, 27017}
HIGH_VALUE_SIGNAL_KEYS = {
    "web.login_portal": ("Public login surface detected", 24),
    "web.admin_interface": ("Administrative interface detected", 32),
    "web.public_files": ("Interesting public file exposure detected", 30),
    "web.default_page": ("Default or placeholder page detected", 10),
    "web.soft_404": ("Soft-404 behavior detected", 10),
    "web.response.too_generic": ("Response may be generic or intermediary-controlled", 16),
    "web.redirect.loop": ("Redirect behavior may be masking the real application", 10),
    "web.cdn_parking_page": ("CDN or parking response detected", 10),
    "web.execution.downgraded": ("Target triggered a more careful probing mode", 8),
    "web.discovery.graphql_endpoints": ("GraphQL surface discovered", 18),
    "web.discovery.source_maps": ("Source maps discovered", 16),
    "cloud.storage.public": ("Public cloud storage-like surface detected", 34),
    "cloud.storage.object_listing": ("Cloud storage object listing detected", 28),
    "cloud.storage.static_site": ("Cloud static-site hosting detected", 10),
    "cloud.storage.signed_url": ("Signed cloud URL markers detected", 10),
    "tls.weak_protocol": ("Weak TLS protocol detected", 24),
    "tls.weak_cipher": ("Weak TLS cipher detected", 24),
    "tls.san.mismatch": ("TLS hostname mismatch detected", 22),
    "dns.takeover.candidate": ("Potential dangling DNS or takeover candidate detected", 34),
    "mail.open_relay.possible": ("Possible SMTP relay behavior detected", 34),
    "web.api.docs.exposed": ("API documentation or collection exposed", 16),
    "web.edge.console.exposed": ("Management or edge console exposed", 30),
    "thirdparty.github.reference": ("Public GitHub reference detected in exposed content", 12),
    "thirdparty.package.reference": ("Public package or image reference detected in exposed content", 10),
}
LEAD_PRIORITY_LABELS = (
    (85, "very-high"),
    (60, "high"),
    (40, "medium"),
    (1, "low"),
)


def _lead_id(category: str, title: str, affected: list[dict[str, str]]) -> str:
    material = "|".join(
        [category, title, ",".join(sorted(f"{item.get('entity_type')}:{item.get('entity_id')}" for item in affected))]
    )
    return f"lead_{hashlib.sha1(material.encode('utf-8')).hexdigest()[:12]}"  # noqa: S324


def _bundle_id(entity_type: str, entity_id: str) -> str:
    return f"bundle_{hashlib.sha1(f'{entity_type}:{entity_id}'.encode('utf-8')).hexdigest()[:12]}"  # noqa: S324


def _priority_label(score: int) -> str:
    for threshold, label in LEAD_PRIORITY_LABELS:
        if score >= threshold:
            return label
    return "none"


def _entity_asset_maps(run_data: RunData) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    service_assets = {item.service_id: item.asset_id for item in run_data.services}
    web_assets = {item.webapp_id: item.asset_id for item in run_data.web_apps}
    tls_assets = {item.tls_id: item.asset_id for item in run_data.tls_assets}
    return service_assets, web_assets, tls_assets


def _observations_by_entity(run_data: RunData) -> dict[tuple[str, str], list[Any]]:
    rows: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for observation in run_data.observations:
        rows[(observation.entity_type, observation.entity_id)].append(observation)
    return rows


def _evidence_lookup(run_data: RunData) -> dict[str, Any]:
    return {item.evidence_id: item for item in run_data.evidence}


def _finding_lookup_by_entity(run_data: RunData) -> dict[tuple[str, str], list[Any]]:
    rows: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for finding in run_data.findings:
        if finding.suppressed:
            continue
        for entity in finding.affected_entities:
            rows[(str(entity.get("entity_type")), str(entity.get("entity_id")))].append(finding)
    return rows


def _append_signal(
    signals: list[str],
    weights: list[int],
    evidence_ids: set[str],
    observation_ids: set[str],
    sources: set[str],
    note: str,
    weight: int,
    observation: Any | None = None,
) -> None:
    signals.append(note)
    weights.append(weight)
    if observation is not None:
        evidence_ids.update(observation.evidence_ids)
        observation_ids.add(observation.observation_id)
        sources.add(observation.source_tool)


def _lead_from_signals(
    *,
    category: str,
    title: str,
    affected_entities: list[dict[str, str]],
    signals: list[str],
    weights: list[int],
    evidence_ids: set[str],
    observation_ids: set[str],
    sources: set[str],
    next_steps: list[str],
    likely_finding: str | None,
    likely_severity: str | None,
    confidence: float = 0.78,
) -> Lead | None:
    if not weights:
        return None
    score = min(100, sum(weights) + max(0, len(set(signals)) - 1) * 4)
    priority_label = _priority_label(score)
    if priority_label == "none":
        return None
    why_it_matters = "; ".join(signals[:3])
    reasoning = f"Prioritized because {'; '.join(signals[:4])}."
    draft = None
    if likely_finding:
        draft = (
            f"AttackCastle observed {why_it_matters.lower()} on externally reachable infrastructure. "
            "This target should be manually validated to confirm exploitability, authentication exposure, and business relevance."
        )
    return Lead(
        lead_id=_lead_id(category, title, affected_entities),
        title=title,
        category=category,
        priority_score=score,
        priority_label=priority_label,
        confidence=confidence,
        status="likely-finding" if likely_finding else "manual-review",
        why_it_matters=why_it_matters,
        reasoning=reasoning,
        suggested_next_steps=next_steps,
        likely_finding=likely_finding,
        likely_severity=likely_severity,
        draft_finding_seed=draft,
        tags=[category.lower().replace(" ", "-"), priority_label],
        affected_entities=affected_entities,
        evidence_ids=sorted(evidence_ids),
        source_observation_ids=sorted(observation_ids),
        detection_sources=sorted(sources),
    )


def build_priority_leads(run_data: RunData) -> list[Lead]:
    service_assets, web_assets, tls_assets = _entity_asset_maps(run_data)
    observations_by_entity = _observations_by_entity(run_data)
    findings_by_entity = _finding_lookup_by_entity(run_data)
    provider_edge_assets = {
        observation.entity_id: str(observation.value.get("provider"))
        for observation in run_data.observations
        if observation.entity_type == "asset"
        and observation.key == "dns.provider_edge"
        and isinstance(observation.value, dict)
        and str(observation.value.get("provider") or "").strip()
    }
    leads: list[Lead] = []

    for service in run_data.services:
        key = ("service", service.service_id)
        provider_edge = provider_edge_assets.get(service.asset_id)
        generic_provider_web_port = bool(provider_edge and int(service.port) in {80, 443, 8080, 8443})
        signals: list[str] = []
        weights: list[int] = []
        evidence_ids: set[str] = set()
        observation_ids: set[str] = set()
        sources: set[str] = set()
        if int(service.port) in REMOTE_ADMIN_PORTS:
            _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Remote administration port exposed", 28)
        if int(service.port) in SENSITIVE_DATA_PORTS:
            _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Sensitive backend/data service exposed", 26)
        lowered_name = (service.name or "").lower()
        if "vpn" in lowered_name:
            _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Public VPN or remote access service", 34)
        if service.banner and any(char.isdigit() for char in service.banner) and not generic_provider_web_port:
            _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Version-bearing banner observed", 8)
        for observation in observations_by_entity.get(key, []):
            if observation.key == "service.remote_admin.exposed" and observation.value is True:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Remote administration service confirmed", 18, observation)
            if observation.key == "service.vpn.exposed" and observation.value is True:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "VPN/auth gateway exposed", 24, observation)
            if observation.key == "web.vhost.discovered":
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Additional virtual host discovered on this service", 14, observation)
            if observation.key == "vuln.cve.top_priority" and isinstance(observation.value, dict):
                priority = str(observation.value.get("priority", "medium")).lower()
                weight = {"critical": 34, "high": 26, "medium": 16, "low": 8}.get(priority, 12)
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, f"Prioritized CVE candidate ({priority})", weight, observation)
        lead = _lead_from_signals(
            category="Service Lead",
            title=f"{service.name or 'service'} exposed on port {service.port}",
            affected_entities=[{"entity_type": "service", "entity_id": service.service_id}],
            signals=signals,
            weights=weights,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            sources=sources,
            next_steps=[
                "Validate whether internet exposure is expected.",
                "Confirm authentication controls, MFA, and lockout behavior.",
                "Check appliance/software version and known CVEs.",
            ],
            likely_finding="Exposed administrative or remote access surface" if signals else None,
            likely_severity="high" if any(weight >= 30 for weight in weights) else "medium",
        )
        if lead:
            if provider_edge:
                lead.tags.append("provider-edge")
                lead.reasoning += f" Provider edge detected: {provider_edge}."
            leads.append(lead)

    for web_app in run_data.web_apps:
        key = ("web_app", web_app.webapp_id)
        signals = []
        weights: list[int] = []
        evidence_ids: set[str] = set()
        observation_ids: set[str] = set()
        sources: set[str] = set()
        for observation in observations_by_entity.get(key, []):
            signal = HIGH_VALUE_SIGNAL_KEYS.get(observation.key)
            if signal:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, signal[0], signal[1], observation)
            if observation.key == "web.redirect.chain":
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Redirect chain or surface pivot observed", 8, observation)
            if observation.key == "web.missing_security_headers":
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Missing security headers observed", 8, observation)
            if observation.key == "web.waf_or_cdn":
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Protected by CDN/WAF, suggesting important external surface", 4, observation)
            if observation.key == "coverage.gap" and isinstance(observation.value, dict):
                _append_signal(
                    signals,
                    weights,
                    evidence_ids,
                    observation_ids,
                    sources,
                    f"Coverage gap noted: {observation.value.get('reason')}",
                    10,
                    observation,
                )
            if observation.key == "tech.stack.confidence" and float(observation.value or 0.0) >= 0.85:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Technology fingerprint confidence is high", 4, observation)
        for finding in findings_by_entity.get(key, []):
            weight = {"critical": 34, "high": 28, "medium": 18, "low": 10}.get(finding.severity.value, 8)
            signals.append(f"Finding signal present: {finding.title}")
            weights.append(weight)
            evidence_ids.update(finding.evidence_ids)
        lead = _lead_from_signals(
            category="Web Lead",
            title=web_app.title or web_app.url,
            affected_entities=[{"entity_type": "web_app", "entity_id": web_app.webapp_id}],
            signals=signals,
            weights=weights,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            sources=sources,
            next_steps=[
                "Review screenshots, headers, and redirect behavior.",
                "Check default files, admin paths, and public disclosures.",
                "Validate auth flows, password reset, and version/CVE hints.",
            ],
            likely_finding="Publicly accessible administrative or login surface" if signals else None,
            likely_severity="high" if any(weight >= 28 for weight in weights) else "medium",
        )
        if lead:
            leads.append(lead)

    for tls_item in run_data.tls_assets:
        key = ("tls", tls_item.tls_id)
        signals = []
        weights: list[int] = []
        evidence_ids: set[str] = set()
        observation_ids: set[str] = set()
        sources: set[str] = set()
        for observation in observations_by_entity.get(key, []):
            if observation.key == "tls.weak_protocol" and observation.value is True:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Weak TLS protocol enabled", 24, observation)
            if observation.key == "tls.cert.expiring_soon" and observation.value is True:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Certificate expiring soon", 8, observation)
        lead = _lead_from_signals(
            category="TLS Lead",
            title=f"TLS posture on {tls_item.host}:{tls_item.port}",
            affected_entities=[{"entity_type": "tls", "entity_id": tls_item.tls_id}],
            signals=signals,
            weights=weights,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            sources=sources,
            next_steps=["Validate protocol/cipher support and certificate hygiene.", "Confirm business impact of exposed TLS weaknesses."],
            likely_finding="Weak TLS configuration" if signals else None,
            likely_severity="medium",
        )
        if lead:
            leads.append(lead)

    for asset in run_data.assets:
        key = ("asset", asset.asset_id)
        signals = []
        weights: list[int] = []
        evidence_ids: set[str] = set()
        observation_ids: set[str] = set()
        sources: set[str] = set()
        for observation in observations_by_entity.get(key, []):
            if observation.key == "mail.mx.records" and observation.value:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "Mail records present for domain", 4, observation)
            if observation.key == "mail.spf.present" and observation.value is False:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "SPF missing", 14, observation)
            if observation.key == "mail.dmarc.present" and observation.value is False:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "DMARC missing", 18, observation)
            if observation.key == "mail.mta_sts.present" and observation.value is False:
                _append_signal(signals, weights, evidence_ids, observation_ids, sources, "MTA-STS missing", 8, observation)
        lead = _lead_from_signals(
            category="Mail Posture",
            title=f"Email security posture for {asset.name}",
            affected_entities=[{"entity_type": "asset", "entity_id": asset.asset_id}],
            signals=signals,
            weights=weights,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            sources=sources,
            next_steps=["Confirm mail flow ownership.", "Validate SPF, DMARC, and MTA-STS policy coverage."],
            likely_finding="Missing email protections" if any(weight >= 14 for weight in weights) else None,
            likely_severity="medium",
            confidence=0.72,
        )
        if lead:
            leads.append(lead)

    asset_rollups: dict[str, list[Lead]] = defaultdict(list)
    for lead in leads:
        for entity in lead.affected_entities:
            entity_type = entity.get("entity_type")
            entity_id = entity.get("entity_id")
            asset_id = None
            if entity_type == "asset":
                asset_id = entity_id
            elif entity_type == "service":
                asset_id = service_assets.get(str(entity_id))
            elif entity_type == "web_app":
                asset_id = web_assets.get(str(entity_id))
            elif entity_type == "tls":
                asset_id = tls_assets.get(str(entity_id))
            if asset_id:
                asset_rollups[str(asset_id)].append(lead)
    for asset_id, asset_leads in asset_rollups.items():
        if len(asset_leads) < 2:
            continue
        asset = next((item for item in run_data.assets if item.asset_id == asset_id), None)
        aggregated_signals = [f"{lead.category}: {lead.title}" for lead in asset_leads[:4]]
        rollup = _lead_from_signals(
            category="Exposure Cluster",
            title=f"Multi-signal exposure cluster on {asset.name if asset else asset_id}",
            affected_entities=[{"entity_type": "asset", "entity_id": asset_id}],
            signals=aggregated_signals,
            weights=[max(10, int(lead.priority_score / 3)) for lead in asset_leads[:4]],
            evidence_ids={evidence_id for lead in asset_leads for evidence_id in lead.evidence_ids},
            observation_ids={obs_id for lead in asset_leads for obs_id in lead.source_observation_ids},
            sources={source for lead in asset_leads for source in lead.detection_sources},
            next_steps=["Review this host as a priority manual-testing cluster.", "Use the per-host workspace to pivot through evidence quickly."],
            likely_finding="Excessive attack surface",
            likely_severity="high",
            confidence=0.8,
        )
        if rollup:
            leads.append(rollup)

    leads.sort(key=lambda item: (-item.priority_score, -item.confidence, item.title))
    deduped: dict[str, Lead] = {}
    for lead in leads:
        deduped.setdefault(lead.lead_id, lead)
    return list(deduped.values())


def build_evidence_bundles(run_data: RunData) -> list[EvidenceBundle]:
    evidence_lookup = _evidence_lookup(run_data)
    observations_by_entity = _observations_by_entity(run_data)
    service_assets, web_assets, tls_assets = _entity_asset_maps(run_data)
    bundles: list[EvidenceBundle] = []
    entities: set[tuple[str | None, str | None]] = set()
    entities.update((item.entity_type, item.entity_id) for item in run_data.observations)
    entities.update(
        (item.get("entity_type"), item.get("entity_id"))
        for lead in run_data.leads
        for item in lead.affected_entities
    )
    for entity_type, entity_id in entities:
        if not entity_type or not entity_id:
            continue
        evidence_ids: set[str] = set()
        source_tools: set[str] = set()
        for observation in observations_by_entity.get((str(entity_type), str(entity_id)), []):
            evidence_ids.update(observation.evidence_ids)
            source_tools.add(observation.source_tool)
        for lead in run_data.leads:
            if any(item.get("entity_type") == entity_type and item.get("entity_id") == entity_id for item in lead.affected_entities):
                evidence_ids.update(lead.evidence_ids)
                source_tools.update(lead.detection_sources)
        if not evidence_ids:
            continue
        artifact_paths = sorted(
            {
                evidence_lookup[evidence_id].artifact_path
                for evidence_id in evidence_ids
                if evidence_id in evidence_lookup and evidence_lookup[evidence_id].artifact_path
            }
        )
        screenshot_paths = sorted(
            {
                evidence_lookup[evidence_id].artifact_path
                for evidence_id in evidence_ids
                if evidence_id in evidence_lookup and evidence_lookup[evidence_id].kind == "web_screenshot"
                and evidence_lookup[evidence_id].artifact_path
            }
        )
        confidence_values = [
            float(evidence_lookup[evidence_id].confidence)
            for evidence_id in evidence_ids
            if evidence_id in evidence_lookup
        ]
        asset_id = None
        if entity_type == "asset":
            asset_id = str(entity_id)
        elif entity_type == "service":
            asset_id = service_assets.get(str(entity_id))
        elif entity_type == "web_app":
            asset_id = web_assets.get(str(entity_id))
        elif entity_type == "tls":
            asset_id = tls_assets.get(str(entity_id))
        bundles.append(
            EvidenceBundle(
                bundle_id=_bundle_id(str(entity_type), str(entity_id)),
                label=f"{entity_type}:{entity_id}",
                entity_type=str(entity_type),
                entity_id=str(entity_id),
                asset_id=asset_id,
                summary=f"{len(evidence_ids)} evidence items across {len(source_tools)} sources",
                confidence=round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0,
                evidence_ids=sorted(evidence_ids),
                artifact_paths=artifact_paths,
                screenshot_paths=screenshot_paths,
                raw_output_paths=artifact_paths,
                source_tools=sorted(source_tools),
            )
        )
    bundles.sort(key=lambda item: (-len(item.evidence_ids), -item.confidence, item.label))
    return bundles
