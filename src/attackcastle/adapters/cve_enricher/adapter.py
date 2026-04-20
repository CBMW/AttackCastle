from __future__ import annotations

import json

from attackcastle.adapters.base import build_tool_execution, cancellation_requested
from attackcastle.adapters.cve_enricher.knowledge import (
    enrich_service_signature,
    enrich_technology_signature,
)
from attackcastle.adapters.cve_enricher.prioritization import (
    fetch_epss_score,
    fetch_kev_set,
    prioritize_cves,
)
from attackcastle.adapters.cve_enricher.remote import fetch_cve_candidates
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, new_id, now_utc


class CVEEnricherAdapter:
    name = "cve_enricher"
    capability = "vuln_enrichment"
    noise_score = 0
    cost_score = 2

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return ["local cpe/cve enrichment correlation"]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")
        backend = str(context.config.get("cve_enricher", {}).get("backend", "local")).lower()
        remote_enabled = backend in {"remote", "hybrid"}
        remote_timeout = int(context.config.get("cve_enricher", {}).get("remote_timeout_seconds", 8))
        remote_max_items = int(context.config.get("cve_enricher", {}).get("remote_max_items", 10))
        epss_timeout = int(context.config.get("cve_enricher", {}).get("epss_timeout_seconds", 6))
        kev_timeout = int(context.config.get("cve_enricher", {}).get("kev_timeout_seconds", 8))
        kev_feed_url = str(context.config.get("cve_enricher", {}).get("kev_feed_url", "")).strip()
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()
        kev_enabled = bool(context.config.get("cve_enricher", {}).get("kev_enabled", remote_enabled))
        if kev_feed_url and kev_enabled:
            if proxy_url:
                kev_set = fetch_kev_set(kev_feed_url, timeout_seconds=kev_timeout, proxy_url=proxy_url)
            else:
                kev_set = fetch_kev_set(kev_feed_url, timeout_seconds=kev_timeout)
        else:
            kev_set = set()
        epss_cache: dict[str, float | None] = {}

        candidates: list[dict[str, object]] = []
        for service in run_data.services:
            if cancellation_requested(context):
                result.warnings.append("CVE enrichment cancelled by scheduler before all services were processed")
                break
            enriched = enrich_service_signature(service.name or "", service.banner)
            cves: list[str] = list(enriched.get("cves", [])) if enriched else []
            cpe = enriched.get("cpe") if enriched else None
            if remote_enabled:
                remote_keyword = " ".join([service.name or "", service.banner or ""]).strip()
                if proxy_url:
                    remote_candidates = fetch_cve_candidates(
                        remote_keyword,
                        timeout_seconds=remote_timeout,
                        max_items=remote_max_items,
                        proxy_url=proxy_url,
                    )
                else:
                    remote_candidates = fetch_cve_candidates(
                        remote_keyword,
                        timeout_seconds=remote_timeout,
                        max_items=remote_max_items,
                    )
                for cve_id in remote_candidates:
                    if cve_id not in cves:
                        cves.append(cve_id)
            if not cves and not cpe:
                continue
            for cve_id in cves:
                normalized = str(cve_id).upper()
                if normalized not in epss_cache:
                    if proxy_url:
                        epss_cache[normalized] = fetch_epss_score(
                            normalized,
                            timeout_seconds=epss_timeout,
                            proxy_url=proxy_url,
                        )
                    else:
                        epss_cache[normalized] = fetch_epss_score(normalized, timeout_seconds=epss_timeout)
            prioritized = prioritize_cves(cves, epss_cache, kev_set)
            candidates.append(
                {
                    "entity_type": "service",
                    "entity_id": service.service_id,
                    "asset_id": service.asset_id,
                    "source": service.name or "service",
                    "cpe": cpe,
                    "cves": cves,
                    "prioritized": prioritized,
                }
            )

        for technology in run_data.technologies:
            if cancellation_requested(context):
                result.warnings.append("CVE enrichment cancelled by scheduler before all technologies were processed")
                break
            enriched = enrich_technology_signature(technology.name, technology.version)
            cves: list[str] = list(enriched.get("cves", [])) if enriched else []
            cpe = enriched.get("cpe") if enriched else None
            if remote_enabled:
                remote_keyword = " ".join([technology.name or "", technology.version or ""]).strip()
                if proxy_url:
                    remote_candidates = fetch_cve_candidates(
                        remote_keyword,
                        timeout_seconds=remote_timeout,
                        max_items=remote_max_items,
                        proxy_url=proxy_url,
                    )
                else:
                    remote_candidates = fetch_cve_candidates(
                        remote_keyword,
                        timeout_seconds=remote_timeout,
                        max_items=remote_max_items,
                    )
                for cve_id in remote_candidates:
                    if cve_id not in cves:
                        cves.append(cve_id)
            if not cves and not cpe:
                continue
            for cve_id in cves:
                normalized = str(cve_id).upper()
                if normalized not in epss_cache:
                    if proxy_url:
                        epss_cache[normalized] = fetch_epss_score(
                            normalized,
                            timeout_seconds=epss_timeout,
                            proxy_url=proxy_url,
                        )
                    else:
                        epss_cache[normalized] = fetch_epss_score(normalized, timeout_seconds=epss_timeout)
            prioritized = prioritize_cves(cves, epss_cache, kev_set)
            candidates.append(
                {
                    "entity_type": "asset",
                    "entity_id": technology.asset_id,
                    "asset_id": technology.asset_id,
                    "source": technology.name,
                    "cpe": cpe,
                    "cves": cves,
                    "prioritized": prioritized,
                }
            )

        if not candidates:
            ended_at = now_utc()
            result.facts["cve_enricher.candidate_count"] = 0
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="local cpe/cve enrichment",
                    started_at=started_at,
                    ended_at=ended_at,
                    status="completed",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=0,
                )
            )
            return result

        artifact_path = context.run_store.artifact_path(self.name, "cve_candidates.json")
        artifact_path.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
        evidence = Evidence(
            evidence_id=new_id("evidence"),
            source_tool=self.name,
            kind="cve_enrichment",
            snippet=f"{len(candidates)} cpe/cve candidate mappings identified",
            artifact_path=str(artifact_path),
            selector={"kind": "json", "items": len(candidates)},
            source_execution_id=execution_id,
            parser_version="cve_enricher_v1",
            confidence=0.7,
        )
        result.evidence.append(evidence)

        for candidate in candidates:
            cpe = candidate.get("cpe")
            cves = candidate.get("cves", [])
            prioritized = candidate.get("prioritized", [])
            if cpe:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="vuln.cpe.candidate",
                        value=str(cpe),
                        entity_type=str(candidate["entity_type"]),
                        entity_id=str(candidate["entity_id"]),
                        source_tool=self.name,
                        confidence=0.7,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="cve_enricher_v1",
                    )
                )
            if cves:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="vuln.cve.candidates",
                        value=[str(item) for item in cves],
                        entity_type=str(candidate["entity_type"]),
                        entity_id=str(candidate["entity_id"]),
                        source_tool=self.name,
                        confidence=0.65,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="cve_enricher_v1",
                    )
                )
            if prioritized:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="vuln.cve.prioritized",
                        value=prioritized,
                        entity_type=str(candidate["entity_type"]),
                        entity_id=str(candidate["entity_id"]),
                        source_tool=self.name,
                        confidence=0.7,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="cve_enricher_v2",
                    )
                )
                top_item = prioritized[0]
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="vuln.cve.top_priority",
                        value=top_item,
                        entity_type=str(candidate["entity_type"]),
                        entity_id=str(candidate["entity_id"]),
                        source_tool=self.name,
                        confidence=0.68,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="cve_enricher_v2",
                    )
                )

        ended_at = now_utc()
        result.facts["cve_enricher.candidate_count"] = len(candidates)
        result.facts["cve_enricher.asset_count"] = len(
            {str(item.get("asset_id")) for item in candidates if item.get("asset_id")}
        )
        result.facts["cve_enricher.backend"] = backend
        result.facts["cve_enricher.kev_count"] = len(kev_set)
        result.facts["cve_enricher.epss_cached"] = {
            key: value for key, value in epss_cache.items() if value is not None
        }
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="local cpe/cve enrichment",
                started_at=started_at,
                ended_at=ended_at,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "candidate_count": len(candidates),
            },
        )
        return result
