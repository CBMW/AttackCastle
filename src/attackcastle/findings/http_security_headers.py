from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from attackcastle.core.enums import Severity
from attackcastle.core.models import Finding, RunData, new_id
from attackcastle.findings.schema import load_templates
from attackcastle.quality.evidence import summarize_evidence_quality

TEMPLATE_ID = "HTTP_HEADER_MISCONFIGURATION"


def generate_http_security_header_finding(run_data: RunData, *, template_dir: Path) -> list[Finding]:
    analyses = _collect_analyses(run_data)
    affected = [item for item in analyses if item["analysis"].get("trigger_finding")]
    if not affected:
        return []

    template = _load_template(template_dir)
    evidence_lookup = {item.evidence_id: item for item in run_data.evidence}
    evidence_ids = _unique(
        evidence_id
        for item in affected
        for evidence_id in item["observation"].evidence_ids
        if evidence_id in evidence_lookup
    )
    evidence_items = [evidence_lookup[evidence_id] for evidence_id in evidence_ids]
    evidence_quality = summarize_evidence_quality(evidence_items)
    affected_entities = _unique_entity_refs(
        (item["entity_type"], item["entity_id"]) for item in affected
    )
    affected_targets = [
        {
            "url": str(item["analysis"].get("url") or ""),
            "status_code": item["analysis"].get("status_code"),
            "core_missing": list(item["analysis"].get("core_missing", [])),
            "core_weak": list(item["analysis"].get("core_weak", [])),
        }
        for item in affected
    ]
    fingerprint = _fingerprint(affected_entities, affected_targets)
    if any(str(existing.fingerprint or "") == fingerprint for existing in run_data.findings):
        return []

    finding = Finding(
        finding_id=new_id("finding"),
        template_id=TEMPLATE_ID,
        title=str(template.get("title") or "HTTP Header Response Misconfiguration"),
        severity=Severity(str(template.get("severity") or "low").lower()),
        category=str(template.get("category") or "Web Security Misconfiguration"),
        description=str(template.get("description") or ""),
        impact=str(template.get("impact") or ""),
        likelihood=str(template.get("likelihood") or "low"),
        recommendations=[str(item) for item in template.get("recommendations", [])],
        references=[str(item) for item in template.get("references", [])],
        tags=[str(item) for item in template.get("tags", [])],
        affected_entities=affected_entities,
        evidence_ids=evidence_ids,
        plextrac=dict(template.get("plextrac", {})),
        fingerprint=fingerprint,
        status="confirmed" if evidence_quality["average_score"] >= 0.8 else "candidate",
        evidence_quality_score=float(evidence_quality["average_score"]),
        corroboration={
            "qualified_observations": len(affected),
            "distinct_sources": sorted({item["observation"].source_tool for item in affected}),
            "observation_ids": [item["observation"].observation_id for item in affected],
            "evidence_summary": evidence_quality,
            "affected_targets": affected_targets,
        },
        quality_notes=[],
    )
    run_data.findings.append(finding)
    return [finding]


def _collect_analyses(run_data: RunData) -> list[dict[str, Any]]:
    analyses: list[dict[str, Any]] = []
    for observation in run_data.observations:
        if observation.key != "web.http_security_headers.analysis":
            continue
        if not isinstance(observation.value, dict):
            continue
        analyses.append(
            {
                "entity_type": observation.entity_type,
                "entity_id": observation.entity_id,
                "observation": observation,
                "analysis": observation.value,
            }
        )
    analyses.sort(key=lambda item: str(item["analysis"].get("url") or ""))
    return analyses


def _load_template(template_dir: Path) -> dict[str, Any]:
    for template in load_templates(template_dir):
        if template.get("id") == TEMPLATE_ID:
            return template
    raise KeyError(f"Template '{TEMPLATE_ID}' not found")


def _unique(values) -> list[str]:  # noqa: ANN001
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _unique_entity_refs(values) -> list[dict[str, str]]:  # noqa: ANN001
    ordered: list[dict[str, str]] = []
    seen: set[str] = set()
    for entity_type, entity_id in values:
        normalized = f"{entity_type}:{entity_id}"
        if not entity_type or not entity_id or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append({"entity_type": entity_type, "entity_id": entity_id})
    return ordered


def _fingerprint(affected_entities: list[dict[str, str]], affected_targets: list[dict[str, Any]]) -> str:
    material = "|".join(
        [
            TEMPLATE_ID,
            ",".join(sorted(f"{item['entity_type']}:{item['entity_id']}" for item in affected_entities)),
            ",".join(sorted(str(item.get("url") or "") for item in affected_targets)),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
