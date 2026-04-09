from __future__ import annotations

from copy import deepcopy
from typing import Any

from attackcastle.core.models import SCHEMA_VERSION


def migrate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(payload)
    metadata = migrated.setdefault("metadata", {})
    current_version = metadata.get("schema_version", "1.0.0")
    if current_version.startswith("1."):
        metadata.setdefault("state", "created")
        metadata.setdefault("audience", "client")
        metadata["schema_version"] = SCHEMA_VERSION
        migrated.setdefault("assertions", [])
        migrated.setdefault("state_history", [])
        migrated.setdefault("alias_map", {})
        for evidence in migrated.get("evidence", []):
            evidence.setdefault("selector", {})
            evidence.setdefault("evidence_hash", None)
        for observation in migrated.get("observations", []):
            observation.setdefault("derived_from", [])
            observation.setdefault("source_execution_id", None)
            observation.setdefault("parser_version", None)
    metadata["schema_version"] = SCHEMA_VERSION
    for evidence in migrated.get("evidence", []):
        evidence.setdefault("selector", {})
        evidence.setdefault("evidence_hash", None)
        evidence.setdefault("source_execution_id", None)
        evidence.setdefault("parser_version", None)
        evidence.setdefault("confidence", 1.0)
    for finding in migrated.get("findings", []):
        finding.setdefault("status", "confirmed")
        finding.setdefault("evidence_quality_score", 0.0)
        finding.setdefault("corroboration", {})
        finding.setdefault("quality_notes", [])
    for lead in migrated.get("leads", []):
        lead.setdefault("status", "manual-review")
        lead.setdefault("confidence", 0.7)
        lead.setdefault("why_it_matters", "")
        lead.setdefault("reasoning", "")
        lead.setdefault("suggested_next_steps", [])
        lead.setdefault("likely_finding", None)
        lead.setdefault("likely_severity", None)
        lead.setdefault("draft_finding_seed", None)
        lead.setdefault("tags", [])
        lead.setdefault("affected_entities", [])
        lead.setdefault("evidence_ids", [])
        lead.setdefault("source_observation_ids", [])
        lead.setdefault("detection_sources", [])
    for bundle in migrated.get("evidence_bundles", []):
        bundle.setdefault("asset_id", None)
        bundle.setdefault("summary", "")
        bundle.setdefault("confidence", 0.0)
        bundle.setdefault("evidence_ids", [])
        bundle.setdefault("artifact_paths", [])
        bundle.setdefault("screenshot_paths", [])
        bundle.setdefault("raw_output_paths", [])
        bundle.setdefault("source_tools", [])
    migrated.setdefault("leads", [])
    migrated.setdefault("evidence_bundles", [])
    migrated.setdefault("normalized_entities", [])
    migrated.setdefault("evidence_artifacts", [])
    migrated.setdefault("task_results", [])
    migrated.setdefault("facts", {})
    return migrated
