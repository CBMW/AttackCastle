from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attackcastle.core.enums import Severity
from attackcastle.core.models import Finding, RunData, new_id
from attackcastle.findings.matcher import (
    build_observation_index,
    match_entities_for_template,
    select_observations_for_entity,
)
from attackcastle.findings.schema import load_templates, validate_template
from attackcastle.quality.evidence import summarize_evidence_quality


class FindingsEngine:
    def __init__(
        self,
        template_dir: Path,
        minimum_confidence: float = 0.6,
        severity_overlays: dict[str, str] | None = None,
        suppression_file: Path | None = None,
        minimum_evidence_completeness: float = 0.8,
        enforce_evidence_for_severities: list[str] | None = None,
        templates: list[dict[str, Any]] | None = None,
    ) -> None:
        self.template_dir = template_dir
        self.templates = templates
        self.minimum_confidence = minimum_confidence
        self.severity_overlays = severity_overlays or {}
        self.suppression_file = suppression_file
        self.minimum_evidence_completeness = minimum_evidence_completeness
        self.enforce_evidence_for_severities = {
            item.lower() for item in (enforce_evidence_for_severities or ["low", "medium", "high", "critical"])
        }
        self._suppressions = self._load_suppressions()

    def _load_suppressions(self) -> list[dict[str, Any]]:
        if not self.suppression_file or not self.suppression_file.exists():
            return []
        try:
            payload = json.loads(self.suppression_file.read_text(encoding="utf-8"))
        except Exception:
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def _severity_from_text(self, value: str) -> Severity:
        try:
            return Severity(value.lower())
        except ValueError:
            return Severity.INFO

    def _apply_severity_policy(self, template_id: str, template_severity: str) -> Severity:
        override = self.severity_overlays.get(template_id, template_severity)
        return self._severity_from_text(override)

    def _collect_evidence_ids(
        self,
        run_data: RunData,
        entity_type: str,
        entity_id: str,
        keys: list[str],
        min_items: int,
    ) -> tuple[list[str], list[str]]:
        observations = select_observations_for_entity(run_data, entity_type, entity_id, keys)
        evidence_ids: list[str] = []
        observation_ids: list[str] = []
        for observation in observations:
            if observation.confidence < self.minimum_confidence:
                continue
            observation_ids.append(observation.observation_id)
            for evidence_id in observation.evidence_ids:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        if len(evidence_ids) < min_items:
            return [], observation_ids
        return evidence_ids, observation_ids

    def _is_suppressed(self, template_id: str, entity_type: str, entity_id: str) -> tuple[bool, str | None]:
        now = datetime.now(timezone.utc)
        for suppression in self._suppressions:
            if suppression.get("template_id") not in {template_id, "*"}:
                continue
            if suppression.get("entity_type") not in {entity_type, "*"}:
                continue
            if suppression.get("entity_id") not in {entity_id, "*"}:
                continue
            expires_at = suppression.get("expires_at")
            if expires_at:
                parsed = expires_at.replace("Z", "+00:00")
                try:
                    expiry_dt = datetime.fromisoformat(parsed)
                except ValueError:
                    continue
                if expiry_dt < now:
                    continue
            return True, suppression.get("reason")
        return False, None

    def _fingerprint(
        self, template_id: str, entity_type: str, entity_id: str, evidence_ids: list[str]
    ) -> str:
        material = "|".join(
            [template_id, entity_type, entity_id, ",".join(sorted(evidence_ids))]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _collect_entity_observations(self, run_data: RunData, entity_type: str, entity_id: str) -> list:
        return [
            observation
            for observation in run_data.observations
            if observation.entity_type == entity_type and observation.entity_id == entity_id
        ]

    def _evaluate_corroboration(
        self,
        run_data: RunData,
        template: dict[str, Any],
        entity_type: str,
        entity_id: str,
    ) -> tuple[bool, dict[str, Any], list[str]]:
        rule = template.get("corroboration", {})
        min_observations = int(rule.get("min_observations", 1))
        min_distinct_sources = int(rule.get("min_distinct_sources", 1))
        min_confidence = float(rule.get("min_confidence", self.minimum_confidence))
        required_assertions = [str(item) for item in rule.get("required_assertions", [])]

        observations = self._collect_entity_observations(run_data, entity_type, entity_id)
        qualified = [obs for obs in observations if obs.confidence >= min_confidence]
        distinct_sources = sorted({obs.source_tool for obs in qualified})
        assertion_keys = {
            assertion.key
            for assertion in run_data.assertions
            for ref in assertion.entity_refs
            if ref.get("entity_type") == entity_type and ref.get("entity_id") == entity_id
        }

        missing_notes: list[str] = []
        if len(qualified) < min_observations:
            missing_notes.append(
                f"corroboration: requires {min_observations} observations >= confidence {min_confidence}"
            )
        if len(distinct_sources) < min_distinct_sources:
            missing_notes.append(
                f"corroboration: requires {min_distinct_sources} distinct sources"
            )
        if required_assertions:
            missing_assertions = [key for key in required_assertions if key not in assertion_keys]
            if missing_assertions:
                missing_notes.append(
                    "corroboration: missing assertions " + ", ".join(missing_assertions)
                )

        corroboration = {
            "qualified_observations": len(qualified),
            "distinct_sources": distinct_sources,
            "required_assertions": required_assertions,
        }
        return len(missing_notes) == 0, corroboration, missing_notes

    def _evaluate_evidence_bundle(
        self, run_data: RunData, evidence_ids: list[str]
    ) -> tuple[float, list[str], dict[str, Any]]:
        evidence_lookup = {evidence.evidence_id: evidence for evidence in run_data.evidence}
        items = [evidence_lookup[evidence_id] for evidence_id in evidence_ids if evidence_id in evidence_lookup]
        summary = summarize_evidence_quality(items)
        notes: list[str] = []
        if not items:
            notes.append("evidence: no evidence records attached")
            return 0.0, notes, summary
        if summary["average_score"] < self.minimum_evidence_completeness:
            notes.append(
                f"evidence: average quality {summary['average_score']:.2f} below threshold {self.minimum_evidence_completeness:.2f}"
            )
        if summary["valid_count"] < 1:
            notes.append("evidence: no fully qualified evidence entries")
        return float(summary["average_score"]), notes, summary

    def _final_status(
        self,
        severity: Severity,
        corroboration_passed: bool,
        evidence_quality_score: float,
        evidence_notes: list[str],
        corroboration_notes: list[str],
    ) -> tuple[str, list[str]]:
        notes = list(corroboration_notes) + list(evidence_notes)
        enforce = severity.value in self.enforce_evidence_for_severities
        if corroboration_passed and (not enforce or evidence_quality_score >= self.minimum_evidence_completeness):
            return "confirmed", notes
        return "candidate", notes

    def _load_templates(self) -> list[dict[str, Any]]:
        if self.templates is not None:
            return [dict(item) for item in self.templates]
        return load_templates(self.template_dir)

    def generate(self, run_data: RunData) -> list[Finding]:
        templates = self._load_templates()
        generated: list[Finding] = []
        dedupe_fingerprints = {finding.fingerprint for finding in run_data.findings if finding.fingerprint}
        observation_index = build_observation_index(run_data)
        telemetry = {
            "confirmed": 0,
            "candidate": 0,
            "suppressed": 0,
            "skipped_evidence": 0,
        }

        for template in templates:
            if template.get("abstract") is True:
                continue
            if template.get("enabled") is False:
                continue
            if isinstance(template.get("detection"), dict):
                continue
            try:
                validate_template(template)
            except Exception as exc:  # noqa: BLE001
                run_data.warnings.append(
                    f"Template validation failed for {template.get('id', 'unknown')}: {exc}"
                )
                continue

            trigger = template["trigger"]
            entity_type = trigger["entity_type"]
            matched_entity_ids = match_entities_for_template(template, observation_index)
            evidence_rules = template.get("evidence_requirements", {})
            evidence_keys = evidence_rules.get("keys", [])
            min_items = int(evidence_rules.get("min_items", 0))

            for entity_id in matched_entity_ids:
                evidence_ids, observation_ids = self._collect_evidence_ids(
                    run_data=run_data,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    keys=evidence_keys,
                    min_items=min_items,
                )
                if min_items > 0 and len(evidence_ids) < min_items:
                    telemetry["skipped_evidence"] += 1
                    continue

                severity = self._apply_severity_policy(template["id"], template["severity"])
                suppressed, suppression_reason = self._is_suppressed(
                    template_id=template["id"],
                    entity_type=entity_type,
                    entity_id=entity_id,
                )

                corroboration_passed, corroboration, corroboration_notes = self._evaluate_corroboration(
                    run_data=run_data,
                    template=template,
                    entity_type=entity_type,
                    entity_id=entity_id,
                )
                evidence_quality_score, evidence_notes, evidence_summary = self._evaluate_evidence_bundle(
                    run_data,
                    evidence_ids,
                )

                status, quality_notes = self._final_status(
                    severity=severity,
                    corroboration_passed=corroboration_passed,
                    evidence_quality_score=evidence_quality_score,
                    evidence_notes=evidence_notes,
                    corroboration_notes=corroboration_notes,
                )
                if suppressed:
                    status = "suppressed"
                    telemetry["suppressed"] += 1
                elif status == "candidate":
                    telemetry["candidate"] += 1
                else:
                    telemetry["confirmed"] += 1

                fingerprint = self._fingerprint(
                    template_id=template["id"],
                    entity_type=entity_type,
                    entity_id=entity_id,
                    evidence_ids=evidence_ids,
                )
                if fingerprint in dedupe_fingerprints:
                    continue
                dedupe_fingerprints.add(fingerprint)

                finding = Finding(
                    finding_id=new_id("finding"),
                    template_id=template["id"],
                    title=template["title"],
                    severity=severity,
                    category=template["category"],
                    description=template["description"],
                    impact=template["impact"],
                    likelihood=template["likelihood"],
                    recommendations=template.get("recommendations", []),
                    references=template.get("references", []),
                    tags=template.get("tags", []),
                    affected_entities=[{"entity_type": entity_type, "entity_id": entity_id}],
                    evidence_ids=evidence_ids,
                    plextrac=template.get("plextrac", {}),
                    fingerprint=fingerprint,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason,
                    status=status,
                    evidence_quality_score=evidence_quality_score,
                    corroboration={
                        **corroboration,
                        "observation_ids": observation_ids,
                        "evidence_summary": evidence_summary,
                    },
                    quality_notes=quality_notes,
                )
                generated.append(finding)

        run_data.findings.extend(generated)
        run_data.facts["findings.telemetry"] = telemetry
        return generated
