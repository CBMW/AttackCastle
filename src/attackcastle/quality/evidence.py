from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackcastle.core.models import Evidence


@dataclass
class EvidenceQuality:
    evidence_id: str
    score: float
    missing: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)


def evaluate_evidence(evidence: Evidence) -> EvidenceQuality:
    artifact_non_empty = True
    if evidence.artifact_path:
        try:
            artifact = Path(evidence.artifact_path)
            if artifact.exists() and artifact.is_file():
                artifact_non_empty = artifact.stat().st_size > 0
        except Exception:
            artifact_non_empty = True
    snippet_text = (evidence.snippet or "").strip().lower()
    non_redirect_proof = True
    if evidence.kind in {"http_response", "web_vuln_scan", "web_template_scan"}:
        redirect_tokens = ("301 moved", "302 found", "307 temporary", "308 permanent", "location:")
        non_redirect_proof = not any(token in snippet_text for token in redirect_tokens)
    checks = {
        "source_tool": bool(evidence.source_tool),
        "source_execution_id": bool(evidence.source_execution_id),
        "artifact_path": bool(evidence.artifact_path),
        "artifact_non_empty": artifact_non_empty,
        "timestamp": evidence.timestamp is not None,
        "confidence": evidence.confidence is not None and evidence.confidence >= 0.0,
        "snippet": bool((evidence.snippet or "").strip()),
        "non_redirect_proof": non_redirect_proof,
    }
    passed = sum(1 for value in checks.values() if value)
    score = passed / float(len(checks))
    missing = [key for key, passed_value in checks.items() if not passed_value]
    return EvidenceQuality(
        evidence_id=evidence.evidence_id,
        score=score,
        missing=missing,
        checks=checks,
    )


def summarize_evidence_quality(evidence_items: list[Evidence]) -> dict[str, Any]:
    if not evidence_items:
        return {
            "average_score": 0.0,
            "max_score": 0.0,
            "min_score": 0.0,
            "items": [],
            "valid_count": 0,
        }
    evaluations = [evaluate_evidence(item) for item in evidence_items]
    scores = [evaluation.score for evaluation in evaluations]
    return {
        "average_score": sum(scores) / len(scores),
        "max_score": max(scores),
        "min_score": min(scores),
        "items": [
            {
                "evidence_id": evaluation.evidence_id,
                "score": evaluation.score,
                "missing": evaluation.missing,
            }
            for evaluation in evaluations
        ],
        "valid_count": sum(1 for evaluation in evaluations if evaluation.score >= 0.8),
    }
