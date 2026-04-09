from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from attackcastle.core.execution_issues import build_execution_issues, summarize_execution_issues
from attackcastle.core.models import RunData, iso, now_utc, to_serializable
from attackcastle.reporting.audience import is_consultant_audience, normalize_report_audience
from attackcastle.scope.compiler import classify_cloud_provider

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 1}
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}
WEAK_TLS_PROTOCOLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


def _read_text_snippet(path_value: str | None, max_chars: int = 3000) -> str | None:
    if not path_value:
        return None
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="ignore")
        if len(text) > max_chars:
            return text[:max_chars] + "\n...[truncated]"
        return text
    except Exception:
        return None


def _read_text_full(path_value: str | None, max_chars: int = 20000) -> str | None:
    return _read_text_snippet(path_value, max_chars=max_chars)


def _read_artifact_content(path_value: str | None, max_chars: int = 24000) -> dict[str, Any]:
    if not path_value:
        return {"text": None, "truncated": False}
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return {"text": None, "truncated": False}
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {"text": None, "truncated": False}
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars] + "\n...[truncated]"
    return {"text": text, "truncated": truncated}


def _parse_key_value_artifact(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    parsed: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in text.splitlines():
        if in_body:
            body_lines.append(line)
            continue
        if line.startswith("body="):
            body_lines.append(line[len("body=") :])
            in_body = True
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key.strip()] = value
            continue
        body_lines.append(line)
    if body_lines:
        parsed["body"] = "\n".join(body_lines).strip()
    return parsed


def _format_request_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.hostname or "-"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: AttackCastle web probe",
        "Accept: */*",
        "Connection: close",
    ]
    return "\n".join(request_lines)


def _format_response_from_http_artifact(parsed: dict[str, str]) -> str:
    status = parsed.get("status") or "-"
    final_url = parsed.get("final_url") or parsed.get("url") or "-"
    header_text = parsed.get("headers", "")
    header_lines: list[str] = []
    if header_text:
        for item in header_text.split(";"):
            cleaned = item.strip()
            if cleaned:
                header_lines.append(cleaned)
    body = parsed.get("body", "")
    parts = [f"HTTP {status}", f"Final-URL: {final_url}"]
    if header_lines:
        parts.extend(header_lines)
    if body:
        parts.extend(["", body])
    return "\n".join(parts)


def _format_terminal_text(text: str | None) -> str:
    return text or "(no captured output)"


def _command_hash(command: str) -> str:
    return hashlib.sha1((command or "").encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _hash_file(path_value: str | None) -> str | None:
    if not path_value:
        return None
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def _severity_counts(run_data: RunData) -> dict[str, int]:
    counts = Counter(
        finding.severity.value
        for finding in run_data.findings
        if not finding.suppressed and finding.status == "confirmed"
    )
    return {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER}


def _is_ip_value(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
    return True


def _root_domain_hint(hostname: str | None) -> str | None:
    if not hostname or _is_ip_value(hostname):
        return None
    parts = [item for item in str(hostname).lower().strip(".").split(".") if item]
    if len(parts) < 2:
        return parts[0] if parts else None
    return ".".join(parts[-2:])


def _netblock_hint(ip_value: str | None) -> str | None:
    if not ip_value or not _is_ip_value(ip_value):
        return None
    parts = ip_value.split(".")
    return ".".join(parts[:3]) + ".0/24"


def _risk_score_raw(severity_counts: dict[str, int]) -> int:
    return sum(SEVERITY_WEIGHTS.get(severity, 0) * count for severity, count in severity_counts.items())


def _risk_score_100(raw_score: int) -> int:
    if raw_score <= 0:
        return 0
    return int(round(min(100.0, (raw_score / (raw_score + 40.0)) * 100.0)))


def _risk_grade(score_100: int) -> str:
    if score_100 <= 10:
        return "A"
    if score_100 <= 25:
        return "B"
    if score_100 <= 45:
        return "C"
    if score_100 <= 70:
        return "D"
    return "F"


def _average(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _finding_domain(finding: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(finding.get("template_id", "")),
            str(finding.get("category", "")),
            " ".join(str(item) for item in finding.get("tags", [])),
            str(finding.get("title", "")),
        ]
    ).lower()
    if any(token in text for token in ("tls", "ssl", "cipher", "certificate")):
        return "tls"
    if any(token in text for token in ("http", "wordpress", "web", "header", "form", "cookie")):
        return "web"
    if any(token in text for token in ("dns", "domain", "resolve")):
        return "dns"
    if any(token in text for token in ("smtp", "imap", "pop3", "mail")):
        return "email"
    if any(token in text for token in ("port", "service", "network", "exposed")):
        return "network"
    return "hygiene"


def _service_exposure_breakdown(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter()
    for service in services:
        port = int(service.get("port", 0))
        name = (service.get("name") or "").lower()
        if port in {80, 443, 8080, 8443} or name in {"http", "https"}:
            counts["web"] += 1
        elif port in {22, 23, 3389, 5900}:
            counts["remote_admin"] += 1
        elif port in {1433, 3306, 5432, 6379, 27017}:
            counts["database"] += 1
        elif port in {25, 110, 143, 465, 587, 993, 995}:
            counts["mail"] += 1
        else:
            counts["other"] += 1
    return [{"category": key, "count": counts.get(key, 0)} for key in ("web", "remote_admin", "database", "mail", "other")]


def _build_execution_rows(run_data: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for execution in run_data.tool_executions:
        rows.append(
            {
                "execution_id": execution.execution_id,
                "tool_name": execution.tool_name,
                "command": execution.command,
                "command_hash": _command_hash(execution.command),
                "capability": execution.capability,
                "status": execution.status,
                "exit_code": execution.exit_code,
                "started_at": iso(execution.started_at),
                "ended_at": iso(execution.ended_at),
                "duration_seconds": round(
                    max((execution.ended_at - execution.started_at).total_seconds(), 0.0),
                    3,
                ),
                "stdout_path": execution.stdout_path,
                "stderr_path": execution.stderr_path,
                "transcript_path": execution.transcript_path,
                "stdout_snippet": _read_text_snippet(execution.stdout_path),
                "stderr_snippet": _read_text_snippet(execution.stderr_path),
                "transcript_text": _read_text_full(execution.transcript_path, max_chars=1_000_000_000),
                "stdout_text": _read_text_full(execution.stdout_path, max_chars=16000),
                "stderr_text": _read_text_full(execution.stderr_path, max_chars=16000),
                "raw_artifact_paths": execution.raw_artifact_paths,
                "raw_artifacts": [
                    {
                        "path": path_value,
                        "content": _read_artifact_content(path_value).get("text"),
                    }
                    for path_value in execution.raw_artifact_paths
                ],
                "error_message": execution.error_message,
                "termination_reason": execution.termination_reason,
                "termination_detail": execution.termination_detail,
                "timed_out": execution.timed_out,
            }
        )
    return rows


def _build_evidence_detail(
    evidence: Any,
    execution_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    artifact_info = _read_artifact_content(evidence.artifact_path)
    artifact_text = artifact_info.get("text")
    execution = execution_lookup.get(str(evidence.source_execution_id), {})
    suffix = Path(evidence.artifact_path).suffix.lower() if evidence.artifact_path else ""
    presentation: dict[str, Any] = {
        "mode": "terminal",
        "title": evidence.kind,
        "request_text": "",
        "request_note": "",
        "response_text": "",
        "terminal_text": _format_terminal_text(artifact_text or evidence.snippet),
        "artifact_text": artifact_text,
    }

    if evidence.kind in {"http_response", "web_auxiliary_path"}:
        parsed = _parse_key_value_artifact(artifact_text)
        request_url = parsed.get("url") or parsed.get("final_url") or evidence.snippet
        presentation.update(
            {
                "mode": "http",
                "request_text": _format_request_from_url(request_url),
                "request_note": "Request reconstructed from stored probe metadata.",
                "response_text": _format_response_from_http_artifact(parsed),
                "terminal_text": "",
            }
        )
    elif evidence.kind == "web_screenshot":
        presentation.update(
            {
                "mode": "screenshot",
                "image_path": evidence.artifact_path,
                "terminal_text": "",
            }
        )
    elif suffix in {".json", ".jsonl"}:
        pretty_text = artifact_text
        if artifact_text:
            try:
                loaded = json.loads(artifact_text)
                pretty_text = json.dumps(loaded, indent=2)
            except Exception:
                pretty_text = artifact_text
        presentation.update(
            {
                "mode": "json",
                "terminal_text": _format_terminal_text(pretty_text),
            }
        )
    elif suffix in {".xml"}:
        presentation.update({"mode": "xml"})

    return {
        "evidence_id": evidence.evidence_id,
        "source_tool": evidence.source_tool,
        "kind": evidence.kind,
        "snippet": evidence.snippet,
        "artifact_path": evidence.artifact_path,
        "source_execution_id": evidence.source_execution_id,
        "confidence": evidence.confidence,
        "timestamp": iso(evidence.timestamp),
        "selector": evidence.selector,
        "execution": execution,
        "presentation": presentation,
    }


def _build_finding_rows(
    run_data: RunData,
    execution_lookup: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_lookup = {evidence.evidence_id: evidence for evidence in run_data.evidence}
    rows_confirmed: list[dict[str, Any]] = []
    rows_candidate: list[dict[str, Any]] = []
    for finding in run_data.findings:
        if finding.suppressed:
            continue
        evidence_rows = []
        for evidence_id in finding.evidence_ids[:10]:
            evidence = evidence_lookup.get(evidence_id)
            if not evidence:
                continue
            evidence_rows.append(_build_evidence_detail(evidence, execution_lookup))
        confidence_score = _average([float(item.get("confidence", 0.0)) for item in evidence_rows])
        corroboration = finding.corroboration or {}
        corroboration_count = int(corroboration.get("qualified_observations", 0))
        distinct_sources = len(corroboration.get("distinct_sources", []))
        proof = evidence_rows[0] if evidence_rows else None
        row = {
            "finding_id": finding.finding_id,
            "template_id": finding.template_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "status": finding.status,
            "category": finding.category,
            "description": finding.description,
            "impact": finding.impact,
            "likelihood": finding.likelihood,
            "recommendations": finding.recommendations,
            "references": finding.references,
            "tags": finding.tags,
            "affected_entities": finding.affected_entities,
            "evidence": evidence_rows,
            "evidence_quality_score": finding.evidence_quality_score,
            "quality_notes": finding.quality_notes,
            "corroboration": finding.corroboration,
            "confidence_score": confidence_score,
            "corroboration_count": corroboration_count,
            "distinct_sources": distinct_sources,
            "proof": proof,
            "evidence_count": len(evidence_rows),
        }
        if finding.status == "confirmed":
            rows_confirmed.append(row)
        else:
            rows_candidate.append(row)
    rows_confirmed.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 99), -item["evidence_quality_score"]))
    rows_candidate.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 99), -item["evidence_quality_score"]))
    return rows_confirmed, rows_candidate


def _build_risk_domains(
    confirmed_findings: list[dict[str, Any]],
    services: list[dict[str, Any]],
    tls_assets: list[dict[str, Any]],
    warnings: list[str],
    errors: list[str],
    candidate_count: int,
) -> list[dict[str, Any]]:
    raw = {"network": 0.0, "web": 0.0, "tls": 0.0, "email": 0.0, "dns": 0.0, "hygiene": 0.0}
    for finding in confirmed_findings:
        severity = finding.get("severity", "info")
        weight = float(SEVERITY_WEIGHTS.get(severity, 1))
        domain = _finding_domain(finding)
        raw[domain] += weight * 1.5

    for service in services:
        port = int(service.get("port", 0))
        name = (service.get("name") or "").lower()
        raw["network"] += 0.6
        if port in {22, 3389, 445, 1433, 3306, 5432, 6379, 9200}:
            raw["network"] += 1.6
        if port in {80, 443, 8080, 8443} or name in {"http", "https"}:
            raw["web"] += 1.0
        if port in {25, 110, 143, 465, 587, 993, 995} or name in {"smtp", "imap", "pop3"}:
            raw["email"] += 1.2

    for tls in tls_assets:
        protocol = str(tls.get("protocol", "")).lower()
        raw["tls"] += 1.2
        if protocol in WEAK_TLS_PROTOCOLS:
            raw["tls"] += 3.0

    raw["hygiene"] += float(len(warnings) * 0.8 + len(errors) * 1.5 + candidate_count * 0.4)
    normalized = {key: min(100, int(round(value * 6.0))) for key, value in raw.items()}
    return [
        {"domain": domain, "score": normalized[domain], "raw": round(raw[domain], 2)}
        for domain in ("network", "web", "tls", "email", "dns", "hygiene")
    ]


def _build_remediation_plan(confirmed_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    owner_by_domain = {
        "web": "Application Security",
        "tls": "Infrastructure",
        "network": "Infrastructure",
        "dns": "Network Engineering",
        "email": "Messaging Team",
        "hygiene": "Security Operations",
    }
    effort_points = {"low": 2, "medium": 5, "high": 8}
    effort_by_severity = {"critical": "high", "high": "medium", "medium": "medium", "low": "low", "info": "low"}
    window_by_severity = {
        "critical": "Now (7 days)",
        "high": "30 days",
        "medium": "60 days",
        "low": "90 days",
        "info": "Backlog",
    }
    rows: list[dict[str, Any]] = []
    for finding in confirmed_findings:
        severity = str(finding.get("severity", "info"))
        domain = _finding_domain(finding)
        effort = effort_by_severity.get(severity, "medium")
        reduction = float(SEVERITY_WEIGHTS.get(severity, 1) * 10) * max(
            float(finding.get("confidence_score", 0.7)),
            0.5,
        )
        effort_cost = effort_points[effort]
        priority_index = round(reduction / effort_cost, 2)
        action = (
            finding.get("recommendations", [None])[0]
            or f"Remediate finding: {finding.get('title', 'Untitled')}"
        )
        rows.append(
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "domain": domain,
                "severity": severity,
                "action": action,
                "owner": owner_by_domain.get(domain, "Security Team"),
                "effort": effort,
                "effort_points": effort_cost,
                "risk_reduction_points": round(reduction, 2),
                "priority_index": priority_index,
                "target_window": window_by_severity.get(severity, "90 days"),
            }
        )
    rows.sort(key=lambda item: (-item["priority_index"], SEVERITY_RANK.get(item["severity"], 99)))
    return rows


def _build_asset_exposure_matrix(
    run_data: RunData,
    confirmed_findings: list[dict[str, Any]],
    services: list[dict[str, Any]],
    web_apps: list[dict[str, Any]],
    technologies: list[dict[str, Any]],
    tls_assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    services_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    web_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tech_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tls_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in services:
        services_by_asset[row["asset_id"]].append(row)
    for row in web_apps:
        web_by_asset[row["asset_id"]].append(row)
    for row in technologies:
        tech_by_asset[row["asset_id"]].append(row)
    for row in tls_assets:
        tls_by_asset[row["asset_id"]].append(row)

    service_to_asset = {row["service_id"]: row["asset_id"] for row in services}
    web_to_asset = {row["webapp_id"]: row["asset_id"] for row in web_apps}
    tls_to_asset = {row["tls_id"]: row["asset_id"] for row in tls_assets}
    findings_by_asset: dict[str, list[str]] = defaultdict(list)
    highest_severity: dict[str, str] = {}
    for finding in confirmed_findings:
        severity = str(finding.get("severity", "info"))
        for entity in finding.get("affected_entities", []):
            entity_type = entity.get("entity_type")
            entity_id = entity.get("entity_id")
            asset_id = None
            if entity_type == "asset":
                asset_id = entity_id
            elif entity_type == "service":
                asset_id = service_to_asset.get(entity_id)
            elif entity_type == "web_app":
                asset_id = web_to_asset.get(entity_id)
            elif entity_type == "tls":
                asset_id = tls_to_asset.get(entity_id)
            if not asset_id:
                continue
            findings_by_asset[asset_id].append(str(finding.get("title")))
            current = highest_severity.get(asset_id)
            if current is None or SEVERITY_RANK.get(severity, 99) < SEVERITY_RANK.get(current, 99):
                highest_severity[asset_id] = severity

    matrix = []
    for asset in run_data.assets:
        services_for_asset = services_by_asset.get(asset.asset_id, [])
        tls_for_asset = tls_by_asset.get(asset.asset_id, [])
        matrix.append(
            {
                "asset_id": asset.asset_id,
                "asset_name": asset.name,
                "kind": asset.kind,
                "ip": asset.ip,
                "open_services": [
                    f"{(item.get('name') or 'unknown')}/{item.get('port')}" for item in services_for_asset
                ],
                "web_apps": [item.get("url") for item in web_by_asset.get(asset.asset_id, [])],
                "technologies": [
                    (item.get("name") + (f" {item.get('version')}" if item.get("version") else ""))
                    for item in tech_by_asset.get(asset.asset_id, [])
                ],
                "tls_profiles": [
                    f"{item.get('protocol') or '-'} {item.get('cipher') or '-'}" for item in tls_for_asset
                ],
                "weak_tls": any(
                    str(item.get("protocol", "")).lower() in WEAK_TLS_PROTOCOLS for item in tls_for_asset
                ),
                "finding_count": len(findings_by_asset.get(asset.asset_id, [])),
                "highest_severity": highest_severity.get(asset.asset_id, "none"),
                "finding_titles": sorted(set(findings_by_asset.get(asset.asset_id, [])))[:5],
            }
        )
    matrix.sort(key=lambda item: (-item["finding_count"], item["asset_name"] or ""))
    return matrix


def _build_attack_stories(exposure_matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stories = []
    for row in exposure_matrix:
        if row.get("finding_count", 0) < 2:
            continue
        service_text = ", ".join(row.get("open_services", [])[:3]) or "exposed services"
        narrative = (
            f"External access to {row.get('asset_name')} ({service_text}) combines with multiple findings. "
            "An attacker could chain discovery, fingerprinting, and exploitation opportunities."
        )
        if row.get("weak_tls"):
            narrative += " Weak TLS posture may enable downgrade or interception risk."
        stories.append(
            {
                "asset_id": row.get("asset_id"),
                "asset_name": row.get("asset_name"),
                "severity": row.get("highest_severity", "medium"),
                "narrative": narrative,
                "steps": row.get("finding_titles", []),
            }
        )
    stories.sort(key=lambda item: SEVERITY_RANK.get(str(item["severity"]), 99))
    return stories[:8]


def _build_tool_coverage(run_data: RunData) -> dict[str, Any]:
    rows = []
    status_counter = Counter()
    for execution in run_data.tool_executions:
        status_counter[execution.status] += 1
        duration = max((execution.ended_at - execution.started_at).total_seconds(), 0.0)
        rows.append(
            {
                "execution_id": execution.execution_id,
                "tool_name": execution.tool_name,
                "capability": execution.capability,
                "status": execution.status,
                "exit_code": execution.exit_code,
                "duration_seconds": round(duration, 2),
                "command": execution.command,
                "error_message": execution.error_message,
                "termination_reason": execution.termination_reason,
                "termination_detail": execution.termination_detail,
                "timed_out": execution.timed_out,
            }
        )
    blind_spots = []
    for task in run_data.task_states:
        status = str(task.get("status", "unknown"))
        if status not in {"failed", "blocked", "skipped"}:
            continue
        detail = task.get("detail", {}) if isinstance(task.get("detail"), dict) else {}
        reason = detail.get("reason") or task.get("error") or "unspecified"
        blind_spots.append(
            {
                "source": f"task:{task.get('key')}",
                "status": status,
                "reason": str(reason),
                "impact": "Coverage reduced for this stage.",
                "suggested_action": "Review policy limits, dependencies, and target availability.",
            }
        )
    for warning in run_data.warnings:
        if "not found" in warning.lower():
            blind_spots.append(
                {
                    "source": "dependency",
                    "status": "warning",
                    "reason": warning,
                    "impact": "Some capability could not run.",
                    "suggested_action": "Install missing tool and re-run.",
                }
            )
    fact_gaps = []
    for key in ("web_probe.coverage_gaps", "web_discovery.coverage_gaps"):
        value = run_data.facts.get(key, [])
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    fact_gaps.append(
                        {
                            "source": key,
                            "status": item.get("mode", "coverage-gap"),
                            "reason": item.get("reason"),
                            "impact": item.get("impact"),
                            "suggested_action": item.get("suggested_action"),
                            "url": item.get("url"),
                        }
                    )
    blind_spots.extend(fact_gaps)
    telemetry = run_data.facts.get("rate_limit.telemetry", {})
    if not isinstance(telemetry, dict):
        telemetry = {}
    return {
        "summary": {
            "total_executions": len(rows),
            "completed": status_counter.get("completed", 0),
            "failed": status_counter.get("failed", 0),
            "skipped": status_counter.get("skipped", 0),
            "coverage_gap_count": len(blind_spots),
        },
        "executions": rows,
        "blind_spots": blind_spots,
        "rate_limit": telemetry,
    }


def _build_lead_rows(run_data: RunData) -> list[dict[str, Any]]:
    rows = []
    for lead in run_data.leads:
        rows.append(
            {
                "lead_id": lead.lead_id,
                "title": lead.title,
                "category": lead.category,
                "priority_score": lead.priority_score,
                "priority_label": lead.priority_label,
                "confidence": lead.confidence,
                "status": lead.status,
                "why_it_matters": lead.why_it_matters,
                "reasoning": lead.reasoning,
                "suggested_next_steps": lead.suggested_next_steps,
                "likely_finding": lead.likely_finding,
                "likely_severity": lead.likely_severity,
                "draft_finding_seed": lead.draft_finding_seed,
                "tags": lead.tags,
                "affected_entities": lead.affected_entities,
                "evidence_ids": lead.evidence_ids,
                "source_observation_ids": lead.source_observation_ids,
                "detection_sources": lead.detection_sources,
            }
        )
    rows.sort(key=lambda item: (-item["priority_score"], -item["confidence"], item["title"]))
    return rows


def _build_bundle_rows(run_data: RunData) -> list[dict[str, Any]]:
    rows = []
    for bundle in run_data.evidence_bundles:
        rows.append(
            {
                "bundle_id": bundle.bundle_id,
                "label": bundle.label,
                "entity_type": bundle.entity_type,
                "entity_id": bundle.entity_id,
                "asset_id": bundle.asset_id,
                "summary": bundle.summary,
                "confidence": bundle.confidence,
                "evidence_ids": bundle.evidence_ids,
                "artifact_paths": bundle.artifact_paths,
                "screenshot_paths": bundle.screenshot_paths,
                "raw_output_paths": bundle.raw_output_paths,
                "source_tools": bundle.source_tools,
            }
        )
    return rows


def _build_issue_groups(
    confirmed_findings: list[dict[str, Any]],
    candidate_findings: list[dict[str, Any]],
    lead_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for finding in [*confirmed_findings, *candidate_findings]:
        key = str(finding.get("template_id") or finding.get("title") or "finding")
        group = groups.setdefault(
            key,
            {
                "group_key": key,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "kind": "finding",
                "affected_entities": [],
                "items": [],
                "evidence_ids": [],
            },
        )
        group["items"].append(finding.get("finding_id"))
        for entity in finding.get("affected_entities", []):
            if entity not in group["affected_entities"]:
                group["affected_entities"].append(entity)
        for evidence in finding.get("evidence", []):
            evidence_id = evidence.get("evidence_id")
            if evidence_id and evidence_id not in group["evidence_ids"]:
                group["evidence_ids"].append(evidence_id)
    for lead in lead_rows:
        key = str(lead.get("likely_finding") or lead.get("category") or lead.get("title") or "lead")
        group = groups.setdefault(
            key,
            {
                "group_key": key,
                "title": lead.get("likely_finding") or lead.get("title"),
                "severity": lead.get("likely_severity") or "medium",
                "kind": "lead",
                "affected_entities": [],
                "items": [],
                "evidence_ids": [],
            },
        )
        group["items"].append(lead.get("lead_id"))
        for entity in lead.get("affected_entities", []):
            if entity not in group["affected_entities"]:
                group["affected_entities"].append(entity)
        for evidence_id in lead.get("evidence_ids", []):
            if evidence_id not in group["evidence_ids"]:
                group["evidence_ids"].append(evidence_id)
    rows = list(groups.values())
    rows.sort(key=lambda item: (SEVERITY_RANK.get(str(item["severity"]), 99), -len(item["items"]), str(item["title"])))
    return rows


def _host_timeline_rows(run_data: RunData, previous_runs: list[RunData] | None = None) -> dict[str, list[dict[str, Any]]]:
    evidence_lookup = {item.evidence_id: item for item in run_data.evidence}
    previous_runs = previous_runs or []
    previous_signatures: dict[tuple[str, str], str] = {}
    for prior_run in previous_runs:
        prior_evidence = {item.evidence_id: item for item in prior_run.evidence}
        for bundle in getattr(prior_run, "evidence_bundles", []):
            if not bundle.asset_id:
                continue
            for evidence_id in bundle.evidence_ids:
                evidence = prior_evidence.get(evidence_id)
                if not evidence or evidence.kind != "web_screenshot":
                    continue
                signature = _hash_file(evidence.artifact_path)
                if signature:
                    previous_signatures[(bundle.asset_id, evidence.snippet)] = signature

    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for bundle in getattr(run_data, "evidence_bundles", []):
        if not bundle.asset_id:
            continue
        for evidence_id in bundle.evidence_ids:
            evidence = evidence_lookup.get(evidence_id)
            if not evidence or evidence.kind not in {"web_screenshot", "http_response", "web_auxiliary_path", "web_discovery", "web_fingerprint"}:
                continue
            signature = _hash_file(evidence.artifact_path) if evidence.kind == "web_screenshot" else None
            changed = False
            if signature and previous_signatures.get((bundle.asset_id, evidence.snippet)):
                changed = previous_signatures[(bundle.asset_id, evidence.snippet)] != signature
            rows[str(bundle.asset_id)].append(
                {
                    "run_id": run_data.metadata.run_id,
                    "timestamp": iso(evidence.timestamp),
                    "kind": evidence.kind,
                    "label": evidence.snippet,
                    "path": evidence.artifact_path,
                    "source_tool": evidence.source_tool,
                    "bundle_label": bundle.label,
                    "changed": changed,
                }
            )
    for asset_id in rows:
        rows[asset_id].sort(key=lambda item: (item.get("timestamp") or ""), reverse=True)
        rows[asset_id] = rows[asset_id][:10]
    return rows


def _build_host_workspaces(
    run_data: RunData,
    services: list[dict[str, Any]],
    web_apps: list[dict[str, Any]],
    technologies: list[dict[str, Any]],
    tls_assets: list[dict[str, Any]],
    lead_rows: list[dict[str, Any]],
    bundle_rows: list[dict[str, Any]],
    host_timelines: dict[str, list[dict[str, Any]]],
    coverage: dict[str, Any],
) -> list[dict[str, Any]]:
    services_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    web_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tech_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tls_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in services:
        services_by_asset[row["asset_id"]].append(row)
    for row in web_apps:
        web_by_asset[row["asset_id"]].append(row)
    for row in technologies:
        tech_by_asset[row["asset_id"]].append(row)
    for row in tls_assets:
        tls_by_asset[row["asset_id"]].append(row)
    lead_service_to_asset = {row["service_id"]: row["asset_id"] for row in services}
    lead_web_to_asset = {row["webapp_id"]: row["asset_id"] for row in web_apps}
    lead_tls_to_asset = {row["tls_id"]: row["asset_id"] for row in tls_assets}
    leads_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    bundles_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for lead in lead_rows:
        for entity in lead.get("affected_entities", []):
            entity_type = entity.get("entity_type")
            entity_id = entity.get("entity_id")
            asset_id = None
            if entity_type == "asset":
                asset_id = entity_id
            elif entity_type == "service":
                asset_id = lead_service_to_asset.get(entity_id)
            elif entity_type == "web_app":
                asset_id = lead_web_to_asset.get(entity_id)
            elif entity_type == "tls":
                asset_id = lead_tls_to_asset.get(entity_id)
            if asset_id:
                leads_by_asset[str(asset_id)].append(lead)
    for bundle in bundle_rows:
        asset_id = bundle.get("asset_id")
        if asset_id:
            bundles_by_asset[str(asset_id)].append(bundle)
    gaps_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    blind_spots = coverage.get("blind_spots", []) if isinstance(coverage, dict) else []
    for gap in blind_spots:
        if not isinstance(gap, dict):
            continue
        url_value = str(gap.get("url") or "")
        if not url_value:
            continue
        for web_row in web_apps:
            if url_value.startswith(str(web_row.get("url") or "")) or str(web_row.get("url") or "").startswith(url_value):
                gaps_by_asset[str(web_row["asset_id"])].append(gap)
    rows = []
    for asset in run_data.assets:
        rows.append(
            {
                "asset_id": asset.asset_id,
                "asset_name": asset.name,
                "kind": asset.kind,
                "ip": asset.ip,
                "services": services_by_asset.get(asset.asset_id, []),
                "web_apps": web_by_asset.get(asset.asset_id, []),
                "technologies": tech_by_asset.get(asset.asset_id, []),
                "tls_assets": tls_by_asset.get(asset.asset_id, []),
                "leads": sorted(
                    leads_by_asset.get(asset.asset_id, []),
                    key=lambda item: (-int(item["priority_score"]), str(item["title"])),
                ),
                "bundles": bundles_by_asset.get(asset.asset_id, []),
                "timeline": host_timelines.get(asset.asset_id, []),
                "coverage_gaps": gaps_by_asset.get(asset.asset_id, [])[:5],
                "notes_key": f"{run_data.metadata.run_id}:{asset.asset_id}",
            }
        )
    rows.sort(key=lambda item: (-len(item["leads"]), -len(item["services"]), item["asset_name"] or ""))
    return rows


def _build_screenshot_gallery(run_data: RunData, previous_runs: list[RunData] | None = None) -> list[dict[str, Any]]:
    previous_runs = previous_runs or []
    previous_signatures: dict[str, str] = {}
    for prior_run in previous_runs:
        for evidence in prior_run.evidence:
            if evidence.kind != "web_screenshot" or not evidence.artifact_path:
                continue
            signature = _hash_file(evidence.artifact_path)
            if signature:
                previous_signatures[evidence.snippet] = signature
    rows = []
    for evidence in run_data.evidence:
        if evidence.kind != "web_screenshot" or not evidence.artifact_path:
            continue
        current_signature = _hash_file(evidence.artifact_path)
        rows.append(
            {
                "evidence_id": evidence.evidence_id,
                "path": evidence.artifact_path,
                "caption": evidence.snippet,
                "timestamp": iso(evidence.timestamp),
                "source_tool": evidence.source_tool,
                "changed": bool(
                    current_signature
                    and evidence.snippet in previous_signatures
                    and previous_signatures[evidence.snippet] != current_signature
                ),
            }
        )
    return rows


def _attack_surface_score(
    services: list[dict[str, Any]],
    web_apps: list[dict[str, Any]],
    lead_rows: list[dict[str, Any]],
) -> int:
    raw = len(services) * 0.8 + len(web_apps) * 1.2
    raw += sum((int(item["priority_score"]) / 12.0) for item in lead_rows[:12])
    return min(100, int(round(raw)))


def _build_asset_groups(
    run_data: RunData,
    services: list[dict[str, Any]],
    web_apps: list[dict[str, Any]],
    lead_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    services_by_asset: dict[str, int] = Counter(str(item.get("asset_id") or "") for item in services)
    web_by_asset: dict[str, int] = Counter(str(item.get("asset_id") or "") for item in web_apps)
    lead_service_to_asset = {item["service_id"]: item["asset_id"] for item in services}
    lead_web_to_asset = {item["webapp_id"]: item["asset_id"] for item in web_apps}
    lead_counts_by_asset: Counter[str] = Counter()
    for lead in lead_rows:
        for entity in lead.get("affected_entities", []):
            entity_type = entity.get("entity_type")
            entity_id = entity.get("entity_id")
            asset_id = None
            if entity_type == "asset":
                asset_id = str(entity_id)
            elif entity_type == "service":
                asset_id = str(lead_service_to_asset.get(entity_id) or "")
            elif entity_type == "web_app":
                asset_id = str(lead_web_to_asset.get(entity_id) or "")
            if asset_id:
                lead_counts_by_asset[asset_id] += 1

    groups: dict[str, dict[str, Any]] = {}
    for asset in run_data.assets:
        root_domain = _root_domain_hint(asset.name)
        cloud_provider = classify_cloud_provider(asset.name)
        netblock = _netblock_hint(asset.ip)
        group_type = "org-domain"
        group_key = root_domain or asset.name
        if cloud_provider:
            group_type = "cloud-provider"
            group_key = f"{cloud_provider}:{root_domain or asset.name}"
        elif not root_domain and netblock:
            group_type = "netblock"
            group_key = netblock
        group = groups.setdefault(
            group_key,
            {
                "group_key": group_key,
                "group_type": group_type,
                "label": group_key,
                "cloud_provider": cloud_provider,
                "asset_count": 0,
                "service_count": 0,
                "web_app_count": 0,
                "lead_count": 0,
                "assets": [],
                "example_hosts": [],
            },
        )
        group["asset_count"] += 1
        group["service_count"] += int(services_by_asset.get(asset.asset_id, 0))
        group["web_app_count"] += int(web_by_asset.get(asset.asset_id, 0))
        group["lead_count"] += int(lead_counts_by_asset.get(asset.asset_id, 0))
        group["assets"].append(
            {
                "asset_id": asset.asset_id,
                "name": asset.name,
                "ip": asset.ip,
                "kind": asset.kind,
            }
        )
        if asset.name and asset.name not in group["example_hosts"]:
            group["example_hosts"].append(asset.name)
    rows = list(groups.values())
    rows.sort(key=lambda item: (-int(item["lead_count"]), -int(item["web_app_count"]), str(item["label"])))
    return rows


def build_view_model(
    run_data: RunData,
    audience: str = "consultant",
    trend: dict[str, Any] | None = None,
    previous_runs: list[RunData] | None = None,
) -> dict[str, Any]:
    audience = normalize_report_audience(audience)
    execution_issues = build_execution_issues(run_data)
    execution_issues_summary = summarize_execution_issues(run_data, execution_issues)
    completeness_status = str(execution_issues_summary.get("completeness_status") or "healthy")
    severity_counts = _severity_counts(run_data)
    raw_risk_score = _risk_score_raw(severity_counts)
    risk_score = _risk_score_100(raw_risk_score)
    risk_grade = _risk_grade(risk_score)
    tool_execution_rows = _build_execution_rows(run_data)
    execution_lookup = {row["execution_id"]: row for row in tool_execution_rows}
    findings_confirmed, findings_candidate = _build_finding_rows(run_data, execution_lookup)

    service_rows = [
        {
            "service_id": service.service_id,
            "asset_id": service.asset_id,
            "port": service.port,
            "protocol": service.protocol,
            "state": service.state,
            "name": service.name,
            "banner": service.banner,
        }
        for service in run_data.services
    ]
    web_rows = [
        {
            "webapp_id": web_app.webapp_id,
            "asset_id": web_app.asset_id,
            "url": web_app.url,
            "status_code": web_app.status_code,
            "title": web_app.title,
            "forms_count": web_app.forms_count,
        }
        for web_app in run_data.web_apps
    ]
    tech_rows = [
        {
            "tech_id": tech.tech_id,
            "asset_id": tech.asset_id,
            "webapp_id": tech.webapp_id,
            "name": tech.name,
            "version": tech.version,
            "confidence": tech.confidence,
        }
        for tech in run_data.technologies
    ]
    endpoint_rows = [
        {
            "endpoint_id": endpoint.endpoint_id,
            "webapp_id": endpoint.webapp_id,
            "asset_id": endpoint.asset_id,
            "service_id": endpoint.service_id,
            "url": endpoint.url,
            "path": endpoint.path,
            "method": endpoint.method,
            "kind": endpoint.kind,
            "tags": endpoint.tags,
            "auth_hints": endpoint.auth_hints,
            "confidence": endpoint.confidence,
        }
        for endpoint in run_data.endpoints
    ]
    parameter_rows = [
        {
            "parameter_id": parameter.parameter_id,
            "webapp_id": parameter.webapp_id,
            "endpoint_id": parameter.endpoint_id,
            "name": parameter.name,
            "location": parameter.location,
            "sensitive": parameter.sensitive,
            "confidence": parameter.confidence,
        }
        for parameter in run_data.parameters
    ]
    form_rows = [
        {
            "form_id": form.form_id,
            "webapp_id": form.webapp_id,
            "endpoint_id": form.endpoint_id,
            "action_url": form.action_url,
            "method": form.method,
            "field_names": form.field_names,
            "has_password": form.has_password,
            "confidence": form.confidence,
        }
        for form in run_data.forms
    ]
    login_surface_rows = [
        {
            "login_surface_id": item.login_surface_id,
            "webapp_id": item.webapp_id,
            "endpoint_id": item.endpoint_id,
            "url": item.url,
            "reasons": item.reasons,
            "username_fields": item.username_fields,
            "password_fields": item.password_fields,
            "auth_hints": item.auth_hints,
            "confidence": item.confidence,
        }
        for item in run_data.login_surfaces
    ]
    replay_request_rows = [
        {
            "replay_request_id": item.replay_request_id,
            "webapp_id": item.webapp_id,
            "asset_id": item.asset_id,
            "endpoint_id": item.endpoint_id,
            "service_id": item.service_id,
            "url": item.url,
            "method": item.method,
            "headers": item.headers,
            "parameter_names": item.parameter_names,
            "body_field_names": item.body_field_names,
            "cookie_names": item.cookie_names,
            "tags": item.tags,
            "auth_hints": item.auth_hints,
            "replay_enabled": item.replay_enabled,
            "confidence": item.confidence,
        }
        for item in run_data.replay_requests
    ]
    validation_result_rows = [
        {
            "validation_result_id": item.validation_result_id,
            "replay_request_id": item.replay_request_id,
            "webapp_id": item.webapp_id,
            "entity_type": item.entity_type,
            "entity_id": item.entity_id,
            "service_id": item.service_id,
            "protocol_family": item.protocol_family,
            "validator_key": item.validator_key,
            "family": item.family,
            "category": item.category,
            "status": item.status,
            "title": item.title,
            "summary": item.summary,
            "severity_hint": item.severity_hint,
            "request_url": item.request_url,
            "request_method": item.request_method,
            "mutated": item.mutated,
            "confidence": item.confidence,
            "coverage_lane_id": item.coverage_lane_id,
            "attack_path_id": item.attack_path_id,
            "playbook_key": item.playbook_key,
            "step_key": item.step_key,
            "response_delta": item.response_delta,
            "stop_reason": item.stop_reason,
            "proof_strength": item.proof_strength,
            "evidence_ids": item.evidence_ids,
            "tags": item.tags,
            "details": item.details,
        }
        for item in run_data.validation_results
    ]
    surface_signal_rows = [to_serializable(item) for item in run_data.surface_signals]
    attack_path_rows = [to_serializable(item) for item in run_data.attack_paths]
    investigation_step_rows = [to_serializable(item) for item in run_data.investigation_steps]
    playbook_execution_rows = [to_serializable(item) for item in run_data.playbook_executions]
    coverage_decision_rows = [to_serializable(item) for item in run_data.coverage_decisions]
    hypothesis_rows = [to_serializable(item) for item in run_data.hypotheses]
    validation_task_rows = [to_serializable(item) for item in run_data.validation_tasks]
    coverage_gap_rows = [to_serializable(item) for item in run_data.coverage_gaps]
    tls_rows = [
        {
            "tls_id": tls.tls_id,
            "asset_id": tls.asset_id,
            "host": tls.host,
            "port": tls.port,
            "protocol": tls.protocol,
            "cipher": tls.cipher,
            "issuer": tls.issuer,
            "subject": tls.subject,
            "not_after": tls.not_after,
        }
        for tls in run_data.tls_assets
    ]
    service_counter = Counter((service.get("name") or "unknown") for service in service_rows)
    service_distribution = [
        {"name": name, "count": count}
        for name, count in sorted(service_counter.items(), key=lambda item: (-item[1], item[0]))
    ]

    domain_scores = _build_risk_domains(
        findings_confirmed,
        service_rows,
        tls_rows,
        run_data.warnings,
        run_data.errors,
        len(findings_candidate),
    )
    remediation_plan = _build_remediation_plan(findings_confirmed)
    exposure_matrix = _build_asset_exposure_matrix(
        run_data,
        findings_confirmed,
        service_rows,
        web_rows,
        tech_rows,
        tls_rows,
    )
    attack_stories = _build_attack_stories(exposure_matrix)
    coverage = _build_tool_coverage(run_data)
    top_business_risks = [
        {
            "title": finding["title"],
            "severity": finding["severity"],
            "business_impact": finding.get("impact") or finding.get("description") or "Business impact requires review.",
            "proof_snippet": (finding.get("proof") or {}).get("snippet"),
            "recommended_action": (finding.get("recommendations") or ["Investigate and remediate."])[0],
        }
        for finding in findings_confirmed[:5]
    ]
    vulnerability_records = run_data.facts.get("vulnerability_records", [])
    if not isinstance(vulnerability_records, list):
        vulnerability_records = []
    task_timeline = []
    for task in run_data.task_states:
        if not isinstance(task, dict):
            continue
        detail = task.get("detail", {}) if isinstance(task.get("detail"), dict) else {}
        task_timeline.append(
            {
                "key": task.get("key"),
                "label": task.get("label"),
                "status": task.get("status"),
                "started_at": task.get("started_at"),
                "ended_at": task.get("ended_at"),
                "reason": detail.get("reason"),
                "decision_reason": detail.get("decision_reason"),
                "attempt": detail.get("attempt"),
                "stage": detail.get("stage"),
                "capability": detail.get("capability"),
                "error": task.get("error"),
            }
        )
    decision_trail = run_data.facts.get("plan.decision_items", [])
    if not isinstance(decision_trail, list):
        decision_trail = []
    lead_rows = _build_lead_rows(run_data)
    bundle_rows = _build_bundle_rows(run_data)
    issue_groups = _build_issue_groups(findings_confirmed, findings_candidate, lead_rows)
    host_timelines = _host_timeline_rows(run_data, previous_runs=previous_runs)
    host_workspaces = _build_host_workspaces(
        run_data,
        service_rows,
        web_rows,
        tech_rows,
        tls_rows,
        lead_rows,
        bundle_rows,
        host_timelines,
        coverage,
    )
    screenshot_gallery = _build_screenshot_gallery(run_data, previous_runs=previous_runs)
    attack_surface_score = _attack_surface_score(service_rows, web_rows, lead_rows)
    asset_groups = _build_asset_groups(run_data, service_rows, web_rows, lead_rows)
    risky_services_count = len(
        [
            item
            for item in service_rows
            if int(item.get("port", 0)) in {22, 23, 25, 3389, 5900, 1433, 3306, 5432, 6379, 9200, 27017}
        ]
    )
    outdated_software_count = len(
        [
            item
            for item in vulnerability_records
            if "cve" in str(item.get("title", "")).lower() or "cve" in str(item.get("category", "")).lower()
        ]
    )
    likely_findings_count = len([item for item in lead_rows if item.get("likely_finding")])
    high_priority_lead_count = len(
        [item for item in lead_rows if item.get("priority_label") in {"very-high", "high"}]
    )
    auth_surface_count = len(
        [
            item
            for item in lead_rows
            if str(item.get("title", "")).lower().find("login") >= 0
            or str(item.get("likely_finding", "")).lower().find("auth") >= 0
        ]
    )
    metadata = {
        "run_id": run_data.metadata.run_id,
        "target_input": run_data.metadata.target_input,
        "profile": run_data.metadata.profile,
        "risk_mode": run_data.facts.get("scan.risk_mode"),
        "started_at": iso(run_data.metadata.started_at),
        "ended_at": iso(run_data.metadata.ended_at),
        "tool_version": run_data.metadata.tool_version,
        "schema_version": run_data.metadata.schema_version,
        "state": run_data.metadata.state.value
        if hasattr(run_data.metadata.state, "value")
        else str(run_data.metadata.state),
    }
    summary = {
        "asset_count": len(run_data.assets),
        "service_count": len(service_rows),
        "web_app_count": len(web_rows),
        "technology_count": len(tech_rows),
        "tls_count": len(tls_rows),
        "finding_count": len(findings_confirmed),
        "candidate_finding_count": len(findings_candidate),
        "lead_count": len(lead_rows),
        "high_priority_lead_count": high_priority_lead_count,
        "likely_findings_count": likely_findings_count,
        "internet_facing_web_apps": len(web_rows),
        "risky_service_count": risky_services_count,
        "outdated_software_count": outdated_software_count,
        "auth_surface_count": auth_surface_count,
        "attack_surface_score": attack_surface_score,
        "risk_score": risk_score,
        "risk_score_raw": raw_risk_score,
        "risk_grade": risk_grade,
        "warning_count": len(run_data.warnings),
        "error_count": len(run_data.errors),
    }
    scorecard = {
        "overall_risk_score": risk_score,
        "overall_risk_grade": risk_grade,
        "attack_surface_score": attack_surface_score,
        "top_business_risks": top_business_risks,
        "fix_first_actions": remediation_plan[:5],
    }
    scope_rows = [
        {"raw": target.raw, "type": target.target_type.value, "value": target.value}
        for target in run_data.scope
    ]
    service_exposure_breakdown = _service_exposure_breakdown(service_rows)
    evidence_rows = [_build_evidence_detail(evidence, execution_lookup) for evidence in run_data.evidence]
    raw_extensions = run_data.facts.get("gui.extensions", [])
    extension_rows = [dict(item) for item in raw_extensions if isinstance(item, dict)] if isinstance(raw_extensions, list) else []
    trend_payload = trend or {
        "available": False,
        "baseline_run_id": None,
        "latest_run_id": run_data.metadata.run_id,
        "risk_score_delta": None,
        "new_findings": [],
        "resolved_findings": [],
        "unchanged_findings": [],
        "history": [],
    }
    assessment_context = {
        "authorization_statement": "This report is generated for authorized professional security testing only.",
        "profile": run_data.metadata.profile,
        "limitations": [
            "Results represent day-1 external visibility and are time-bound to this execution window.",
            "Findings may be affected by target-side filtering, temporary outages, or policy guardrails.",
        ],
        "data_provenance": "All findings reference normalized evidence with source tool and execution provenance.",
    }
    show_technical_details = is_consultant_audience(audience)
    overview = {
        "executive": {"summary": summary, "scorecard": scorecard, "audience": audience},
        "context": {
            "metadata": metadata,
            "scope": scope_rows,
            "scope_compiler": run_data.facts.get("scope.compiler.summary", {}),
            "scope_cloud_hosts": run_data.facts.get("scope.cloud_hosts", []),
            "assessment_context": assessment_context,
            "audience": audience,
        },
        "risk": {
            "severity_counts": severity_counts,
            "service_distribution": service_distribution,
            "risk_domains": domain_scores,
            "service_exposure_breakdown": service_exposure_breakdown,
            "audience": audience,
        },
        "remediation": {"remediation_plan": remediation_plan, "audience": audience},
        "stories": {"attack_stories": attack_stories, "audience": audience},
        "audience": audience,
    }
    investigation_queue = {
        "summary": {
            "high_priority_lead_count": high_priority_lead_count,
            "candidate_finding_count": len(findings_candidate),
            "likely_findings_count": likely_findings_count,
            "validation_task_count": len(validation_task_rows),
            "hypothesis_count": len(hypothesis_rows),
        },
        "test_first": {"leads": lead_rows[:12], "audience": audience},
        "likely_findings": {
            "leads": [item for item in lead_rows if item.get("likely_finding")][:20],
            "audience": audience,
        },
        "priority_leads": {"leads": lead_rows, "audience": audience},
        "candidate_findings": {"findings": findings_candidate, "audience": audience},
        "validation_queue": {"validation_tasks": validation_task_rows, "audience": audience},
        "hypotheses": {"hypotheses": hypothesis_rows, "audience": audience},
        "audience": audience,
    }
    attack_surface = {
        "summary": {
            "asset_count": len(run_data.assets),
            "service_count": len(service_rows),
            "web_app_count": len(web_rows),
            "technology_count": len(tech_rows),
            "tls_count": len(tls_rows),
            "endpoint_count": len(endpoint_rows),
            "parameter_count": len(parameter_rows),
            "replay_request_count": len(replay_request_rows),
        },
        "exposure": {"exposure_matrix": exposure_matrix, "audience": audience},
        "asset_groups": {"asset_groups": asset_groups, "audience": audience},
        "services": {"services": service_rows, "audience": audience},
        "web": {"web_apps": web_rows, "audience": audience},
        "endpoints": {"endpoints": endpoint_rows, "audience": audience},
        "parameters": {"parameters": parameter_rows, "audience": audience},
        "forms": {"forms": form_rows, "audience": audience},
        "login_surfaces": {"login_surfaces": login_surface_rows, "audience": audience},
        "replay_requests": {"replay_requests": replay_request_rows, "audience": audience},
        "tech": {"technologies": tech_rows, "audience": audience},
        "tls": {"tls_assets": tls_rows, "audience": audience},
        "audience": audience,
    }
    appendices = {
        "summary": {
            "execution_issue_count": execution_issues_summary.get("total_count", 0),
            "coverage_gap_count": coverage.get("summary", {}).get("coverage_gap_count", 0),
            "evidence_count": len(evidence_rows),
        },
        "screenshots": {"screenshots": screenshot_gallery, "audience": audience},
        "bundles": {"bundles": bundle_rows, "audience": audience},
        "evidence": {"evidence": evidence_rows, "audience": audience},
        "errors": {
            "execution_issues": execution_issues,
            "execution_issues_summary": execution_issues_summary,
            "completeness_status": completeness_status,
            "show_technical_details": show_technical_details,
            "audience": audience,
        },
        "coverage": {"coverage": coverage, "audience": audience},
        "active_validation": {
            "surface_signals": surface_signal_rows,
            "attack_paths": attack_path_rows,
            "investigation_steps": investigation_step_rows,
            "playbook_executions": playbook_execution_rows,
            "coverage_decisions": coverage_decision_rows,
            "validation_results": validation_result_rows,
            "coverage_gaps": coverage_gap_rows,
            "audience": audience,
        },
        "decisions": {"decision_trail": decision_trail, "audience": audience},
        "timeline": {"task_timeline": task_timeline, "audience": audience},
        "tools": {"tool_executions": tool_execution_rows, "audience": audience},
        "trend": {"trend": trend_payload, "audience": audience},
        "host_workspaces": {"host_workspaces": host_workspaces, "audience": audience},
        "issue_groups": {"issue_groups": issue_groups, "audience": audience},
        "vulnerabilities": {"vulnerabilities": vulnerability_records, "audience": audience},
        "audience": audience,
    }

    return {
        "generated_at": iso(now_utc()),
        "audience": audience,
        "completeness_status": completeness_status,
        "metadata": metadata,
        "summary": summary,
        "scorecard": scorecard,
        "risk_domains": domain_scores,
        "severity_counts": severity_counts,
        "service_distribution": service_distribution,
        "service_exposure_breakdown": service_exposure_breakdown,
        "scope": scope_rows,
        "scope_compiler": run_data.facts.get("scope.compiler.summary", {}),
        "scope_cloud_hosts": run_data.facts.get("scope.cloud_hosts", []),
        "services": service_rows,
        "web_apps": web_rows,
        "endpoints": endpoint_rows,
        "parameters": parameter_rows,
        "forms": form_rows,
        "login_surfaces": login_surface_rows,
        "replay_requests": replay_request_rows,
        "surface_signals": surface_signal_rows,
        "attack_paths": attack_path_rows,
        "investigation_steps": investigation_step_rows,
        "playbook_executions": playbook_execution_rows,
        "coverage_decisions": coverage_decision_rows,
        "validation_results": validation_result_rows,
        "validation_tasks": validation_task_rows,
        "hypotheses": hypothesis_rows,
        "coverage_gaps": coverage_gap_rows,
        "technologies": tech_rows,
        "tls_assets": tls_rows,
        "findings": findings_confirmed,
        "candidate_findings": findings_candidate,
        "remediation_plan": remediation_plan,
        "priority_leads": lead_rows,
        "test_first": lead_rows[:12],
        "likely_findings": [item for item in lead_rows if item.get("likely_finding")][:20],
        "issue_groups": issue_groups,
        "host_workspaces": host_workspaces,
        "asset_groups": asset_groups,
        "screenshots": screenshot_gallery,
        "evidence_bundles": bundle_rows,
        "exposure_matrix": exposure_matrix,
        "attack_stories": attack_stories,
        "evidence": evidence_rows,
        "tool_executions": tool_execution_rows,
        "vulnerabilities": vulnerability_records,
        "task_timeline": task_timeline,
        "decision_trail": decision_trail,
        "coverage": coverage,
        "execution_issues": execution_issues,
        "execution_issues_summary": execution_issues_summary,
        "trend": trend_payload,
        "assessment_context": assessment_context,
        "extensions": extension_rows,
        "overview": overview,
        "investigation_queue": investigation_queue,
        "attack_surface": attack_surface,
        "appendices": appendices,
        "warnings": run_data.warnings,
        "errors": run_data.errors,
    }
