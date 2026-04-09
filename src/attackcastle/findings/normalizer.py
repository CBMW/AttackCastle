from __future__ import annotations

import hashlib
import re
from typing import Any

from attackcastle.core.models import RunData

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _web_context(run_data: RunData) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for item in run_data.web_apps:
        lookup[item.webapp_id] = {
            "url": item.url,
            "asset_id": item.asset_id,
            "service_id": item.service_id,
        }
    return lookup


def _entity_context(run_data: RunData, entity_type: str, entity_id: str) -> dict[str, Any]:
    if entity_type == "web_app":
        web_lookup = _web_context(run_data)
        return web_lookup.get(entity_id, {})
    if entity_type == "service":
        service = next((item for item in run_data.services if item.service_id == entity_id), None)
        if service:
            return {
                "asset_id": service.asset_id,
                "port": service.port,
                "protocol": service.protocol,
                "name": service.name,
            }
    if entity_type == "asset":
        asset = next((item for item in run_data.assets if item.asset_id == entity_id), None)
        if asset:
            return {"asset_id": asset.asset_id, "asset_name": asset.name, "ip": asset.ip}
    if entity_type == "tls":
        tls_item = next((item for item in run_data.tls_assets if item.tls_id == entity_id), None)
        if tls_item:
            return {"asset_id": tls_item.asset_id, "host": tls_item.host, "port": tls_item.port}
    return {}


def _normalize_title(value: str) -> str:
    lowered = re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()
    return " ".join(lowered.split())


def _severity_of(value: str) -> str:
    normalized = str(value or "info").lower()
    if normalized not in SEVERITY_RANK:
        return "info"
    return normalized


def _merge_severity(left: str, right: str) -> str:
    left_rank = SEVERITY_RANK.get(_severity_of(left), 99)
    right_rank = SEVERITY_RANK.get(_severity_of(right), 99)
    return _severity_of(left if left_rank <= right_rank else right)


def _confidence_score(status: str, severity: str, source_count: int, evidence_count: int) -> float:
    base = 0.55
    if str(status).lower() == "confirmed":
        base += 0.15
    severity_bonus = {
        "critical": 0.15,
        "high": 0.12,
        "medium": 0.08,
        "low": 0.04,
        "info": 0.02,
    }.get(_severity_of(severity), 0.02)
    source_bonus = min(0.15, source_count * 0.05)
    evidence_bonus = min(0.15, evidence_count * 0.03)
    return round(min(0.99, base + severity_bonus + source_bonus + evidence_bonus), 3)


def _affected_key(affected: list[dict[str, Any]]) -> str:
    ordered = sorted(
        f"{item.get('entity_type', '')}:{item.get('entity_id', '')}"
        for item in affected
    )
    return ",".join(ordered)


def _correlation_key(title: str, category: str, affected: list[dict[str, Any]]) -> str:
    return f"{_normalize_title(title)}|{_normalize_title(category)}|{_affected_key(affected)}"


def _record_id(prefix: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return f"{prefix}_{digest}"


def _finding_rows(run_data: RunData, evidence_lookup: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in run_data.findings:
        if finding.suppressed:
            continue
        affected = []
        for entity in finding.affected_entities:
            entity_type = str(entity.get("entity_type"))
            entity_id = str(entity.get("entity_id"))
            affected.append(
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "context": _entity_context(run_data, entity_type, entity_id),
                }
            )
        rows.append(
            {
                "row_id": finding.finding_id,
                "source": "findings_engine",
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status,
                "category": finding.category,
                "template_id": finding.template_id,
                "affected": affected,
                "evidence_ids": list(finding.evidence_ids),
                "evidence_snippets": [
                    evidence_lookup[evidence_id].snippet
                    for evidence_id in finding.evidence_ids[:3]
                    if evidence_id in evidence_lookup
                ],
            }
        )
    return rows


def _raw_rows(run_data: RunData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    raw_key_map = {
        "web.nikto.issues": ("Nikto issues detected", "medium"),
        "web.nuclei.issues": ("Nuclei template issues detected", "high"),
        "web.sqlmap.injectable": ("Potential SQL injection detected", "critical"),
        "web.login_portal": ("Public login portal detected", "medium"),
        "web.admin_interface": ("Administrative interface detected", "high"),
        "web.public_files": ("Interesting public file exposure detected", "high"),
        "cloud.storage.public": ("Public cloud storage-like surface detected", "high"),
        "web.default_page": ("Default or placeholder page detected", "low"),
        "web.soft_404": ("Soft-404 behavior detected", "low"),
        "wp.vulnerabilities.titles": ("WordPress vulnerabilities reported", "high"),
        "framework.scan.issue_count": ("Framework-targeted issues detected", "high"),
        "service.smtp.exposed": ("SMTP service exposed externally", "low"),
        "service.dns.exposed": ("DNS service exposed externally", "low"),
        "service.vpn.exposed": ("VPN service exposed externally", "low"),
        "service.ssh.exposed": ("SSH service exposed externally", "medium"),
        "service.ftp.exposed": ("FTP service exposed externally", "medium"),
        "service.rdp.exposed": ("RDP service exposed externally", "medium"),
        "service.remote_admin.exposed": ("Remote admin service exposed externally", "medium"),
        "web.vhost.discovered": ("Additional virtual host discovered", "medium"),
    }
    for observation in run_data.observations:
        if observation.key == "vuln.cve.top_priority":
            top = observation.value if isinstance(observation.value, dict) else {}
            cve_id = str(top.get("cve", "CVE candidate"))
            priority = str(top.get("priority", "medium")).lower()
            severity = {
                "critical": "high",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }.get(priority, "medium")
            rows.append(
                {
                    "row_id": f"raw|{observation.key}|{observation.entity_type}|{observation.entity_id}",
                    "source": observation.source_tool,
                    "title": f"Prioritized CVE candidate: {cve_id}",
                    "severity": severity,
                    "status": "candidate",
                    "category": "CVE Prioritization",
                    "template_id": "",
                    "affected": [
                        {
                            "entity_type": observation.entity_type,
                            "entity_id": observation.entity_id,
                            "context": _entity_context(run_data, observation.entity_type, observation.entity_id),
                        }
                    ],
                    "evidence_ids": list(observation.evidence_ids),
                    "evidence_snippets": [],
                }
            )
            continue
        if observation.key not in raw_key_map:
            continue
        if observation.key == "web.sqlmap.injectable" and observation.value is not True:
            continue
        if observation.key == "web.soft_404" and observation.value is not True:
            continue
        if observation.key.endswith(".exposed") and observation.value is not True:
            continue
        if observation.key == "framework.scan.issue_count":
            try:
                if int(observation.value) <= 0:
                    continue
            except (TypeError, ValueError):
                continue
        label, severity = raw_key_map[observation.key]
        rows.append(
            {
                "row_id": f"raw|{observation.key}|{observation.entity_type}|{observation.entity_id}",
                "source": observation.source_tool,
                "title": label,
                "severity": severity,
                "status": "candidate",
                "category": "Raw Scanner Signal",
                "template_id": "",
                "affected": [
                    {
                        "entity_type": observation.entity_type,
                        "entity_id": observation.entity_id,
                        "context": _entity_context(run_data, observation.entity_type, observation.entity_id),
                    }
                ],
                "evidence_ids": list(observation.evidence_ids),
                "evidence_snippets": [],
            }
        )
    return rows


def build_vulnerability_records(run_data: RunData) -> list[dict[str, Any]]:
    evidence_lookup = {item.evidence_id: item for item in run_data.evidence}
    rows = [*_finding_rows(run_data, evidence_lookup), *_raw_rows(run_data)]
    merged: dict[str, dict[str, Any]] = {}

    for row in rows:
        key = _correlation_key(
            title=str(row.get("title", "")),
            category=str(row.get("category", "")),
            affected=list(row.get("affected", [])),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = {
                "record_id": _record_id("vuln", key),
                "source": str(row.get("source", "")),
                "sources": [str(row.get("source", ""))],
                "title": str(row.get("title", "")),
                "severity": _severity_of(str(row.get("severity", "info"))),
                "status": str(row.get("status", "candidate")),
                "category": str(row.get("category", "General")),
                "template_id": str(row.get("template_id", "")),
                "affected": list(row.get("affected", [])),
                "evidence_ids": list(row.get("evidence_ids", [])),
                "evidence_count": len(list(row.get("evidence_ids", []))),
                "evidence_snippets": list(row.get("evidence_snippets", [])),
                "merged_from": [str(row.get("row_id", ""))],
            }
            continue

        source = str(row.get("source", ""))
        if source and source not in existing["sources"]:
            existing["sources"].append(source)
        existing["source"] = ",".join(sorted(existing["sources"]))
        existing["severity"] = _merge_severity(existing["severity"], str(row.get("severity", "info")))
        if str(row.get("status", "")).lower() == "confirmed":
            existing["status"] = "confirmed"
        if not existing.get("template_id") and row.get("template_id"):
            existing["template_id"] = str(row.get("template_id"))
        for evidence_id in row.get("evidence_ids", []):
            if evidence_id not in existing["evidence_ids"]:
                existing["evidence_ids"].append(evidence_id)
        existing["evidence_count"] = len(existing["evidence_ids"])
        for snippet in row.get("evidence_snippets", []):
            if snippet and snippet not in existing["evidence_snippets"]:
                existing["evidence_snippets"].append(snippet)
        row_id = str(row.get("row_id", ""))
        if row_id and row_id not in existing["merged_from"]:
            existing["merged_from"].append(row_id)

    records = list(merged.values())
    for record in records:
        record["confidence_score"] = _confidence_score(
            status=str(record.get("status", "candidate")),
            severity=str(record.get("severity", "info")),
            source_count=len(record.get("sources", [])),
            evidence_count=int(record.get("evidence_count", 0)),
        )

    records.sort(
        key=lambda item: (
            SEVERITY_RANK.get(_severity_of(str(item.get("severity", "info"))), 99),
            -int(item.get("evidence_count", 0)),
            str(item.get("title", "")),
        )
    )
    return records
