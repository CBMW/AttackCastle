from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attackcastle.core.models import Asset, Evidence, Observation, Service, new_id

HTTP_PORTS = {80, 443, 8000, 8080, 8443}
TLS_PORTS = {443, 465, 587, 993, 995, 8443}


def _iter_masscan_records(payload_text: str) -> list[dict[str, Any]]:
    text = payload_text.strip()
    if not text:
        return []

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None

    if isinstance(loaded, list):
        return [item for item in loaded if isinstance(item, dict)]
    if isinstance(loaded, dict):
        return [loaded]

    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        candidate = line.strip().rstrip(",")
        if not candidate or candidate in {"[", "]"}:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _to_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0 or parsed > 65535:
        return None
    return parsed


def parse_masscan_json(
    json_path: Path,
    source_tool: str,
    source_execution_id: str | None = None,
    parser_version: str = "masscan_json_v1",
) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "assets": [],
        "services": [],
        "observations": [],
        "evidence": [],
        "facts": {
            "masscan.parsed": False,
            "masscan.discovered_hosts": 0,
            "masscan.discovered_services": 0,
            "masscan.open_ports_by_host": {},
        },
    }
    if not json_path.exists():
        return parsed

    payload_text = json_path.read_text(encoding="utf-8", errors="ignore")
    records = _iter_masscan_records(payload_text)
    if not records:
        return parsed
    parsed["facts"]["masscan.parsed"] = True

    seen_hosts: set[str] = set()
    open_ports_by_host: dict[str, set[int]] = {}

    for record in records:
        ip = str(record.get("ip") or record.get("ip_address") or "").strip()
        if not ip:
            continue
        ports = record.get("ports", [])
        if not isinstance(ports, list):
            continue

        host_asset = Asset(
            asset_id=new_id("asset"),
            kind="host",
            name=ip,
            ip=ip,
            source_tool=source_tool,
            source_execution_id=source_execution_id,
            parser_version=parser_version,
        )
        if ip not in seen_hosts:
            parsed["assets"].append(host_asset)
            seen_hosts.add(ip)
            parsed["facts"]["masscan.discovered_hosts"] += 1

        for port_item in ports:
            if not isinstance(port_item, dict):
                continue
            status = str(port_item.get("status", "open")).lower()
            if status != "open":
                continue
            port_id = _to_int(port_item.get("port"))
            if port_id is None:
                continue
            protocol = str(port_item.get("proto", "tcp")).lower()
            service = Service(
                service_id=new_id("service"),
                asset_id=host_asset.asset_id,
                port=port_id,
                protocol=protocol,
                state="open",
                name="unknown",
                source_tool=source_tool,
                source_execution_id=source_execution_id,
                parser_version=parser_version,
            )
            parsed["services"].append(service)
            parsed["facts"]["masscan.discovered_services"] += 1
            open_ports_by_host.setdefault(ip, set()).add(port_id)

            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=source_tool,
                kind="open_port",
                snippet=f"{ip}:{port_id}/{protocol} open",
                artifact_path=str(json_path),
                selector={"kind": "json", "ip": ip, "port": port_id},
                source_execution_id=source_execution_id,
                parser_version=parser_version,
                confidence=1.0,
            )
            parsed["evidence"].append(evidence)

            parsed["observations"].append(
                Observation(
                    observation_id=new_id("obs"),
                    key="service.open",
                    value=True,
                    entity_type="service",
                    entity_id=service.service_id,
                    source_tool=source_tool,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=source_execution_id,
                    parser_version=parser_version,
                )
            )
            parsed["observations"].append(
                Observation(
                    observation_id=new_id("obs"),
                    key="service.port",
                    value=port_id,
                    entity_type="service",
                    entity_id=service.service_id,
                    source_tool=source_tool,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=source_execution_id,
                    parser_version=parser_version,
                )
            )
            if port_id in HTTP_PORTS:
                parsed["observations"].append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.http.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=source_tool,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=source_execution_id,
                        parser_version=parser_version,
                    )
                )
            if port_id in TLS_PORTS:
                parsed["observations"].append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.tls.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=source_tool,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=source_execution_id,
                        parser_version=parser_version,
                    )
                )

    parsed["facts"]["masscan.open_ports_by_host"] = {
        host: sorted(ports) for host, ports in open_ports_by_host.items()
    }
    return parsed

