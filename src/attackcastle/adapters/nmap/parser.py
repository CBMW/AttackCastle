from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from attackcastle.core.models import Asset, Evidence, Observation, Service, new_id

HTTP_PORTS = {80, 443, 8080, 8443, 8000}
TLS_PORTS = {443, 465, 587, 993, 995, 8443}
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}


def parse_nmap_xml(
    xml_path: Path,
    source_tool: str,
    source_execution_id: str | None = None,
    parser_version: str = "nmap_xml_v1",
) -> dict:
    parsed = {
        "assets": [],
        "services": [],
        "observations": [],
        "evidence": [],
        "facts": {"nmap.parsed": True, "nmap.discovered_hosts": 0},
    }

    if not xml_path.exists():
        parsed["facts"]["nmap.parsed"] = False
        return parsed

    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="ignore"))
    except ET.ParseError:
        parsed["facts"]["nmap.parsed"] = False
        return parsed
    for host in root.findall("host"):
        status_element = host.find("status")
        if status_element is None or status_element.get("state") != "up":
            continue

        address_value = None
        for address in host.findall("address"):
            addr_type = address.get("addrtype")
            if addr_type in {"ipv4", "ipv6"}:
                address_value = address.get("addr")
                break
        if not address_value:
            continue

        host_asset = Asset(
            asset_id=new_id("asset"),
            kind="host",
            name=address_value,
            ip=address_value,
            source_tool=source_tool,
            source_execution_id=source_execution_id,
            parser_version=parser_version,
        )
        parsed["assets"].append(host_asset)
        parsed["facts"]["nmap.discovered_hosts"] += 1

        hostnames = host.findall("hostnames/hostname")
        for host_entry in hostnames:
            hostname = host_entry.get("name")
            if not hostname:
                continue
            parsed["assets"].append(
                Asset(
                    asset_id=new_id("asset"),
                    kind="domain",
                    name=hostname,
                    parent_asset_id=host_asset.asset_id,
                    source_tool=source_tool,
                    source_execution_id=source_execution_id,
                    parser_version=parser_version,
                )
            )

        parsed["observations"].append(
            Observation(
                observation_id=new_id("obs"),
                key="host.up",
                value=True,
                entity_type="asset",
                entity_id=host_asset.asset_id,
                source_tool=source_tool,
                source_execution_id=source_execution_id,
                parser_version=parser_version,
            )
        )

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = int(port.get("portid", "0"))
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            tunnel = service_el.get("tunnel") if service_el is not None else None
            banner = " ".join(part for part in [service_name, product, version] if part).strip() or None

            service = Service(
                service_id=new_id("service"),
                asset_id=host_asset.asset_id,
                port=port_id,
                protocol=protocol,
                state="open",
                name=service_name,
                banner=banner,
                source_tool=source_tool,
                source_execution_id=source_execution_id,
                parser_version=parser_version,
            )
            parsed["services"].append(service)

            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=source_tool,
                kind="open_port",
                snippet=f"{address_value}:{port_id}/{protocol} {banner or ''}".strip(),
                artifact_path=str(xml_path),
                selector={"kind": "xml", "path": "/nmaprun/host/ports/port"},
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
                    key="service.name",
                    value=service_name,
                    entity_type="service",
                    entity_id=service.service_id,
                    source_tool=source_tool,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=source_execution_id,
                    parser_version=parser_version,
                )
            )

            if port_id in HTTP_PORTS or "http" in (service_name or "").lower():
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

            if port_id in TLS_PORTS or tunnel == "ssl" or "https" in (service_name or "").lower():
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

            if port_id in MAIL_PORTS:
                parsed["observations"].append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="service.mail.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service.service_id,
                        source_tool=source_tool,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=source_execution_id,
                        parser_version=parser_version,
                    )
                )

    return parsed
