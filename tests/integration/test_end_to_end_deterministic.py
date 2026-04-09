from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import attackcastle.app as app_module
from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.interfaces import AdapterResult
from attackcastle.core.models import (
    Asset,
    Evidence,
    Observation,
    Service,
    TLSAsset,
    Technology,
    WebApplication,
)


FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


class FixtureDNSAdapter:
    name = "dns_fixture"
    capability = "dns_resolution"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context, run_data):  # noqa: ANN001
        return ["resolve example.com"]

    def run(self, context, run_data):  # noqa: ANN001
        result = AdapterResult()
        execution_id = "exec_dns_fixture"
        artifact_path = context.run_store.artifact_path(self.name, "dns_fixture.txt")
        artifact_path.write_text("example.com -> 203.0.113.10\n", encoding="utf-8")

        domain_asset = Asset(
            asset_id="asset_domain_fixture",
            kind="domain",
            name="example.com",
            source_tool=self.name,
            source_execution_id=execution_id,
            parser_version="fixture_dns_v1",
        )
        host_asset = Asset(
            asset_id="asset_host_fixture",
            kind="host",
            name="203.0.113.10",
            ip="203.0.113.10",
            parent_asset_id=domain_asset.asset_id,
            source_tool=self.name,
            source_execution_id=execution_id,
            parser_version="fixture_dns_v1",
        )
        evidence = Evidence(
            evidence_id="evidence_dns_fixture",
            source_tool=self.name,
            kind="dns_resolution",
            snippet="example.com -> 203.0.113.10",
            artifact_path=str(artifact_path),
            selector={"kind": "line", "line": 1},
            source_execution_id=execution_id,
            parser_version="fixture_dns_v1",
            confidence=1.0,
            timestamp=FIXED_TIME,
        )
        observation = Observation(
            observation_id="obs_dns_fixture",
            key="dns.resolved_ips",
            value=["203.0.113.10"],
            entity_type="asset",
            entity_id=domain_asset.asset_id,
            source_tool=self.name,
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
            source_execution_id=execution_id,
            parser_version="fixture_dns_v1",
            timestamp=FIXED_TIME,
        )
        result.assets.extend([domain_asset, host_asset])
        result.evidence.append(evidence)
        result.observations.append(observation)
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="fixture_dns",
                started_at=FIXED_TIME,
                ended_at=FIXED_TIME,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        return result


class FixtureNmapAdapter:
    name = "nmap_fixture"
    capability = "network_port_scan"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context, run_data):  # noqa: ANN001
        return ["parse nmap fixture xml"]

    def run(self, context, run_data):  # noqa: ANN001
        fixture_xml_path = (
            Path(__file__).resolve().parents[1] / "fixtures" / "integration" / "nmap_fixture.xml"
        )
        root = ET.fromstring(fixture_xml_path.read_text(encoding="utf-8"))
        host_ip = root.find("host/address").attrib["addr"]  # type: ignore[union-attr]
        host_asset = next(asset for asset in run_data.assets if asset.ip == host_ip)
        execution_id = "exec_nmap_fixture"

        result = AdapterResult()
        for port in root.findall("host/ports/port"):
            port_id = int(port.attrib["portid"])
            service_name = (port.find("service").attrib.get("name", "unknown"))  # type: ignore[union-attr]
            banner = " ".join(
                part
                for part in [
                    service_name,
                    (port.find("service").attrib.get("product") if port.find("service") is not None else None),
                    (port.find("service").attrib.get("version") if port.find("service") is not None else None),
                ]
                if part
            )
            service_id = f"service_fixture_{port_id}"
            service = Service(
                service_id=service_id,
                asset_id=host_asset.asset_id,
                port=port_id,
                protocol=port.attrib.get("protocol", "tcp"),
                state="open",
                name=service_name,
                banner=banner,
                source_tool=self.name,
                source_execution_id=execution_id,
                parser_version="fixture_nmap_v1",
            )
            evidence_id = f"evidence_nmap_{port_id}"
            evidence = Evidence(
                evidence_id=evidence_id,
                source_tool=self.name,
                kind="open_port",
                snippet=f"{host_ip}:{port_id}/{service.protocol} {banner}",
                artifact_path=str(fixture_xml_path),
                selector={"kind": "xml", "path": "/nmaprun/host/ports/port"},
                source_execution_id=execution_id,
                parser_version="fixture_nmap_v1",
                confidence=1.0,
                timestamp=FIXED_TIME,
            )
            result.services.append(service)
            result.evidence.append(evidence)
            result.observations.append(
                Observation(
                    observation_id=f"obs_nmap_open_{port_id}",
                    key="service.open",
                    value=True,
                    entity_type="service",
                    entity_id=service_id,
                    source_tool=self.name,
                    confidence=1.0,
                    evidence_ids=[evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_nmap_v1",
                    timestamp=FIXED_TIME,
                )
            )
            if port_id in {80, 443}:
                result.observations.append(
                    Observation(
                        observation_id=f"obs_nmap_http_{port_id}",
                        key="service.http.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service_id,
                        source_tool=self.name,
                        confidence=0.95,
                        evidence_ids=[evidence_id],
                        source_execution_id=execution_id,
                        parser_version="fixture_nmap_v1",
                        timestamp=FIXED_TIME,
                    )
                )
            if port_id == 443:
                result.observations.append(
                    Observation(
                        observation_id=f"obs_nmap_tls_{port_id}",
                        key="service.tls.detected",
                        value=True,
                        entity_type="service",
                        entity_id=service_id,
                        source_tool=self.name,
                        confidence=0.95,
                        evidence_ids=[evidence_id],
                        source_execution_id=execution_id,
                        parser_version="fixture_nmap_v1",
                        timestamp=FIXED_TIME,
                    )
                )

        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="fixture_nmap_parser",
                started_at=FIXED_TIME,
                ended_at=FIXED_TIME,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(fixture_xml_path)],
            )
        )
        return result


class FixtureWebAdapter:
    name = "web_fixture"
    capability = "web_probe"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context, run_data):  # noqa: ANN001
        return ["read mocked web response fixture"]

    def run(self, context, run_data):  # noqa: ANN001
        fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "integration" / "web_response.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        host_asset = next(asset for asset in run_data.assets if asset.ip == "203.0.113.10")
        web_service = next(service for service in run_data.services if service.port == 443)
        execution_id = "exec_web_fixture"
        artifact_path = context.run_store.artifact_path(self.name, "web_fixture_response.txt")
        artifact_path.write_text(
            f"status={data['status_code']}\nheaders={json.dumps(data['headers'])}\nbody={data['body']}\n",
            encoding="utf-8",
        )

        result = AdapterResult()
        web_app = WebApplication(
            webapp_id="web_fixture_1",
            asset_id=host_asset.asset_id,
            service_id=web_service.service_id,
            url=data["url"],
            status_code=data["status_code"],
            title="Example WP Site",
            forms_count=1,
            source_tool=self.name,
            source_execution_id=execution_id,
            parser_version="fixture_web_v1",
        )
        evidence = Evidence(
            evidence_id="evidence_web_fixture",
            source_tool=self.name,
            kind="http_response",
            snippet=data["body"][:120],
            artifact_path=str(artifact_path),
            selector={"kind": "bytes", "start": 0, "end": 120},
            source_execution_id=execution_id,
            parser_version="fixture_web_v1",
            confidence=0.9,
            timestamp=FIXED_TIME,
        )
        result.web_apps.append(web_app)
        result.evidence.append(evidence)
        result.observations.extend(
            [
                Observation(
                    observation_id="obs_web_status",
                    key="web.status_code",
                    value=200,
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=1.0,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_web_v1",
                    timestamp=FIXED_TIME,
                ),
                Observation(
                    observation_id="obs_web_forms",
                    key="web.forms.count",
                    value=1,
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_web_v1",
                    timestamp=FIXED_TIME,
                ),
                Observation(
                    observation_id="obs_web_headers",
                    key="web.missing_security_headers",
                    value=["content-security-policy", "x-frame-options"],
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_web_v1",
                    timestamp=FIXED_TIME,
                ),
                Observation(
                    observation_id="obs_wp_detected",
                    key="tech.wordpress.detected",
                    value=True,
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=0.95,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_web_v1",
                    timestamp=FIXED_TIME,
                ),
                Observation(
                    observation_id="obs_wp_version",
                    key="tech.wordpress.version",
                    value="6.4.3",
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_web_v1",
                    timestamp=FIXED_TIME,
                ),
            ]
        )
        result.technologies.append(
            Technology(
                tech_id="tech_fixture_wp",
                asset_id=host_asset.asset_id,
                webapp_id=web_app.webapp_id,
                name="WordPress",
                version="6.4.3",
                confidence=0.95,
                source_tool=self.name,
                source_execution_id=execution_id,
                parser_version="fixture_web_v1",
            )
        )
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="fixture_web_response",
                started_at=FIXED_TIME,
                ended_at=FIXED_TIME,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        return result


class FixtureVHostAdapter:
    name = "vhost_fixture"
    capability = "vhost_discovery"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context, run_data):  # noqa: ANN001
        return ["no-op vhost fixture"]

    def run(self, context, run_data):  # noqa: ANN001
        result = AdapterResult()
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="fixture_vhost",
                started_at=FIXED_TIME,
                ended_at=FIXED_TIME,
                status="completed",
                execution_id="exec_vhost_fixture",
                capability=self.capability,
                exit_code=0,
            )
        )
        return result


class FixtureTLSAdapter:
    name = "tls_fixture"
    capability = "tls_probe"
    noise_score = 1
    cost_score = 1

    def preview_commands(self, context, run_data):  # noqa: ANN001
        return ["mock tls handshake"]

    def run(self, context, run_data):  # noqa: ANN001
        host_asset = next(asset for asset in run_data.assets if asset.ip == "203.0.113.10")
        tls_service = next(service for service in run_data.services if service.port == 443)
        execution_id = "exec_tls_fixture"
        artifact_path = context.run_store.artifact_path(self.name, "tls_fixture.txt")
        artifact_path.write_text("protocol=TLSv1.0\ncipher=AES128-SHA\n", encoding="utf-8")

        result = AdapterResult()
        tls_entry = TLSAsset(
            tls_id="tls_fixture_1",
            asset_id=host_asset.asset_id,
            host="203.0.113.10",
            port=443,
            service_id=tls_service.service_id,
            protocol="TLSv1",
            cipher="AES128-SHA",
            subject="CN=example.com",
            issuer="CN=Fixture CA",
            not_after="2026-02-01T00:00:00+00:00",
            source_tool=self.name,
            source_execution_id=execution_id,
            parser_version="fixture_tls_v1",
        )
        evidence = Evidence(
            evidence_id="evidence_tls_fixture",
            source_tool=self.name,
            kind="tls_handshake",
            snippet="protocol=TLSv1 cipher=AES128-SHA",
            artifact_path=str(artifact_path),
            selector={"kind": "line", "line": 1},
            source_execution_id=execution_id,
            parser_version="fixture_tls_v1",
            confidence=0.95,
            timestamp=FIXED_TIME,
        )
        result.tls_assets.append(tls_entry)
        result.evidence.append(evidence)
        result.observations.extend(
            [
                Observation(
                    observation_id="obs_tls_protocol",
                    key="tls.protocol.version",
                    value="TLSv1",
                    entity_type="tls",
                    entity_id=tls_entry.tls_id,
                    source_tool=self.name,
                    confidence=0.95,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_tls_v1",
                    timestamp=FIXED_TIME,
                ),
                Observation(
                    observation_id="obs_tls_weak",
                    key="tls.weak_protocol",
                    value=True,
                    entity_type="tls",
                    entity_id=tls_entry.tls_id,
                    source_tool=self.name,
                    confidence=0.95,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="fixture_tls_v1",
                    timestamp=FIXED_TIME,
                ),
            ]
        )
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="fixture_tls",
                started_at=FIXED_TIME,
                ended_at=FIXED_TIME,
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        return result


class FailingWebAdapter(FixtureWebAdapter):
    name = "web_fixture_fail"

    def run(self, context, run_data):  # noqa: ANN001
        raise RuntimeError("fixture web failure")


def _snapshot_from_payload(payload: dict) -> dict:
    confirmed = sorted(
        finding["template_id"]
        for finding in payload["findings"]
        if finding.get("status") == "confirmed" and not finding.get("suppressed", False)
    )
    candidates = sorted(
        finding["template_id"]
        for finding in payload["findings"]
        if finding.get("status") == "candidate" and not finding.get("suppressed", False)
    )
    tool_statuses = {
        execution["tool_name"]: execution["status"]
        for execution in payload["tool_executions"]
        if execution["tool_name"].endswith("_fixture")
    }
    evidence_quality_all_present = all(
        bool(item.get("source_tool"))
        and bool(item.get("source_execution_id"))
        and bool(item.get("artifact_path"))
        and item.get("timestamp") is not None
        and item.get("confidence") is not None
        and bool((item.get("snippet") or "").strip())
        for item in payload["evidence"]
    )
    return {
        "scope_count": len(payload["scope"]),
        "asset_count": len(payload["assets"]),
        "service_count": len(payload["services"]),
        "web_app_count": len(payload["web_apps"]),
        "tls_count": len(payload["tls_assets"]),
        "confirmed_findings": confirmed,
        "candidate_findings": candidates,
        "tool_statuses": tool_statuses,
        "evidence_quality_all_present": evidence_quality_all_present,
        "state": payload["metadata"]["state"],
    }


def test_end_to_end_pipeline_with_fixtures(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "_build_run_id", lambda: "deterministic_fixture_run")
    monkeypatch.setattr(app_module, "ResolveHostsAdapter", FixtureDNSAdapter)
    monkeypatch.setattr(app_module, "NmapAdapter", FixtureNmapAdapter)
    monkeypatch.setattr(app_module, "WebProbeAdapter", FixtureWebAdapter)
    monkeypatch.setattr(app_module, "VHostDiscoveryAdapter", FixtureVHostAdapter)
    monkeypatch.setattr(app_module, "TLSAdapter", FixtureTLSAdapter)

    outcome = app_module.run_scan(
        target_input="example.com",
        output_directory=str(tmp_path / "out"),
        profile="cautious",
        no_report=False,
        verbose=False,
    )
    assert outcome.run_id == "deterministic_fixture_run"
    payload = json.loads(outcome.json_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    snapshot = _snapshot_from_payload(payload)
    expected_path = Path(__file__).resolve().parents[1] / "fixtures" / "integration" / "expected_end_to_end_snapshot.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert snapshot == expected


def test_partial_failure_tolerance_with_fixtures(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "_build_run_id", lambda: "deterministic_failure_run")
    monkeypatch.setattr(app_module, "ResolveHostsAdapter", FixtureDNSAdapter)
    monkeypatch.setattr(app_module, "NmapAdapter", FixtureNmapAdapter)
    monkeypatch.setattr(app_module, "WebProbeAdapter", FailingWebAdapter)
    monkeypatch.setattr(app_module, "VHostDiscoveryAdapter", FixtureVHostAdapter)
    monkeypatch.setattr(app_module, "TLSAdapter", FixtureTLSAdapter)

    outcome = app_module.run_scan(
        target_input="example.com",
        output_directory=str(tmp_path / "out"),
        profile="cautious",
        no_report=False,
        verbose=False,
    )

    assert outcome.json_path is not None
    assert outcome.report_path is not None
    payload = json.loads(outcome.json_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["state"] == "failed"
    assert payload["errors"]
    assert any("fixture web failure" in item for item in payload["errors"])
