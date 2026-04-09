from attackcastle.core.enums import Severity
from attackcastle.core.models import Evidence, Finding, Observation, RunData, RunMetadata, Service, WebApplication, now_utc
from attackcastle.findings.normalizer import build_vulnerability_records


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="normalizer-test",
            target_input="example.com",
            profile="standard",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )


def test_build_vulnerability_records_merges_duplicate_findings_and_upgrades_confidence():
    run_data = _run_data()
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web-1",
            asset_id="asset-1",
            service_id="svc-1",
            url="https://example.com/items?id=1",
        )
    )
    run_data.evidence.extend(
        [
            Evidence(
                evidence_id="e1",
                source_tool="sqlmap",
                kind="http_response",
                snippet="database error returned",
            ),
            Evidence(
                evidence_id="e2",
                source_tool="manual-review",
                kind="note",
                snippet="stack trace confirms injectable parameter",
            ),
        ]
    )
    run_data.findings.extend(
        [
            Finding(
                finding_id="f1",
                template_id="",
                title="SQL Injection!",
                severity=Severity.HIGH,
                category="Injection",
                description="Potential SQL injection.",
                impact="Database compromise.",
                likelihood="High",
                recommendations=["Parameterize queries."],
                references=[],
                tags=["web"],
                affected_entities=[{"entity_type": "web_app", "entity_id": "web-1"}],
                evidence_ids=["e1"],
                status="candidate",
            ),
            Finding(
                finding_id="f2",
                template_id="SQLI_TEMPLATE",
                title="sql injection",
                severity=Severity.CRITICAL,
                category="Injection",
                description="Confirmed SQL injection.",
                impact="Database compromise.",
                likelihood="High",
                recommendations=["Parameterize queries."],
                references=[],
                tags=["web"],
                affected_entities=[{"entity_type": "web_app", "entity_id": "web-1"}],
                evidence_ids=["e2"],
                status="confirmed",
            ),
        ]
    )

    records = build_vulnerability_records(run_data)

    assert len(records) == 1
    record = records[0]
    assert record["severity"] == "critical"
    assert record["status"] == "confirmed"
    assert record["template_id"] == "SQLI_TEMPLATE"
    assert record["evidence_ids"] == ["e1", "e2"]
    assert record["evidence_count"] == 2
    assert record["evidence_snippets"] == [
        "database error returned",
        "stack trace confirms injectable parameter",
    ]
    assert record["affected"][0]["context"]["url"] == "https://example.com/items?id=1"
    assert record["confidence_score"] == 0.96


def test_build_vulnerability_records_turns_supported_raw_signals_into_records():
    run_data = _run_data()
    run_data.services.append(
        Service(
            service_id="svc-1",
            asset_id="asset-1",
            port=3389,
            protocol="tcp",
            state="open",
            name="rdp",
        )
    )
    run_data.observations.extend(
        [
            Observation(
                observation_id="o1",
                key="service.rdp.exposed",
                value=True,
                entity_type="service",
                entity_id="svc-1",
                source_tool="nmap",
            ),
            Observation(
                observation_id="o2",
                key="framework.scan.issue_count",
                value=0,
                entity_type="service",
                entity_id="svc-1",
                source_tool="framework-checks",
            ),
            Observation(
                observation_id="o3",
                key="vuln.cve.top_priority",
                value={"cve": "CVE-2026-9999", "priority": "critical"},
                entity_type="service",
                entity_id="svc-1",
                source_tool="cve-enricher",
            ),
        ]
    )

    records = build_vulnerability_records(run_data)
    titles = [record["title"] for record in records]

    assert titles == [
        "Prioritized CVE candidate: CVE-2026-9999",
        "RDP service exposed externally",
    ]
    assert all(record["category"] in {"CVE Prioritization", "Raw Scanner Signal"} for record in records)
    assert records[0]["severity"] == "high"
    assert records[1]["severity"] == "medium"
    assert records[1]["affected"][0]["context"] == {
        "asset_id": "asset-1",
        "port": 3389,
        "protocol": "tcp",
        "name": "rdp",
    }
