from pathlib import Path

from attackcastle.core.models import Evidence, Observation, RunData, RunMetadata, WebApplication, now_utc
from attackcastle.findings.http_security_headers import generate_http_security_header_finding


def _template_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "findings" / "templates"


def _base_run_data() -> RunData:
    run_data = RunData(
        metadata=RunMetadata(
            run_id="quality",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web_1",
            asset_id="asset_1",
            url="https://example.com",
        )
    )
    return run_data


def test_findings_become_candidate_when_evidence_is_incomplete():
    run_data = _base_run_data()
    run_data.evidence.append(
        Evidence(
            evidence_id="e1",
            source_tool="web_probe",
            kind="http_response",
            snippet="missing headers",
            artifact_path=None,
            source_execution_id=None,
            confidence=0.9,
            timestamp=now_utc(),
        )
    )
    run_data.observations.append(
        Observation(
            observation_id="o1",
            key="web.http_security_headers.analysis",
            value={
                "url": "https://example.com",
                "status_code": 200,
                "core_missing": ["X-Frame-Options"],
                "core_weak": [],
                "trigger_finding": True,
            },
            entity_type="web_app",
            entity_id="web_1",
            source_tool="web_probe",
            confidence=0.9,
            evidence_ids=["e1"],
            timestamp=now_utc(),
        )
    )

    findings = generate_http_security_header_finding(run_data, template_dir=_template_dir())
    finding = next(item for item in findings if item.template_id == "HTTP_HEADER_MISCONFIGURATION")
    assert finding.status == "candidate"
    assert finding.evidence_quality_score < 0.8


def test_findings_confirm_with_good_evidence_and_corroboration():
    run_data = _base_run_data()
    run_data.evidence.append(
        Evidence(
            evidence_id="e2",
            source_tool="web_probe",
            kind="http_response",
            snippet="missing headers",
            artifact_path="/tmp/http.txt",
            source_execution_id="exec1",
            confidence=0.95,
            timestamp=now_utc(),
        )
    )
    run_data.observations.append(
        Observation(
            observation_id="o2",
            key="web.http_security_headers.analysis",
            value={
                "url": "https://example.com",
                "status_code": 200,
                "core_missing": ["X-Frame-Options"],
                "core_weak": [],
                "trigger_finding": True,
            },
            entity_type="web_app",
            entity_id="web_1",
            source_tool="web_probe",
            confidence=0.95,
            evidence_ids=["e2"],
            source_execution_id="exec1",
            timestamp=now_utc(),
        )
    )

    findings = generate_http_security_header_finding(run_data, template_dir=_template_dir())
    finding = next(item for item in findings if item.template_id == "HTTP_HEADER_MISCONFIGURATION")
    assert finding.status == "confirmed"
    assert finding.evidence_quality_score >= 0.8
