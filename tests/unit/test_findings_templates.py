from pathlib import Path

from attackcastle.core.models import Evidence, Observation, RunData, RunMetadata, WebApplication, new_id, now_utc
from attackcastle.findings.http_security_headers import generate_http_security_header_finding
from attackcastle.findings.schema import lint_templates, load_templates


def _blank_run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )


def test_templates_lint_clean():
    template_dir = Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "findings" / "templates"
    issues = lint_templates(template_dir)
    assert issues == []


def test_template_inheritance_resolution():
    template_dir = Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "findings" / "templates"
    templates = load_templates(template_dir)
    ids = {item["id"] for item in templates}
    assert "BASE_WEB_FINDING" in ids
    http_template = next(item for item in templates if item["id"] == "HTTP_HEADER_MISCONFIGURATION")
    assert "misconfiguration" in [tag.lower() for tag in http_template.get("tags", [])]
    assert http_template["category"] == "Web Security Misconfiguration"
    assert http_template["title"] == "HTTP Header Response Misconfiguration"


def test_http_security_header_finding_generator_aggregates_targets(tmp_path):
    run_data = _blank_run_data()
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web_1",
            asset_id="asset_1",
            url="https://example.com",
        )
    )
    run_data.evidence.append(
        Evidence(
            evidence_id="evidence_1",
            source_tool="test",
            kind="http_response",
            snippet="missing header evidence",
            artifact_path=str(tmp_path / "headers.json"),
        )
    )
    run_data.observations.append(
        Observation(
            observation_id=new_id("obs"),
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
            source_tool="test",
            evidence_ids=["evidence_1"],
        )
    )
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web_2",
            asset_id="asset_2",
            url="https://admin.example.com",
        )
    )
    run_data.evidence.append(
        Evidence(
            evidence_id="evidence_2",
            source_tool="test",
            kind="http_response",
            snippet="weak header evidence",
            artifact_path=str(tmp_path / "headers-2.json"),
        )
    )
    run_data.observations.append(
        Observation(
            observation_id=new_id("obs"),
            key="web.http_security_headers.analysis",
            value={
                "url": "https://admin.example.com",
                "status_code": 200,
                "core_missing": [],
                "core_weak": ["Content-Security-Policy"],
                "trigger_finding": True,
            },
            entity_type="web_app",
            entity_id="web_2",
            source_tool="test",
            evidence_ids=["evidence_2"],
        )
    )

    findings = generate_http_security_header_finding(
        run_data,
        template_dir=Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "findings" / "templates",
    )

    assert len(findings) == 1
    assert findings[0].title == "HTTP Header Response Misconfiguration"
    assert findings[0].severity.value == "low"
    assert {item["entity_id"] for item in findings[0].affected_entities} == {"web_1", "web_2"}
