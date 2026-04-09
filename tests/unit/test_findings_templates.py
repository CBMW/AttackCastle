from pathlib import Path

from attackcastle.core.models import Observation, RunData, RunMetadata, WebApplication, new_id, now_utc
from attackcastle.findings.engine import FindingsEngine
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
    assert "web" in [tag.lower() for tag in http_template.get("tags", [])]
    assert http_template["category"] == "Web Security Hardening"


def test_findings_engine_applies_suppression(tmp_path):
    suppression_path = tmp_path / "suppressions.json"
    suppression_path.write_text(
        '[{"template_id":"HTTP_HEADER_MISCONFIGURATION","entity_type":"web_app","entity_id":"web_1","reason":"accepted risk"}]',
        encoding="utf-8",
    )

    run_data = _blank_run_data()
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web_1",
            asset_id="asset_1",
            url="https://example.com",
        )
    )
    evidence_id = new_id("evidence")
    from attackcastle.core.models import Evidence

    run_data.evidence.append(
        Evidence(
            evidence_id=evidence_id,
            source_tool="test",
            kind="http_response",
            snippet="missing header evidence",
        )
    )
    run_data.observations.append(
        Observation(
            observation_id=new_id("obs"),
            key="web.missing_security_headers",
            value=["x-frame-options"],
            entity_type="web_app",
            entity_id="web_1",
            source_tool="test",
            evidence_ids=[evidence_id],
        )
    )
    engine = FindingsEngine(
        template_dir=Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "findings" / "templates",
        suppression_file=suppression_path,
    )
    findings = engine.generate(run_data)
    matched = [finding for finding in findings if finding.template_id == "HTTP_HEADER_MISCONFIGURATION"]
    assert matched
    assert matched[0].suppressed is True
    assert matched[0].suppression_reason == "accepted risk"
