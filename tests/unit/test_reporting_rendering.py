from __future__ import annotations

import re
from pathlib import Path

from attackcastle.core.enums import RunState, Severity
from attackcastle.core.models import Evidence, Finding, RunData, RunMetadata, ToolExecution, now_utc
from attackcastle.reporting.builder import ReportBuilder
from attackcastle.storage.run_store import RunStore


def test_report_css_uses_square_modern_tabs_and_radii() -> None:
    css_path = Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "reporting" / "assets" / "report.css"
    css = css_path.read_text(encoding="utf-8")

    assert "--radius-sm: 2px;" in css
    assert "--radius-md: 3px;" in css
    assert "--radius-lg: 4px;" in css
    assert ".tab-btn" in css
    assert "border-bottom: 2px solid transparent;" in css
    assert ".tab-btn.active" in css
    assert "border-bottom-color: var(--accent);" in css
    assert "border-radius: 999px" not in css

    for disallowed_radius in ("12px", "14px", "16px", "18px", "20px", "22px", "24px"):
        assert f"border-radius: {disallowed_radius}" not in css


def test_asset_graph_css_uses_square_modern_surface_tokens() -> None:
    css_path = Path(__file__).resolve().parents[2] / "src" / "attackcastle" / "gui" / "web" / "asset_graph.css"
    css = css_path.read_text(encoding="utf-8")

    assert "--graph-bg: #0b1119;" in css
    assert "--graph-radius: 3px;" in css
    assert "background: var(--graph-bg);" in css
    assert "border-radius: 0;" in css
    assert "border-radius: 999px" not in css


def test_report_renders_expandable_http_evidence(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="reportproof")
    http_artifact = run_store.artifact_path("web_probe", "web_example.txt")
    http_artifact.write_text(
        "\n".join(
            [
                "url=https://example.com/login",
                "final_url=https://example.com/login",
                "status=200",
                "headers=server: nginx; content-type: text/html",
                "body=<html><body>login form here</body></html>",
            ]
        ),
        encoding="utf-8",
    )
    stdout_path = run_store.artifact_path("web_probe", "probe.stdout.txt")
    stdout_path.write_text("probe complete", encoding="utf-8")
    stderr_path = run_store.artifact_path("web_probe", "probe.stderr.txt")
    stderr_path.write_text("", encoding="utf-8")

    execution = ToolExecution(
        execution_id="exec_123",
        tool_name="web_probe",
        command="python urllib web probe",
        started_at=now_utc(),
        ended_at=now_utc(),
        exit_code=0,
        status="completed",
        capability="web_probe",
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        raw_artifact_paths=[str(http_artifact)],
    )
    evidence = Evidence(
        evidence_id="evidence_123",
        source_tool="web_probe",
        kind="http_response",
        snippet="login form here",
        artifact_path=str(http_artifact),
        source_execution_id="exec_123",
        confidence=0.9,
    )
    finding = Finding(
        finding_id="finding_123",
        template_id="LOGIN_PORTAL",
        title="Public Login Portal",
        severity=Severity.INFO,
        category="web",
        description="A public login interface is exposed.",
        impact="Can increase attack surface.",
        likelihood="High",
        recommendations=["Review access controls."],
        references=[],
        tags=["web"],
        affected_entities=[{"entity_type": "asset", "entity_id": "asset_1"}],
        evidence_ids=["evidence_123"],
        status="confirmed",
        evidence_quality_score=0.9,
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="reportproof",
            target_input="example.com",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        evidence=[evidence],
        findings=[finding],
        tool_executions=[execution],
    )

    result = ReportBuilder().build(
        run_data=run_data,
        run_store=run_store,
        audience="technical",
        export_csv=False,
        export_json_summary=False,
        export_integrations=False,
    )

    html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "View evidence (1)" in html
    assert "Request" in html
    assert "Response" in html
    assert "AttackCastle web probe" in html
    assert 'id="section-appendices"' in html
    assert "Audience</span><strong>consultant</strong>" in html


def test_report_section_layout_varies_by_audience_and_aliases_technical(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="reporterrors")
    started_at = now_utc()
    run_data = RunData(
        metadata=RunMetadata(
            run_id="reporterrors",
            target_input="example.com",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=started_at,
            state=RunState.FAILED,
        ),
        task_states=[
            {
                "key": "run-nmap",
                "label": "Nmap",
                "status": "failed",
                "error": "nmap exited unexpectedly",
                "detail": {"stage": "recon", "capability": "network_port_scan"},
            }
        ],
        tool_executions=[
            ToolExecution(
                execution_id="exec_report_errors",
                tool_name="nmap",
                command="nmap example.com",
                started_at=started_at,
                ended_at=started_at,
                exit_code=1,
                status="failed",
                error_message="permission denied",
            )
        ],
        errors=["run-nmap: nmap exited unexpectedly"],
        warnings=["nmap binary not found on PATH"],
    )

    client_html = Path(
        ReportBuilder().build(
            run_data=run_data,
            run_store=run_store,
            audience="client-safe",
            export_csv=False,
            export_json_summary=False,
            export_integrations=False,
        )["report_path"]
    ).read_text(encoding="utf-8")

    consultant_run_store = RunStore(output_root=tmp_path, run_id="reporterrors-consultant")
    consultant_html = Path(
        ReportBuilder().build(
            run_data=run_data,
            run_store=consultant_run_store,
            audience="technical",
            export_csv=False,
            export_json_summary=False,
            export_integrations=False,
        )["report_path"]
    ).read_text(encoding="utf-8")

    executive_run_store = RunStore(output_root=tmp_path, run_id="reporterrors-executive")
    executive_html = Path(
        ReportBuilder().build(
            run_data=run_data,
            run_store=executive_run_store,
            audience="executive",
            export_csv=False,
            export_json_summary=False,
            export_integrations=False,
        )["report_path"]
    ).read_text(encoding="utf-8")

    assert 'id="section-overview"' in client_html
    assert 'id="section-findings"' in client_html
    assert 'id="section-attack-surface"' in client_html
    assert 'id="section-investigation-queue"' not in client_html
    assert 'id="section-appendices"' not in client_html
    assert "Task: <code>run-nmap</code>" not in client_html

    assert 'id="section-overview"' in consultant_html
    assert 'id="section-findings"' in consultant_html
    assert 'id="section-investigation-queue"' in consultant_html
    assert 'id="section-attack-surface"' in consultant_html
    assert 'id="section-appendices"' in consultant_html
    assert "Task: <code>run-nmap</code>" in consultant_html
    assert "Exit Code: <code>1</code>" in consultant_html
    assert "Audience</span><strong>consultant</strong>" in consultant_html
    assert re.search(r'id="section-appendices".*?<details class="section-shell"\s*>', consultant_html, re.S)

    assert 'id="section-overview"' in executive_html
    assert 'id="section-findings"' in executive_html
    assert 'id="section-attack-surface"' not in executive_html
    assert 'id="section-investigation-queue"' not in executive_html
    assert 'id="section-appendices"' not in executive_html


def test_report_renders_extensions_section_only_when_outputs_exist(tmp_path: Path) -> None:
    started_at = now_utc()
    run_data = RunData(
        metadata=RunMetadata(
            run_id="extensions-report",
            target_input="example.com",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=started_at,
        ),
        facts={
            "gui.extensions": [
                {
                    "extension_id": "custom-tool",
                    "name": "Custom Tool",
                    "status": "completed",
                    "summary": "Custom report section ready.",
                    "report": {
                        "cards": [{"label": "Rows", "value": "3"}],
                        "notes": ["Generated by extension."],
                    },
                }
            ]
        },
    )
    run_store = RunStore(output_root=tmp_path, run_id="extensions-report")
    html = Path(
        ReportBuilder().build(
            run_data=run_data,
            run_store=run_store,
            audience="client-safe",
            export_csv=False,
            export_json_summary=False,
            export_integrations=False,
        )["report_path"]
    ).read_text(encoding="utf-8")

    clean_store = RunStore(output_root=tmp_path, run_id="extensions-report-clean")
    clean_html = Path(
        ReportBuilder().build(
            run_data=RunData(
                metadata=RunMetadata(
                    run_id="extensions-report-clean",
                    target_input="example.com",
                    profile="cautious",
                    output_dir=str(tmp_path),
                    started_at=started_at,
                )
            ),
            run_store=clean_store,
            audience="client-safe",
            export_csv=False,
            export_json_summary=False,
            export_integrations=False,
        )["report_path"]
    ).read_text(encoding="utf-8")

    assert 'id="section-extensions"' in html
    assert "Custom report section ready." in html
    assert 'id="section-extensions"' not in clean_html
