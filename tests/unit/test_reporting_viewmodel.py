import json
from pathlib import Path

from attackcastle.core.enums import RunState
from attackcastle.core.models import RunData, RunMetadata, now_utc
from attackcastle.core.models import ToolExecution
from attackcastle.reporting.schema import validate_view_model
from attackcastle.reporting.sections import DEFAULT_SECTION_PLUGINS
from attackcastle.reporting.viewmodel import build_view_model


def test_view_model_contract_validation():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )
    view_model = build_view_model(run_data, audience="consultant")
    view_model["sections"] = [
        plugin.render(view_model, "consultant")
        for plugin in DEFAULT_SECTION_PLUGINS
        if plugin.should_render(view_model, "consultant")
    ]
    validate_view_model(view_model)
    assert [section["id"] for section in view_model["sections"]] == [
        "overview",
        "findings",
        "investigation-queue",
        "attack-surface",
        "appendices",
    ]


def test_view_model_exposes_extension_rows_when_gui_extensions_exist():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="extensions",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        ),
        facts={
            "gui.extensions": [
                {
                    "extension_id": "custom-tool",
                    "name": "Custom Tool",
                    "status": "completed",
                    "summary": "Custom report section ready.",
                }
            ]
        },
    )

    view_model = build_view_model(run_data, audience="consultant")

    assert view_model["extensions"][0]["extension_id"] == "custom-tool"


def test_section_plugins_include_extensions_when_outputs_exist():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="extensions-sections",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        ),
        facts={
            "gui.extensions": [
                {
                    "extension_id": "custom-tool",
                    "name": "Custom Tool",
                    "status": "completed",
                    "summary": "Custom report section ready.",
                }
            ]
        },
    )
    view_model = build_view_model(run_data, audience="consultant")
    sections = [
        plugin.render(view_model, "consultant")
        for plugin in DEFAULT_SECTION_PLUGINS
        if plugin.should_render(view_model, "consultant")
    ]

    assert [section["id"] for section in sections] == [
        "overview",
        "findings",
        "investigation-queue",
        "attack-surface",
        "extensions",
        "appendices",
    ]


def test_view_model_snapshot_contract():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="snapshot",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )
    view_model = build_view_model(run_data, audience="consultant")
    snapshot_path = Path(__file__).resolve().parents[1] / "fixtures" / "report_viewmodel_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    for key in snapshot["required_top_level"]:
        assert key in view_model
    assert sorted(view_model["metadata"].keys()) == snapshot["metadata_keys"]
    assert sorted(view_model["summary"].keys()) == snapshot["summary_keys"]


def test_view_model_includes_empty_execution_issues_for_clean_run():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="clean",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
            state=RunState.COMPLETED,
        )
    )

    view_model = build_view_model(run_data, audience="consultant")

    assert view_model["execution_issues"] == []
    assert view_model["execution_issues_summary"]["total_count"] == 0
    assert view_model["completeness_status"] == "healthy"


def test_view_model_normalizes_technical_audience_and_exposes_grouped_sections():
    run_data = RunData(
        metadata=RunMetadata(
            run_id="alias",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )

    view_model = build_view_model(run_data, audience="technical")

    assert view_model["audience"] == "consultant"
    assert sorted(view_model["overview"].keys()) == ["audience", "context", "executive", "remediation", "risk", "stories"]
    assert "candidate_findings" in view_model["investigation_queue"]
    assert "services" in view_model["attack_surface"]
    assert "errors" in view_model["appendices"]


def test_view_model_normalizes_execution_issues_from_failures():
    started_at = now_utc()
    run_data = RunData(
        metadata=RunMetadata(
            run_id="issues",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
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
            },
            {
                "key": "run-web-discovery",
                "label": "Web Discovery",
                "status": "skipped",
                "detail": {"reason": "dependency not available", "stage": "analysis"},
            },
        ],
        tool_executions=[
            ToolExecution(
                execution_id="exec_issue",
                tool_name="nuclei",
                command="nuclei -target https://example.com",
                started_at=started_at,
                ended_at=started_at,
                exit_code=2,
                status="failed",
                error_message="templates failed to load",
            )
        ],
        warnings=["nuclei binary not found on PATH"],
        errors=["run-nmap: nmap exited unexpectedly"],
        facts={
            "web_probe.coverage_gaps": [
                {
                    "reason": "target returned blocking response",
                    "impact": "web probing incomplete",
                    "suggested_action": "retry with alternate headers",
                    "url": "https://example.com",
                }
            ]
        },
    )

    view_model = build_view_model(run_data, audience="technical")

    issue_kinds = {item["kind"] for item in view_model["execution_issues"]}
    assert {"run_state", "task", "tool", "run_error", "warning", "coverage_gap"}.issubset(issue_kinds)
    assert view_model["execution_issues_summary"]["total_count"] >= 6
    assert view_model["execution_issues_summary"]["blocking_count"] >= 1
    assert view_model["execution_issues_summary"]["coverage_count"] == 1
    assert view_model["completeness_status"] == "failed"
    assert view_model["audience"] == "consultant"
