from __future__ import annotations

from pathlib import Path

from attackcastle.core.models import (
    Asset,
    Evidence,
    Observation,
    RunData,
    RunMetadata,
    TaskArtifactRef,
    TaskResult,
    ToolExecution,
    new_id,
    now_utc,
)
from attackcastle.findings.rule_engine import DetectionRuleEngine


def _run_data(tmp_path: Path) -> RunData:
    run_data = RunData(
        metadata=RunMetadata(
            run_id="rules",
            target_input="example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    run_data.assets.append(Asset(asset_id="asset-1", kind="domain", name="example.com"))
    return run_data


def _definition(operator: str, value="", *, scope: str = "combined_output", logic: str = "any") -> dict[str, object]:
    return {
        "id": f"RULE_{operator.replace(' ', '_').upper()}",
        "version": "1.0.0",
        "enabled": True,
        "title": operator,
        "severity": "medium",
        "category": "Rules",
        "description": "Description",
        "impact": "Impact",
        "likelihood": "Likelihood",
        "recommendations": ["Fix"],
        "references": [],
        "tags": ["rule"],
        "trigger": {"entity_type": "asset", "logic": "all", "conditions": [{"key": "entity.detected", "op": "exists"}]},
        "evidence_requirements": {"min_items": 0, "keys": []},
        "corroboration": {"min_observations": 1, "min_distinct_sources": 1, "min_confidence": 0.6, "required_assertions": []},
        "plextrac": {},
        "detection": {
            "logic": logic,
            "triggers": [{"id": "trigger-1", "enabled": True, "tool": "test_tool", "operator": operator, "scope": scope, "value": value}],
        },
    }


def _add_execution(run_data: RunData, tmp_path: Path, *, stdout: str = "", stderr: str = "", exit_code: int | None = 0, status: str = "completed", timed_out: bool = False) -> None:
    stdout_path = tmp_path / "stdout.txt"
    stderr_path = tmp_path / "stderr.txt"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    run_data.tool_executions.append(
        ToolExecution(
            execution_id="exec-1",
            tool_name="test_tool",
            command="test",
            started_at=now_utc(),
            ended_at=now_utc(),
            exit_code=exit_code,
            status=status,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            timed_out=timed_out,
            termination_reason="timeout" if timed_out else "completed",
        )
    )


def test_output_operators_generate_confirmed_findings(tmp_path):
    run_data = _run_data(tmp_path)
    _add_execution(run_data, tmp_path, stdout="vulnerable banner", stderr="clean")
    definitions = [
        _definition("output contains", "vulnerable", scope="stdout"),
        _definition("output does not contain", "panic", scope="combined_output"),
        _definition("output matches regex", "vuln[a-z]+", scope="stdout"),
    ]

    generated = DetectionRuleEngine(definitions).generate(run_data)

    assert len(generated) == 3
    assert all(item.status == "confirmed" for item in generated)
    assert generated[0].corroboration["matched_triggers"][0]["why"]


def test_header_and_status_operators_use_structured_http_analysis(tmp_path):
    run_data = _run_data(tmp_path)
    run_data.evidence.append(Evidence(evidence_id="evidence-1", source_tool="http_security_headers", kind="http_response_headers", snippet="headers"))
    run_data.observations.append(
        Observation(
            observation_id=new_id("obs"),
            key="web.http_security_headers.analysis",
            value={
                "url": "https://example.com/",
                "status_code": 200,
                "headers": {"server": "nginx", "x-frame-options": "SAMEORIGIN"},
            },
            entity_type="web_app",
            entity_id="web-1",
            source_tool="http_security_headers",
            evidence_ids=["evidence-1"],
        )
    )
    definitions = [
        {**_definition("header exists", "Server", scope="response_headers"), "id": "HEADER_EXISTS", "detection": {"logic": "any", "triggers": [{"id": "t1", "enabled": True, "tool": "http_security_headers", "operator": "header exists", "scope": "response_headers", "value": "Server"}]}},
        {**_definition("header missing", "Strict-Transport-Security", scope="response_headers"), "id": "HEADER_MISSING", "detection": {"logic": "any", "triggers": [{"id": "t1", "enabled": True, "tool": "http_security_headers", "operator": "header missing", "scope": "response_headers", "value": "Strict-Transport-Security"}]}},
        {**_definition("header equals", "X-Frame-Options=SAMEORIGIN", scope="response_headers"), "id": "HEADER_EQUALS", "detection": {"logic": "any", "triggers": [{"id": "t1", "enabled": True, "tool": "http_security_headers", "operator": "header equals", "scope": "response_headers", "value": "X-Frame-Options=SAMEORIGIN"}]}},
        {**_definition("status code equals", 200, scope="response_status"), "id": "STATUS_EQUALS", "detection": {"logic": "any", "triggers": [{"id": "t1", "enabled": True, "tool": "http_security_headers", "operator": "status code equals", "scope": "response_status", "value": 200}]}},
        {**_definition("status code in list", [200, 204], scope="response_status"), "id": "STATUS_LIST", "detection": {"logic": "any", "triggers": [{"id": "t1", "enabled": True, "tool": "http_security_headers", "operator": "status code in list", "scope": "response_status", "value": [200, 204]}]}},
    ]

    generated = DetectionRuleEngine(definitions).generate(run_data)

    assert {item.template_id for item in generated} == {"HEADER_EXISTS", "HEADER_MISSING", "HEADER_EQUALS", "STATUS_EQUALS", "STATUS_LIST"}
    assert generated[0].evidence_ids == ["evidence-1"]


def test_execution_operators_and_all_logic(tmp_path):
    run_data = _run_data(tmp_path)
    _add_execution(run_data, tmp_path, stderr="timed out", exit_code=7, status="failed", timed_out=True)
    definitions = [
        _definition("exit code equals", 7, scope="tool_execution"),
        _definition("tool failed", "", scope="tool_execution"),
        _definition("timeout occurred", "", scope="tool_execution"),
        {
            **_definition("tool failed", "", scope="tool_execution", logic="all"),
            "id": "ALL_RULE",
            "detection": {
                "logic": "all",
                "triggers": [
                    {"id": "failed", "enabled": True, "tool": "test_tool", "operator": "tool failed", "scope": "tool_execution"},
                    {"id": "timeout", "enabled": True, "tool": "test_tool", "operator": "timeout occurred", "scope": "tool_execution"},
                ],
            },
        },
    ]

    generated = DetectionRuleEngine(definitions).generate(run_data)

    assert len(generated) == 4
    assert any(item.template_id == "ALL_RULE" for item in generated)


def test_disabled_definition_and_trigger_do_not_fire(tmp_path):
    run_data = _run_data(tmp_path)
    _add_execution(run_data, tmp_path, stdout="secret")
    disabled = _definition("output contains", "secret")
    disabled["enabled"] = False
    disabled_trigger = _definition("output contains", "secret")
    disabled_trigger["id"] = "DISABLED_TRIGGER"
    disabled_trigger["detection"]["triggers"][0]["enabled"] = False  # type: ignore[index]

    generated = DetectionRuleEngine([disabled, disabled_trigger]).generate(run_data)

    assert generated == []


def test_task_result_raw_output_is_supported(tmp_path):
    run_data = _run_data(tmp_path)
    stdout_path = tmp_path / "task_stdout.txt"
    stdout_path.write_text("task finding", encoding="utf-8")
    run_data.task_results.append(
        TaskResult(
            task_id="task-1",
            task_type="test_tool",
            status="completed",
            command="test",
            exit_code=0,
            started_at=now_utc(),
            finished_at=now_utc(),
            raw_artifacts=[TaskArtifactRef(artifact_type="stdout", path=str(stdout_path))],
        )
    )

    generated = DetectionRuleEngine([_definition("output contains", "task finding", scope="stdout")]).generate(run_data)

    assert len(generated) == 1
    assert generated[0].corroboration["raw_artifact_path"] == str(stdout_path)

