from __future__ import annotations

import logging
from pathlib import Path

from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import (
    Asset,
    EvidenceArtifact,
    RunData,
    RunMetadata,
    TaskArtifactRef,
    TaskResult,
    ToolExecution,
    now_utc,
)
from attackcastle.orchestration.scheduler import WorkflowScheduler
from attackcastle.orchestration.task_graph import TaskDefinition
from attackcastle.storage.run_store import RunStore


class _AuditStub:
    def write(self, _event_type: str, _payload: dict[str, object]) -> None:
        return


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="scheduler-matrix-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_scheduler_skips_matrix_gated_task_and_runs_dependents(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="matrix-deadlock")
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {"task_start_delay_seconds": 0.0},
            "escalation": {"matrix": {"wordpress": {"tasks": ["run-wpscan"]}}},
        },
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-matrix-test"),
        audit=_AuditStub(),
    )
    executed = {"findings": False}

    def _unexpected_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        raise AssertionError("Matrix-gated task should not execute in this scenario.")

    def _findings_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        executed["findings"] = True
        return AdapterResult()

    tasks = [
        TaskDefinition(
            key="run-wpscan",
            label="Run WPScan",
            capability="cms_wordpress_scan",
            stage="enumeration",
            runner=_unexpected_runner,
            should_run=lambda _run_data: (True, "always"),
        ),
        TaskDefinition(
            key="generate-findings",
            label="Generate findings",
            capability="findings_engine",
            stage="analysis",
            runner=_findings_runner,
            should_run=lambda _run_data: (True, "always"),
            dependencies=["run-wpscan"],
        ),
    ]
    scheduler = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False)
    states = scheduler.execute(tasks=tasks, context=context, run_data=_run_data())
    state_by_key = {state.key: state.status for state in states}

    assert state_by_key["run-wpscan"] == "skipped"
    assert state_by_key["generate-findings"] == "completed"
    assert executed["findings"] is True


def test_scheduler_emits_live_result_events_and_persists_task_rows_in_checkpoints(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-live-events")
    started_at = now_utc()
    emitted: list[tuple[str, dict[str, object]]] = []
    artifact_path = run_store.artifact_path("subfinder", "stdout.txt")
    artifact_path.write_text("www.example.com\n", encoding="utf-8")
    task_result = TaskResult(
        task_id="task_result_subfinder",
        task_type="EnumerateSubdomains",
        status="completed",
        command="subfinder -silent -d example.com",
        exit_code=0,
        started_at=started_at,
        finished_at=started_at,
        raw_artifacts=[TaskArtifactRef(artifact_type="stdout", path=str(artifact_path))],
    )
    tool_execution = ToolExecution(
        execution_id="exec_subfinder",
        tool_name="subfinder",
        command="subfinder -silent -d example.com",
        started_at=started_at,
        ended_at=started_at,
        exit_code=0,
        status="completed",
        capability="subdomain_enumeration",
        stdout_path=str(artifact_path),
        stderr_path=str(artifact_path),
    )
    evidence_artifact = EvidenceArtifact(
        artifact_id="artifact_subfinder",
        kind="stdout",
        path=str(artifact_path),
        source_tool="subfinder",
        caption="EnumerateSubdomains stdout",
        source_task_id=task_result.task_id,
        source_execution_id=tool_execution.execution_id,
    )
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-live-events"),
        audit=_AuditStub(),
        event_emitter=lambda event, payload: emitted.append((event, payload)),
    )

    def _runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(
            assets=[
                Asset(
                    asset_id="asset_subfinder",
                    kind="domain",
                    name="www.example.com",
                    source_tool="subfinder",
                    source_execution_id=tool_execution.execution_id,
                )
            ],
            evidence_artifacts=[evidence_artifact],
            task_results=[task_result],
            tool_executions=[tool_execution],
        )

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="enumerate-subdomains",
                label="Enumerate Subdomains",
                capability="subdomain_enumeration",
                stage="enumeration",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    checkpoint = run_store.load_latest_checkpoint()
    assert checkpoint is not None
    checkpoint_run_data = checkpoint["run_data"]
    assert checkpoint_run_data["task_states"][0]["key"] == "enumerate-subdomains"
    assert checkpoint_run_data["task_states"][0]["status"] == "completed"
    assert {event for event, _payload in emitted} >= {
        "entity.upserted",
        "artifact.available",
        "task_result.recorded",
        "tool_execution.recorded",
    }
    assert states[0].status == "completed"


def test_scheduler_marks_adapter_results_with_errors_as_failed(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-error-state")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-error-state"),
        audit=_AuditStub(),
    )

    def _runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(errors=["subdomain enumeration failed for 2 root domain(s)"])

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="enumerate-subdomains",
                label="Enumerate Subdomains",
                capability="subdomain_enumeration",
                stage="enumeration",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
                retryable=False,
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert states[0].status == "failed"
    assert "subdomain enumeration failed" in str(states[0].error)
