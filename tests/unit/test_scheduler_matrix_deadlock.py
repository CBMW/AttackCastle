from __future__ import annotations

import logging
from pathlib import Path

from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData, RunMetadata, now_utc
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

