from __future__ import annotations

import logging
import time
from hashlib import sha1
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


def _instance_key(task_key: str, task_input: str, iteration: int = 1) -> str:
    digest = sha1(task_input.encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return f"{task_key}::iter{iteration}::{digest}"


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


def test_scheduler_runs_findings_after_failed_terminal_dependency(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="failed-dependency-findings")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("failed-dependency-findings"),
        audit=_AuditStub(),
    )
    executed = {"findings": False}

    def _failed_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(errors=["HTTP security header check did not return usable headers"])

    def _findings_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        executed["findings"] = True
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="check-http-security-headers",
                label="Checking HTTP security headers",
                capability="http_security_headers_check",
                stage="enumeration",
                runner=_failed_runner,
                should_run=lambda _run_data: (True, "http targets"),
                retryable=False,
            ),
            TaskDefinition(
                key="generate-findings",
                label="Generate findings",
                capability="findings_engine",
                stage="analysis",
                runner=_findings_runner,
                should_run=lambda _run_data: (True, "always"),
                dependencies=["check-http-security-headers"],
            ),
        ],
        context=context,
        run_data=_run_data(),
    )

    state_by_key = {state.key: state.status for state in states}
    assert state_by_key["check-http-security-headers"] == "failed"
    assert state_by_key["generate-findings"] == "completed"
    assert executed["findings"] is True


def test_scheduler_deadlock_state_lists_blocking_dependencies(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="deadlock-details")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("deadlock-details"),
        audit=_AuditStub(),
    )

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="missing-upstream-task",
                label="Missing upstream task",
                capability="upstream",
                stage="analysis",
                runner=lambda _context, _run_data: AdapterResult(),
                should_run=lambda _run_data: (True, "always"),
                dependencies=["generate-findings"],
            ),
            TaskDefinition(
                key="generate-findings",
                label="Generate findings",
                capability="findings_engine",
                stage="analysis",
                runner=lambda _context, _run_data: AdapterResult(),
                should_run=lambda _run_data: (True, "always"),
                dependencies=["missing-upstream-task"],
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    state_by_key = {state.key: state for state in states}
    assert state_by_key["generate-findings"].status == "skipped"
    assert state_by_key["generate-findings"].detail["reason"] == "dependency_deadlock"
    assert state_by_key["generate-findings"].detail["blocking_dependencies"] == ["missing-upstream-task"]


def test_scheduler_ignores_dependencies_omitted_from_current_plan(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="omitted-dependency-findings")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("omitted-dependency-findings"),
        audit=_AuditStub(),
    )
    executed = {"findings": False}

    def _findings_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        executed["findings"] = True
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="generate-findings",
                label="Generate findings",
                capability="findings_engine",
                stage="analysis",
                runner=_findings_runner,
                should_run=lambda _run_data: (True, "always"),
                dependencies=["run-nmap", "check-http-security-headers", "assess-web"],
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert states[0].status == "completed"
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
    assert (run_store.data_dir / "scan_data.partial.json").exists()
    assert states[0].status == "completed"


def test_scheduler_records_running_fanout_task_state_before_completion(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-running-fanout")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-running-fanout"),
        audit=_AuditStub(),
    )
    observed_running_rows: list[dict[str, object]] = []

    def _runner(task_context: AdapterContext, run_data: RunData) -> AdapterResult:
        matching_rows = [
            row
            for row in run_data.task_states
            if row.get("status") == "running"
            and row.get("detail", {}).get("instance_key") == task_context.task_instance_key
        ]
        observed_running_rows.extend(matching_rows)
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
                can_run_many=True,
                input_items=lambda _run_data: ["13.111.70.13", "18.65.244.102"],
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    checkpoint = run_store.load_latest_checkpoint()
    assert checkpoint is not None
    assert len(observed_running_rows) == 2
    assert {row["detail"]["task_inputs"][0] for row in observed_running_rows} == {
        "13.111.70.13",
        "18.65.244.102",
    }
    assert all(state.status == "completed" for state in states)
    assert all(row["status"] == "completed" for row in checkpoint["run_data"]["task_states"])


def test_scheduler_resume_skips_only_completed_fanout_instances(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-resume-fanout")
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-resume-fanout"),
        audit=_AuditStub(),
    )
    observed_inputs: list[str] = []

    def _runner(task_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        observed_inputs.extend(task_context.task_inputs)
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
                can_run_many=True,
                input_items=lambda _run_data: ["198.51.100.10", "198.51.100.11"],
            )
        ],
        context=context,
        run_data=_run_data(),
        completed_task_instances={("run-nmap", _instance_key("run-nmap", "198.51.100.10"))},
    )

    assert observed_inputs == ["198.51.100.11"]
    assert len(states) == 1
    assert states[0].detail["task_inputs"] == ["198.51.100.11"]


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


def test_scheduler_marks_failed_tool_results_without_payload_as_failed(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-tool-failure-state")
    started_at = now_utc()
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-tool-failure-state"),
        audit=_AuditStub(),
    )

    def _runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(
            tool_executions=[
                ToolExecution(
                    execution_id="exec-nmap-timeout",
                    tool_name="nmap",
                    command="nmap 198.51.100.10",
                    started_at=started_at,
                    ended_at=started_at,
                    exit_code=None,
                    status="failed",
                    capability="network_port_scan",
                    termination_reason="timeout",
                    termination_detail="command exceeded timeout of 1s",
                    timed_out=True,
                )
            ]
        )

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
                retryable=False,
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert states[0].status == "failed"
    assert "command exceeded timeout" in str(states[0].error)


def test_scheduler_resource_pressure_cancels_one_running_task(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-resource-pressure")
    emitted: list[tuple[str, dict[str, object]]] = []
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {"task_start_delay_seconds": 0.0},
            "adaptive_execution": {
                "resource_limits": {
                    "grace_samples": 1,
                    "cooldown_seconds": 5,
                    "cpu_limit_percent": 50,
                    "memory_limit_percent": 100,
                }
            },
        },
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-resource-pressure"),
        audit=_AuditStub(),
        event_emitter=lambda event, payload: emitted.append((event, payload)),
    )

    def _runner(task_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        run_store.write_control(
            "resource_pressure",
            {
                "reason": "CPU 75.0% > 50%",
                "limits": {"grace_samples": 1, "cooldown_seconds": 5, "cpu_limit_percent": 50, "memory_limit_percent": 100},
                "sample": {"cpu_percent": 75.0, "memory_used_percent": 10.0},
                "throttle": {"cpu_cores": 1, "max_workers": 1, "max_tool_threads": 1, "max_heavy_processes": 1},
            },
        )
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            token = task_context.cancellation_token
            if token is not None and token.is_set():
                break
            time.sleep(0.01)
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert states[0].status == "cancelled"
    assert states[0].error == "cancelled_for_resource_limit"
    assert "worker.resource_pressure" in {event for event, _payload in emitted}


def test_scheduler_stop_control_cancels_running_task_token(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-stop-control")
    emitted: list[tuple[str, dict[str, object]]] = []
    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-stop-control"),
        audit=_AuditStub(),
        event_emitter=lambda event, payload: emitted.append((event, payload)),
    )
    token_was_set = {"value": False}

    def _runner(task_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        run_store.write_control("stop", {"reason": "operator_requested_stop"})
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            token = task_context.cancellation_token
            if token is not None and token.is_set():
                token_was_set["value"] = True
                break
            time.sleep(0.01)
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert token_was_set["value"] is True
    assert states[0].status == "cancelled"
    assert states[0].error == "orchestration_cancelled"
    assert "task.waiting" in {event for event, _payload in emitted}


def test_scheduler_deadline_budget_cancels_running_task_token(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-deadline-budget")
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {
                "task_start_delay_seconds": 0.0,
                "stage_time_budget_seconds": {"recon": 0.05},
            }
        },
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-deadline-budget"),
        audit=_AuditStub(),
    )
    token_was_set = {"value": False}

    def _runner(task_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            token = task_context.cancellation_token
            if token is not None and token.is_set():
                token_was_set["value"] = True
                break
            time.sleep(0.01)
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-nmap",
                label="Running Nmap",
                capability="network_port_scan",
                stage="recon",
                runner=_runner,
                should_run=lambda _run_data: (True, "always"),
                retryable=False,
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert token_was_set["value"] is True
    assert states[0].status == "failed"
    assert states[0].error == "task_time_budget_exceeded"


def test_scheduler_requeues_repeatable_task_when_new_frontier_appears(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-repeatable-frontier")
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {
                "task_start_delay_seconds": 0.0,
                "capability_budgets": {"scanner": {"max_runs": 1, "max_runtime_seconds": 600}},
            }
        },
        profile_config={"concurrency": 1},
        run_store=run_store,
        logger=logging.getLogger("scheduler-repeatable-frontier"),
        audit=_AuditStub(),
    )
    scan_runs: list[list[str]] = []

    def _seed_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(facts={"frontier.targets": ["alpha.example.com"]})

    def _scan_runner(_context: AdapterContext, run_data: RunData) -> AdapterResult:
        processed = set(run_data.facts.get("frontier.processed", []))
        pending = [
            item
            for item in run_data.facts.get("frontier.targets", [])
            if item not in processed
        ]
        scan_runs.append(list(pending))
        return AdapterResult(facts={"frontier.processed": pending})

    def _expand_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        return AdapterResult(facts={"frontier.targets": ["beta.example.com"]})

    def _pending_signature(run_data: RunData) -> str:
        processed = set(run_data.facts.get("frontier.processed", []))
        pending = sorted(
            item
            for item in run_data.facts.get("frontier.targets", [])
            if item not in processed
        )
        return "|".join(pending)

    tasks = [
        TaskDefinition(
            key="seed-targets",
            label="Seed targets",
            capability="seed",
            stage="recon",
            runner=_seed_runner,
            should_run=lambda _run_data: (True, "seed_initial_frontier"),
        ),
        TaskDefinition(
            key="scan-targets",
            label="Scan targets",
            capability="scanner",
            stage="enumeration",
            runner=_scan_runner,
            should_run=lambda run_data: (
                bool(_pending_signature(run_data)),
                "pending_frontier_available" if _pending_signature(run_data) else "no_pending_frontier",
            ),
            dependencies=["seed-targets"],
            repeatable_on_new_inputs=True,
            input_signature=_pending_signature,
        ),
        TaskDefinition(
            key="expand-targets",
            label="Expand targets",
            capability="expander",
            stage="enumeration",
            runner=_expand_runner,
            should_run=lambda run_data: (
                "beta.example.com" not in run_data.facts.get("frontier.targets", []),
                "discover_additional_targets",
            ),
            dependencies=["scan-targets"],
        ),
    ]

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=tasks,
        context=context,
        run_data=_run_data(),
    )

    scan_states = [state for state in states if state.key == "scan-targets"]

    assert scan_runs == [["alpha.example.com"], ["beta.example.com"]]
    assert len(scan_states) == 2
    assert [state.detail["iteration"] for state in scan_states] == [1, 2]


def test_scheduler_fans_out_can_run_many_task_instances(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-fanout")
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {
                "task_start_delay_seconds": 0.0,
                "capability_budgets": {"scanner": {"max_runs": 1, "max_runtime_seconds": 600}},
            }
        },
        profile_config={"concurrency": 4},
        run_store=run_store,
        logger=logging.getLogger("scheduler-fanout"),
        audit=_AuditStub(),
    )
    scanned_inputs: list[tuple[str, ...]] = []
    dependent_seen: list[int] = []

    def _scan_runner(scan_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        time.sleep(0.02)
        scanned_inputs.append(tuple(scan_context.task_inputs))
        return AdapterResult()

    def _dependent_runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        dependent_seen.append(len(scanned_inputs))
        return AdapterResult()

    tasks = [
        TaskDefinition(
            key="scan-targets",
            label="Scan targets",
            capability="scanner",
            stage="enumeration",
            runner=_scan_runner,
            should_run=lambda _run_data: (True, "pending_targets_available"),
            can_run_many=True,
            input_items=lambda _run_data: ["alpha.example.com", "beta.example.com", "gamma.example.com"],
        ),
        TaskDefinition(
            key="dependent-task",
            label="Dependent task",
            capability="analysis",
            stage="analysis",
            runner=_dependent_runner,
            should_run=lambda _run_data: (True, "scanner_complete"),
            dependencies=["scan-targets"],
        ),
    ]

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=tasks,
        context=context,
        run_data=_run_data(),
    )

    scan_states = [state for state in states if state.key == "scan-targets"]
    dependent_states = [state for state in states if state.key == "dependent-task"]

    assert len(scan_states) == 3
    assert all(state.status == "completed" for state in scan_states)
    assert sorted(scanned_inputs) == [
        ("alpha.example.com",),
        ("beta.example.com",),
        ("gamma.example.com",),
    ]
    assert dependent_seen == [3]
    assert dependent_states[0].status == "completed"


def test_scheduler_fanout_failure_does_not_block_sibling_instances(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="scheduler-fanout-isolation")
    context = AdapterContext(
        profile_name="standard",
        config={
            "orchestration": {
                "task_start_delay_seconds": 0.0,
                "circuit_breaker_failures": 1,
            }
        },
        profile_config={"concurrency": 2},
        run_store=run_store,
        logger=logging.getLogger("scheduler-fanout-isolation"),
        audit=_AuditStub(),
    )
    scanned_inputs: list[str] = []

    def _scan_runner(scan_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        target = scan_context.task_inputs[0]
        scanned_inputs.append(target)
        if target == "broken.example.com":
            return AdapterResult(errors=[f"subdomain enumeration failed for {target}"])
        return AdapterResult()

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=[
            TaskDefinition(
                key="run-subdomain-enum",
                label="Enumerating subdomains",
                capability="subdomain_enumeration",
                stage="recon",
                runner=_scan_runner,
                should_run=lambda _run_data: (True, "domain-like targets detected"),
                can_run_many=True,
                input_items=lambda _run_data: [
                    "alpha.example.com",
                    "broken.example.com",
                    "beta.example.com",
                    "gamma.example.com",
                    "delta.example.com",
                ],
                retryable=False,
            )
        ],
        context=context,
        run_data=_run_data(),
    )

    assert sorted(scanned_inputs) == [
        "alpha.example.com",
        "beta.example.com",
        "broken.example.com",
        "delta.example.com",
        "gamma.example.com",
    ]
    assert len(states) == 5
    assert len([state for state in states if state.status == "failed"]) == 1
    assert len([state for state in states if state.status == "completed"]) == 4
