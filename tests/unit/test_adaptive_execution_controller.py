from __future__ import annotations

import logging
import time
from pathlib import Path

from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData, RunMetadata, now_utc
from attackcastle.orchestration.adaptive_execution import AdaptiveExecutionController, HostResources
from attackcastle.orchestration.scheduler import WorkflowScheduler
from attackcastle.orchestration.task_graph import TaskDefinition
from attackcastle.storage.run_store import RunStore


class _AuditStub:
    def write(self, _event_type: str, _payload: dict[str, object]) -> None:
        return


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="adaptive-controller-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_controller_startup_budget_respects_low_memory(monkeypatch) -> None:
    monkeypatch.setattr("attackcastle.orchestration.adaptive_execution.os.cpu_count", lambda: 8)
    monkeypatch.setattr(
        "attackcastle.orchestration.adaptive_execution._read_windows_memory",
        lambda: (None, None, "unavailable"),
    )
    monkeypatch.setattr(
        "attackcastle.orchestration.adaptive_execution._read_linux_meminfo",
        lambda: (8 * 1024**3, 768 * 1024**2, "procfs"),
    )

    controller = AdaptiveExecutionController(
        config={"enabled": True, "memory_per_worker_mb": 512, "startup_ramp_fraction": 0.5},
        profile_config={"concurrency": 8},
    )

    assert controller.hard_max_workers == 1
    assert controller.startup_budget == 1


def test_controller_scales_up_then_down_with_hysteresis(monkeypatch) -> None:
    controller = AdaptiveExecutionController(
        config={
            "enabled": True,
            "sample_interval_seconds": 0.0,
            "cooldown_seconds": 0.0,
            "healthy_samples_for_upgrade": 2,
            "startup_ramp_fraction": 0.5,
        },
        profile_config={"concurrency": 6},
    )
    stable_host = HostResources(
        cpu_count=8,
        cpu_cap=6,
        total_memory_bytes=8 * 1024**3,
        available_memory_bytes=6 * 1024**3,
        memory_source="test",
        load_ratio=0.2,
    )
    monkeypatch.setattr(controller, "_sample_host", lambda: stable_host)
    controller.hard_max_workers = 6
    controller.current_budget = 2
    controller.current_web_budget = 2

    start_budget = controller.dispatch_budget()
    controller.record_event(capability="web_probe", success=True, latency_ms=120.0)
    controller.refresh(pending_count=8, running_count=max(0, start_budget - 1))
    assert controller.dispatch_budget() == start_budget

    time.sleep(0.3)
    controller.record_event(capability="web_probe", success=True, latency_ms=110.0)
    controller.refresh(pending_count=8, running_count=max(0, start_budget - 1))
    assert controller.dispatch_budget() == start_budget + 1

    time.sleep(0.3)
    controller.record_event(capability="web_probe", success=False, latency_ms=4000.0, noisy=True, timeout=True)
    controller.refresh(pending_count=8, running_count=start_budget + 1)
    assert controller.dispatch_budget() <= start_budget
    assert "telemetry_pressure" in controller.snapshot()["downgrade_reasons"]


def test_scheduler_respects_adaptive_dispatch_budget(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="adaptive-scheduler")
    controller = AdaptiveExecutionController(
        config={"enabled": True, "sample_interval_seconds": 0.0, "cooldown_seconds": 999.0},
        profile_config={"concurrency": 4},
    )
    controller.current_budget = 1
    controller.current_web_budget = 1

    context = AdapterContext(
        profile_name="standard",
        config={"orchestration": {"task_start_delay_seconds": 0.0}},
        profile_config={"concurrency": 4},
        run_store=run_store,
        logger=logging.getLogger("adaptive-scheduler"),
        audit=_AuditStub(),
        execution_controller=controller,
    )
    running = 0
    observed_peak = 0

    def _runner(_context: AdapterContext, _run_data: RunData) -> AdapterResult:
        nonlocal running, observed_peak
        running += 1
        observed_peak = max(observed_peak, running)
        time.sleep(0.03)
        running -= 1
        return AdapterResult()

    tasks = [
        TaskDefinition(
            key=f"task-{index}",
            label=f"Task {index}",
            capability="web_probe",
            stage="enumeration",
            runner=_runner,
            should_run=lambda _run_data: (True, "always"),
        )
        for index in range(3)
    ]

    states = WorkflowScheduler(use_rich_progress=False, emit_plain_logs=False).execute(
        tasks=tasks,
        context=context,
        run_data=_run_data(),
    )

    assert all(state.status == "completed" for state in states)
    assert observed_peak == 1
