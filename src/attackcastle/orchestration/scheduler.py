from __future__ import annotations

import json
import signal
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass, replace
from datetime import timedelta
from hashlib import sha1
from threading import Event

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from attackcastle.analysis import refresh_autonomy_state, register_approval_decision
from attackcastle.core.enums import RunState, TaskStatus
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.lifecycle import transition_run_state
from attackcastle.core.models import RunData, now_utc, to_serializable
from attackcastle.core.runtime_events import emit_runtime_event
from attackcastle.normalization.mapper import merge_adapter_result
from attackcastle.orchestration.escalation import task_allowed_by_matrix
from attackcastle.orchestration.task_graph import TaskDefinition, TaskExecutionState


@dataclass
class ScheduledTask:
    definition: TaskDefinition
    attempt: int = 0
    input_signature: str = ""
    iteration: int = 1
    instance_key: str = ""
    task_inputs: tuple[str, ...] = ()


def _emit_adapter_result_runtime_events(context: AdapterContext, result: AdapterResult) -> None:
    entity_groups = (
        ("asset", result.assets),
        ("service", result.services),
        ("web_app", result.web_apps),
        ("technology", result.technologies),
        ("endpoint", result.endpoints),
        ("parameter", result.parameters),
        ("form", result.forms),
        ("login_surface", result.login_surfaces),
        ("replay_request", result.replay_requests),
        ("surface_signal", result.surface_signals),
        ("investigation_step", result.investigation_steps),
        ("playbook_execution", result.playbook_executions),
        ("coverage_decision", result.coverage_decisions),
        ("validation_result", result.validation_results),
        ("hypothesis", result.hypotheses),
        ("validation_task", result.validation_tasks),
        ("coverage_gap", result.coverage_gaps),
        ("evidence", result.evidence),
    )
    for entity_type, rows in entity_groups:
        for row in rows:
            emit_runtime_event(
                context,
                "entity.upserted",
                {
                    "entity_type": entity_type,
                    "action": "upsert",
                    "source": getattr(row, "source_tool", None),
                    "entity": row,
                },
            )

    for artifact in result.evidence_artifacts:
        emit_runtime_event(
            context,
            "artifact.available",
            {
                "artifact_path": artifact.path,
                "kind": artifact.kind,
                "source_tool": artifact.source_tool,
                "caption": artifact.caption or "",
                "artifact_id": artifact.artifact_id,
                "source_task_id": artifact.source_task_id,
                "source_execution_id": artifact.source_execution_id,
            },
        )

    for task_result in result.task_results:
        emit_runtime_event(context, "task_result.recorded", {"result": task_result})

    for execution in result.tool_executions:
        emit_runtime_event(context, "tool_execution.recorded", {"execution": execution})


class WorkflowScheduler:
    def __init__(
        self,
        console: Console | None = None,
        use_rich_progress: bool = True,
        emit_plain_logs: bool = True,
    ) -> None:
        self.console = console or Console()
        self.use_rich_progress = use_rich_progress
        self.emit_plain_logs = emit_plain_logs
        self._cancel_event = Event()

    def _handle_signal(self, signum, frame) -> None:  # noqa: ANN001, ARG002
        self._cancel_event.set()

    def _register_signal_handlers(self) -> tuple[object, object]:
        previous_int = signal.signal(signal.SIGINT, self._handle_signal)
        previous_term = signal.signal(signal.SIGTERM, self._handle_signal)
        return previous_int, previous_term

    def _restore_signal_handlers(self, previous_int, previous_term) -> None:  # noqa: ANN001
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)

    def execute(
        self,
        tasks: list[TaskDefinition],
        context: AdapterContext,
        run_data: RunData,
        completed_task_keys: set[str] | None = None,
    ) -> list[TaskExecutionState]:
        states: list[TaskExecutionState] = []
        completed = set(completed_task_keys or set())
        terminal_status = {TaskStatus.COMPLETED.value, TaskStatus.SKIPPED.value}
        circuit_failures: dict[str, int] = {}
        max_failures = int(context.config.get("orchestration", {}).get("circuit_breaker_failures", 2))
        hard_concurrency = int(context.profile_config.get("concurrency", 2))
        start_delay = float(context.config.get("orchestration", {}).get("task_start_delay_seconds", 0.0))
        stage_budget = context.config.get("orchestration", {}).get("stage_time_budget_seconds", {})
        retry_ceiling_by_capability = context.config.get("orchestration", {}).get(
            "retry_ceiling_by_capability", {}
        )
        max_total_retries = int(context.config.get("orchestration", {}).get("max_total_retries", 5))
        capability_budgets = context.config.get("orchestration", {}).get("capability_budgets", {})
        stage_concurrency = context.config.get("orchestration", {}).get("stage_concurrency", {})
        capability_runs: dict[str, int] = {}
        capability_run_tokens: set[str] = set()
        capability_runtime: dict[str, float] = {}
        total_retries = 0
        waiting_reason_by_task: dict[str, str] = {}
        last_input_signature_by_task: dict[str, str] = {}
        last_iteration_by_task: dict[str, int] = {}
        paused = False
        pause_notice_emitted = False
        pause_event_emitted = False
        last_control_signature = ""
        execution_controller = getattr(context, "execution_controller", None)
        if execution_controller is not None and getattr(execution_controller, "is_enabled", lambda: False)():
            hard_concurrency = int(getattr(execution_controller, "hard_max_workers", hard_concurrency))

        def build_instance_key(task_key: str, iteration: int, task_inputs: tuple[str, ...]) -> str:
            if not task_inputs:
                return f"{task_key}::iter{iteration}"
            digest = sha1("|".join(task_inputs).encode("utf-8")).hexdigest()[:12]  # noqa: S324
            return f"{task_key}::iter{iteration}::{digest}"

        pending: dict[str, ScheduledTask] = {
            build_instance_key(task.key, 1, ()): ScheduledTask(
                definition=task,
                attempt=0,
                iteration=1,
                instance_key=build_instance_key(task.key, 1, ()),
            )
            for task in tasks
            if task.key not in completed
        }
        running: dict[Future, tuple[ScheduledTask, object, str]] = {}
        executor = ThreadPoolExecutor(max_workers=max(1, hard_concurrency))

        progress = (
            Progress(
                SpinnerColumn(style="accent"),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=32),
                TaskProgressColumn(),
                TextColumn("[muted]Assets[/muted] [accent]{task.fields[asset_count]}[/accent]"),
                TextColumn("[muted]Services[/muted] [accent]{task.fields[service_count]}[/accent]"),
                TextColumn("[muted]Findings[/muted] [accent]{task.fields[finding_count]}[/accent]"),
                TextColumn("[muted]Candidates[/muted] [accent]{task.fields[candidate_count]}[/accent]"),
                TextColumn("[muted]Errors[/muted] [err]{task.fields[error_count]}[/err]"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self.console,
                transient=False,
            )
            if self.use_rich_progress
            else None
        )

        previous_int, previous_term = self._register_signal_handlers()
        try:
            with progress if progress is not None else nullcontext():
                progress_total = max(1, len(tasks))
                progress_id = (
                    progress.add_task(
                        "Running adaptive scan",
                        total=progress_total,
                        asset_count=0,
                        service_count=0,
                        finding_count=0,
                        candidate_count=0,
                        error_count=0,
                    )
                    if progress is not None
                    else None
                )
                if progress is None:
                    if self.emit_plain_logs:
                        self.console.print(f"Planning workflow ({len(tasks)} task(s))")

                def update_live_metrics() -> None:
                    if progress is None or progress_id is None:
                        return
                    findings = getattr(run_data, "findings", []) or []
                    confirmed_count = len(
                        [
                            item
                            for item in findings
                            if getattr(item, "status", "") == "confirmed" and not getattr(item, "suppressed", False)
                        ]
                    )
                    candidate_count = len(
                        [
                            item
                            for item in findings
                            if getattr(item, "status", "") == "candidate" and not getattr(item, "suppressed", False)
                        ]
                    )
                    progress.update(
                        progress_id,
                        asset_count=len(getattr(run_data, "assets", []) or []),
                        service_count=len(getattr(run_data, "services", []) or []),
                        finding_count=confirmed_count,
                        candidate_count=candidate_count,
                        error_count=len(getattr(run_data, "errors", []) or []),
                    )

                update_live_metrics()

                def current_input_signature(task: TaskDefinition) -> str:
                    if task.input_signature is None:
                        return ""
                    try:
                        return str(task.input_signature(run_data) or "")
                    except Exception:
                        return ""

                def has_active_instances(task_key: str) -> bool:
                    if any(item.definition.key == task_key for item in pending.values()):
                        return True
                    return any(item.definition.key == task_key for item, *_rest in running.values())

                def mark_task_completed_if_idle(task_key: str) -> None:
                    if not has_active_instances(task_key):
                        completed.add(task_key)

                def upsert_task_state(state: TaskExecutionState) -> None:
                    state_instance_key = str(state.detail.get("instance_key") or "")
                    for index, existing in enumerate(states):
                        existing_instance_key = str(existing.detail.get("instance_key") or "")
                        if existing.key == state.key and existing_instance_key and existing_instance_key == state_instance_key:
                            states[index] = state
                            run_data.task_states = to_serializable(states)
                            return
                    states.append(state)
                    run_data.task_states = to_serializable(states)

                def record_running_state(item: ScheduledTask, started_at, reason: str) -> None:  # noqa: ANN001
                    task = item.definition
                    upsert_task_state(
                        TaskExecutionState(
                            key=task.key,
                            label=task.label,
                            status=TaskStatus.RUNNING.value,
                            started_at=started_at,
                            ended_at=started_at,
                            detail={
                                "attempt": item.attempt + 1,
                                "capability": task.capability,
                                "stage": task.stage,
                                "decision_reason": reason,
                                "last_input_signature": item.input_signature,
                                "iteration": item.iteration,
                                "instance_key": item.instance_key,
                                "task_inputs": list(item.task_inputs),
                            },
                        )
                    )

                def expand_fanout_instances(queue_key: str, item: ScheduledTask) -> bool:
                    task = item.definition
                    if not task.can_run_many or task.input_items is None or item.task_inputs:
                        return False
                    try:
                        raw_inputs = task.input_items(run_data) or []
                    except Exception:
                        raw_inputs = []
                    normalized_inputs: list[str] = []
                    seen_inputs: set[str] = set()
                    for raw_input in raw_inputs:
                        text = str(raw_input or "").strip()
                        if not text or text in seen_inputs:
                            continue
                        seen_inputs.add(text)
                        normalized_inputs.append(text)
                    if len(normalized_inputs) <= 1:
                        single_inputs = tuple(normalized_inputs)
                        instance_key = build_instance_key(task.key, item.iteration, single_inputs)
                        updated = ScheduledTask(
                            definition=task,
                            attempt=item.attempt,
                            input_signature=single_inputs[0] if single_inputs else item.input_signature,
                            iteration=item.iteration,
                            instance_key=instance_key,
                            task_inputs=single_inputs,
                        )
                        if instance_key != queue_key:
                            pending.pop(queue_key, None)
                            pending[instance_key] = updated
                            waiting_reason_by_task.pop(queue_key, None)
                        else:
                            pending[queue_key] = updated
                        return False

                    pending.pop(queue_key, None)
                    waiting_reason_by_task.pop(queue_key, None)
                    progress_delta = 0
                    for task_input in normalized_inputs:
                        task_inputs = (task_input,)
                        instance_key = build_instance_key(task.key, item.iteration, task_inputs)
                        if instance_key in pending or any(
                            running_item.instance_key == instance_key for running_item, *_rest in running.values()
                        ):
                            continue
                        pending[instance_key] = ScheduledTask(
                            definition=task,
                            attempt=item.attempt,
                            input_signature=task_input,
                            iteration=item.iteration,
                            instance_key=instance_key,
                            task_inputs=task_inputs,
                        )
                        progress_delta += 1
                    if progress_delta > 1:
                        for _ in range(progress_delta - 1):
                            extend_progress_total()
                    context.audit.write(
                        "task.fanned_out",
                        {
                            "task": task.key,
                            "iteration": item.iteration,
                            "count": progress_delta,
                        },
                    )
                    emit_runtime_event(
                        context,
                        "task.fanned_out",
                        {
                            "task": task.key,
                            "label": task.label,
                            "iteration": item.iteration,
                            "count": progress_delta,
                        },
                    )
                    return True

                def extend_progress_total() -> None:
                    nonlocal progress_total
                    progress_total += 1
                    if progress is not None and progress_id is not None:
                        progress.update(progress_id, total=progress_total)

                def enqueue_repeatable_frontiers() -> None:
                    running_keys = {running_item.definition.key for running_item, *_rest in running.values()}
                    for task in tasks:
                        if not task.repeatable_on_new_inputs:
                            continue
                        if has_active_instances(task.key) or task.key in running_keys:
                            continue
                        if not all(dep in completed for dep in task.dependencies):
                            continue
                        signature = current_input_signature(task)
                        if not signature or signature == last_input_signature_by_task.get(task.key, ""):
                            continue
                        next_iteration = last_iteration_by_task.get(task.key, 1) + 1
                        instance_key = build_instance_key(task.key, next_iteration, ())
                        pending[instance_key] = ScheduledTask(
                            definition=task,
                            attempt=0,
                            input_signature=signature,
                            iteration=next_iteration,
                            instance_key=instance_key,
                        )
                        if task.key in completed:
                            extend_progress_total()
                        context.audit.write(
                            "task.requeued",
                            {
                                "task": task.key,
                                "input_signature": signature,
                                "iteration": next_iteration,
                            },
                        )
                        emit_runtime_event(
                            context,
                            "task.requeued",
                            {
                                "task": task.key,
                                "label": task.label,
                                "input_signature": signature,
                                "iteration": next_iteration,
                            },
                        )

                def process_done_futures() -> None:
                    nonlocal total_retries
                    done_futures = [future for future in list(running.keys()) if future.done()]
                    for future in done_futures:
                        item, started_at, decision_reason = running.pop(future)
                        task = item.definition
                        attempt = item.attempt
                        input_signature = item.input_signature
                        iteration = item.iteration
                        ended_at = now_utc()
                        error_message = None
                        status = TaskStatus.COMPLETED.value
                        duration_seconds = max((ended_at - started_at).total_seconds(), 0.001)
                        try:
                            result = future.result()
                            if isinstance(result, AdapterResult):
                                merge_adapter_result(run_data, result)
                                _emit_adapter_result_runtime_events(context, result)
                                refresh_autonomy_state(run_data, context.config)
                                if result.errors:
                                    error_message = "; ".join(
                                        str(item).strip() for item in result.errors if str(item).strip()
                                    ) or "adapter reported one or more execution errors"
                                    status = TaskStatus.FAILED.value
                                    circuit_failures[task.capability] = circuit_failures.get(task.capability, 0) + 1
                        except Exception as exc:  # noqa: BLE001
                            context.logger.exception("Task failed: %s", task.key)
                            error_message = str(exc)
                            run_data.errors.append(f"{task.key}: {exc}")
                            status = TaskStatus.FAILED.value
                            circuit_failures[task.capability] = circuit_failures.get(task.capability, 0) + 1

                        # Optional stage time budgets.
                        stage_budget_limit = stage_budget.get(task.stage)
                        if isinstance(stage_budget_limit, (int, float)) and duration_seconds > float(
                            stage_budget_limit
                        ):
                            run_data.warnings.append(
                                f"Task {task.key} exceeded stage budget ({duration_seconds:.2f}s > {stage_budget_limit}s)"
                            )

                        if status == TaskStatus.FAILED.value and task.retryable and attempt < task.max_retries:
                            capability_retry_ceiling = int(
                                retry_ceiling_by_capability.get(task.capability, task.max_retries)
                            )
                            effective_retry_limit = min(task.max_retries, capability_retry_ceiling)
                            if total_retries >= max_total_retries:
                                effective_retry_limit = 0
                            capability_runtime[task.capability] = (
                                capability_runtime.get(task.capability, 0.0) + duration_seconds
                            )
                            retry_attempt = attempt + 1
                            if retry_attempt <= effective_retry_limit:
                                pending[item.instance_key] = ScheduledTask(
                                    definition=task,
                                    attempt=retry_attempt,
                                    input_signature=input_signature,
                                    iteration=iteration,
                                    instance_key=item.instance_key,
                                    task_inputs=item.task_inputs,
                                )
                                total_retries += 1
                                status = TaskStatus.PENDING.value
                                context.audit.write(
                                    "task.retry",
                                    {
                                        "task": task.key,
                                        "instance_key": item.instance_key,
                                        "attempt": retry_attempt + 1,
                                        "backoff_seconds": task.backoff_seconds,
                                    },
                                )
                                if task.backoff_seconds > 0:
                                    time.sleep(task.backoff_seconds)
                            else:
                                context.audit.write(
                                    "task.retry.skipped",
                                    {
                                        "task": task.key,
                                        "attempt": retry_attempt + 1,
                                        "reason": "retry_ceiling_reached",
                                    },
                                )

                        if status in terminal_status | {TaskStatus.FAILED.value, TaskStatus.BLOCKED.value}:
                            capability_runtime[task.capability] = (
                                capability_runtime.get(task.capability, 0.0) + duration_seconds
                            )
                            last_input_signature_by_task[task.key] = input_signature
                            last_iteration_by_task[task.key] = iteration
                            if execution_controller is not None and getattr(
                                execution_controller,
                                "is_enabled",
                                lambda: False,
                            )():
                                execution_controller.record_task_result(
                                    capability=task.capability,
                                    stage=task.stage,
                                    duration_seconds=duration_seconds,
                                    success=status == TaskStatus.COMPLETED.value,
                                    timed_out=bool(error_message and "timeout" in error_message.lower()),
                                )
                            mark_task_completed_if_idle(task.key)
                            state = TaskExecutionState(
                                key=task.key,
                                label=task.label,
                                status=status,
                                started_at=started_at,
                                ended_at=ended_at,
                                error=error_message,
                                detail={
                                    "attempt": attempt + 1,
                                    "duration": str(timedelta(seconds=duration_seconds)),
                                    "capability": task.capability,
                                    "stage": task.stage,
                                    "decision_reason": decision_reason,
                                    "last_input_signature": input_signature,
                                    "iteration": iteration,
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                },
                            )
                            upsert_task_state(state)
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                if self.emit_plain_logs:
                                    self.console.print(
                                        f"{task.label}: {status} (attempt={attempt + 1})"
                                    )
                            context.audit.write(
                                "task.completed",
                                {
                                    "task": task.key,
                                    "status": status,
                                    "error": error_message,
                                    "attempt": attempt + 1,
                                    "iteration": iteration,
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                    "run_id": run_data.metadata.run_id,
                                },
                            )
                            emit_runtime_event(
                                context,
                                "task.completed",
                                {
                                    "task": task.key,
                                    "label": task.label,
                                    "status": status,
                                    "attempt": attempt + 1,
                                    "error": error_message,
                                    "iteration": iteration,
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                },
                            )
                            context.run_store.save_checkpoint(task.key, status, run_data)
                    update_live_metrics()

                def mark_terminal(
                    task: TaskDefinition,
                    status: str,
                    reason: str,
                    *,
                    queue_key: str | None = None,
                    input_signature: str = "",
                    iteration: int = 1,
                    task_inputs: tuple[str, ...] = (),
                ) -> None:
                    timestamp = now_utc()
                    last_input_signature_by_task[task.key] = input_signature
                    last_iteration_by_task[task.key] = iteration
                    states.append(
                        TaskExecutionState(
                            key=task.key,
                            label=task.label,
                            status=status,
                            started_at=timestamp,
                            ended_at=timestamp,
                            detail={
                                "reason": reason,
                                "capability": task.capability,
                                "last_input_signature": input_signature,
                                "iteration": iteration,
                                "instance_key": queue_key or build_instance_key(task.key, iteration, task_inputs),
                                "task_inputs": list(task_inputs),
                            },
                        )
                    )
                    if queue_key is not None:
                        pending.pop(queue_key, None)
                        waiting_reason_by_task.pop(queue_key, None)
                    mark_task_completed_if_idle(task.key)
                    if progress is not None and progress_id is not None:
                        progress.advance(progress_id, 1)
                    else:
                        if self.emit_plain_logs:
                            self.console.print(f"{task.label}: {status} ({reason})")
                    context.audit.write(
                        "task.terminal",
                        {"task": task.key, "status": status, "reason": reason},
                    )
                    emit_runtime_event(
                        context,
                        "task.terminal",
                        {"task": task.key, "label": task.label, "status": status, "reason": reason},
                    )

                while pending or running:
                    if self._cancel_event.is_set():
                        context.audit.write("orchestration.cancelled", {"reason": "signal"})
                        break
                    if execution_controller is not None and getattr(
                        execution_controller,
                        "is_enabled",
                        lambda: False,
                    )():
                        execution_controller.refresh(pending_count=len(pending), running_count=len(running))

                    control_signal = context.run_store.read_control()
                    if isinstance(control_signal, dict):
                        signature = json.dumps(control_signal, sort_keys=True, default=str)
                        action = str(control_signal.get("action", "")).lower()
                        if signature != last_control_signature:
                            if action in {"pause", "hold"}:
                                paused = True
                                pause_notice_emitted = False
                                pause_event_emitted = False
                                context.audit.write(
                                    "orchestration.control",
                                    {"action": "pause", "payload": control_signal},
                                )
                            elif action in {"resume", "continue"}:
                                paused = False
                                pause_notice_emitted = False
                                if (
                                    hasattr(run_data.metadata.state, "value")
                                    and run_data.metadata.state.value == RunState.PAUSED.value
                                ) or str(run_data.metadata.state) == RunState.PAUSED.value:
                                    transition_run_state(run_data, RunState.RUNNING, "operator_resume")
                                    context.run_store.save_checkpoint("_runtime_state", "running", run_data)
                                    emit_runtime_event(
                                        context,
                                        "worker.resumed",
                                        {"state": RunState.RUNNING.value},
                                    )
                                pause_event_emitted = False
                                context.audit.write(
                                    "orchestration.control",
                                    {"action": "resume", "payload": control_signal},
                                )
                                context.run_store.clear_control()
                            elif action in {"stop", "cancel"}:
                                paused = False
                                pause_notice_emitted = False
                                pause_event_emitted = False
                                self._cancel_event.set()
                                context.audit.write(
                                    "orchestration.control",
                                    {"action": "stop", "payload": control_signal},
                                )
                                context.run_store.clear_control()
                            elif action == "approval_decision":
                                approval_status = str(control_signal.get("status", "approved")).lower()
                                approval_class = str(control_signal.get("approval_class", "safe_auto"))
                                task_key = str(control_signal.get("task_key", "") or "") or None
                                validation_task_id = str(control_signal.get("validation_task_id", "") or "") or None
                                hypothesis_id = str(control_signal.get("hypothesis_id", "") or "") or None
                                reason = str(control_signal.get("reason", "") or "")
                                register_approval_decision(
                                    run_data,
                                    approval_class=approval_class,
                                    status=approval_status,
                                    reason=reason,
                                    task_key=task_key,
                                    hypothesis_id=hypothesis_id,
                                    validation_task_id=validation_task_id,
                                    decided_by=str(control_signal.get("decided_by", "operator")),
                                )
                                refresh_autonomy_state(run_data, context.config)
                                paused = False
                                pause_notice_emitted = False
                                pause_event_emitted = False
                                context.audit.write(
                                    "orchestration.approval_decision",
                                    {"payload": control_signal},
                                )
                                context.run_store.clear_control()
                            elif action == "skip_task":
                                requested_key = str(control_signal.get("task_key", "")).strip()
                                if requested_key and requested_key in pending:
                                    mark_terminal(
                                        pending[requested_key].definition,
                                        TaskStatus.SKIPPED.value,
                                        "operator_requested_skip",
                                    )
                                context.audit.write(
                                    "orchestration.control",
                                    {"action": "skip_task", "payload": control_signal},
                                )
                                context.run_store.clear_control()
                            last_control_signature = signature

                    process_done_futures()
                    enqueue_repeatable_frontiers()

                    if paused and not running:
                        if not pause_event_emitted:
                            transition_run_state(run_data, RunState.PAUSED, "operator_pause")
                            context.run_store.save_checkpoint("_runtime_state", "paused", run_data)
                            emit_runtime_event(
                                context,
                                "worker.paused",
                                {"state": RunState.PAUSED.value},
                            )
                            pause_event_emitted = True
                        if self.emit_plain_logs and not pause_notice_emitted:
                            self.console.print("Workflow paused by operator control signal")
                            pause_notice_emitted = True
                        time.sleep(0.2)
                        continue

                    # Schedule ready tasks up to worker limit.
                    scheduled_any = False
                    dispatch_limit = max(1, hard_concurrency)
                    if execution_controller is not None and getattr(
                        execution_controller,
                        "is_enabled",
                        lambda: False,
                    )():
                        dispatch_limit = int(execution_controller.dispatch_budget())
                    for key in list(pending.keys()):
                        if len(running) >= dispatch_limit:
                            break
                        item = pending[key]
                        task = item.definition
                        if not all(dep in completed for dep in task.dependencies):
                            previous_reason = waiting_reason_by_task.get(key)
                            if previous_reason != "waiting_for_dependencies":
                                waiting_reason_by_task[key] = "waiting_for_dependencies"
                                context.audit.write(
                                    "task.waiting",
                                    {
                                        "task": task.key,
                                        "instance_key": item.instance_key,
                                        "reason": "waiting_for_dependencies",
                                        "dependencies": task.dependencies,
                                    },
                                )
                                emit_runtime_event(
                                    context,
                                    "task.waiting",
                                    {
                                        "task": task.key,
                                        "label": task.label,
                                        "reason": "waiting_for_dependencies",
                                    },
                                )
                            continue

                        if circuit_failures.get(task.capability, 0) >= max_failures:
                            timestamp = now_utc()
                            states.append(
                                TaskExecutionState(
                                    key=task.key,
                                    label=task.label,
                                    status=TaskStatus.BLOCKED.value,
                                    started_at=timestamp,
                                    ended_at=timestamp,
                                    detail={
                                        "reason": "circuit_breaker_open",
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                            )
                            context.audit.write(
                                "task.blocked",
                                {
                                    "task": task.key,
                                    "capability": task.capability,
                                    "reason": "circuit_breaker_open",
                                    "instance_key": item.instance_key,
                                },
                            )
                            pending.pop(key, None)
                            waiting_reason_by_task.pop(key, None)
                            mark_task_completed_if_idle(task.key)
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                if self.emit_plain_logs:
                                    self.console.print(f"{task.label}: blocked (circuit breaker)")
                            continue

                        capability_budget = capability_budgets.get(task.capability, {})
                        max_runs = capability_budget.get("max_runs")
                        max_runtime_seconds = capability_budget.get("max_runtime_seconds")
                        capability_run_token = (
                            f"{task.capability}:{task.key}:{item.iteration}"
                            if task.can_run_many and task.input_items is not None
                            else item.instance_key
                        )
                        if (
                            max_runs is not None
                            and capability_run_token not in capability_run_tokens
                            and capability_runs.get(task.capability, 0) >= int(max_runs)
                        ):
                            timestamp = now_utc()
                            states.append(
                                TaskExecutionState(
                                    key=task.key,
                                    label=task.label,
                                    status=TaskStatus.BLOCKED.value,
                                    started_at=timestamp,
                                    ended_at=timestamp,
                                    detail={
                                        "reason": "capability_run_budget_exceeded",
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                            )
                            pending.pop(key, None)
                            waiting_reason_by_task.pop(key, None)
                            mark_task_completed_if_idle(task.key)
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                if self.emit_plain_logs:
                                    self.console.print(f"{task.label}: blocked (run budget)")
                            context.audit.write(
                                "task.blocked",
                                {
                                    "task": task.key,
                                    "reason": "capability_run_budget_exceeded",
                                    "instance_key": item.instance_key,
                                },
                            )
                            continue
                        if (
                            max_runtime_seconds is not None
                            and capability_runtime.get(task.capability, 0.0) >= float(max_runtime_seconds)
                        ):
                            timestamp = now_utc()
                            states.append(
                                TaskExecutionState(
                                    key=task.key,
                                    label=task.label,
                                    status=TaskStatus.BLOCKED.value,
                                    started_at=timestamp,
                                    ended_at=timestamp,
                                    detail={
                                        "reason": "capability_runtime_budget_exceeded",
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                            )
                            pending.pop(key, None)
                            waiting_reason_by_task.pop(key, None)
                            mark_task_completed_if_idle(task.key)
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                if self.emit_plain_logs:
                                    self.console.print(f"{task.label}: blocked (runtime budget)")
                            context.audit.write(
                                "task.blocked",
                                {
                                    "task": task.key,
                                    "reason": "capability_runtime_budget_exceeded",
                                    "instance_key": item.instance_key,
                                },
                            )
                            continue

                        policy_engine = getattr(context, "policy_engine", None)
                        if policy_engine is not None:
                            decision = policy_engine.evaluate_task(task, run_data)
                            if not decision.allow:
                                if decision.action == "pause":
                                    paused = True
                                    pause_notice_emitted = False
                                    wait_reason = f"policy_pause:{decision.reason}"
                                    previous_reason = waiting_reason_by_task.get(key)
                                    if previous_reason != wait_reason:
                                        waiting_reason_by_task[key] = wait_reason
                                        context.audit.write(
                                            "task.waiting",
                                            {
                                                "task": task.key,
                                                "instance_key": item.instance_key,
                                                "reason": wait_reason,
                                                "rule_id": decision.rule_id,
                                            },
                                        )
                                        emit_runtime_event(
                                            context,
                                            "task.waiting",
                                            {
                                                "task": task.key,
                                                "label": task.label,
                                                "reason": wait_reason,
                                            },
                                        )
                                    continue
                                mark_terminal(
                                    task,
                                    TaskStatus.BLOCKED.value,
                                    f"policy_denied:{decision.reason}",
                                    queue_key=key,
                                    input_signature=item.input_signature,
                                    iteration=item.iteration,
                                    task_inputs=item.task_inputs,
                                )
                                continue

                        matrix_allowed, matrix_reason = task_allowed_by_matrix(
                            task.key,
                            run_data,
                            context.config,
                        )
                        if not matrix_allowed:
                            previous_reason = waiting_reason_by_task.get(key)
                            if previous_reason != matrix_reason:
                                waiting_reason_by_task[key] = matrix_reason
                                context.audit.write(
                                    "task.waiting",
                                    {
                                        "task": task.key,
                                        "reason": matrix_reason,
                                        "instance_key": item.instance_key,
                                    },
                                )
                                emit_runtime_event(
                                    context,
                                    "task.waiting",
                                    {"task": task.key, "label": task.label, "reason": matrix_reason},
                                )
                            continue

                        frontier_signature = item.input_signature
                        if task.repeatable_on_new_inputs:
                            frontier_signature = current_input_signature(task)
                            if not frontier_signature:
                                previous_reason = waiting_reason_by_task.get(key)
                                wait_reason = "no_pending_inputs"
                                if previous_reason != wait_reason:
                                    waiting_reason_by_task[key] = wait_reason
                                    context.audit.write(
                                        "task.waiting",
                                        {
                                            "task": task.key,
                                            "reason": wait_reason,
                                            "instance_key": item.instance_key,
                                        },
                                    )
                                    emit_runtime_event(
                                        context,
                                        "task.waiting",
                                        {"task": task.key, "label": task.label, "reason": wait_reason},
                                    )
                                continue
                            item.input_signature = frontier_signature

                        if expand_fanout_instances(key, item):
                            scheduled_any = True
                            break

                        should_run, reason = task.should_run(run_data)
                        if not should_run:
                            # Keep pending until nothing else can change run facts.
                            previous_reason = waiting_reason_by_task.get(key)
                            if previous_reason != reason:
                                waiting_reason_by_task[key] = reason
                                context.audit.write(
                                    "task.waiting",
                                    {
                                        "task": task.key,
                                        "reason": reason,
                                        "instance_key": item.instance_key,
                                    },
                                )
                                emit_runtime_event(
                                    context,
                                    "task.waiting",
                                    {"task": task.key, "label": task.label, "reason": reason},
                                )
                            continue

                        if start_delay > 0:
                            time.sleep(start_delay)

                        stage_limit = stage_concurrency.get(task.stage)
                        adaptive_stage_limit = None
                        if execution_controller is not None and getattr(
                            execution_controller,
                            "is_enabled",
                            lambda: False,
                        )():
                            adaptive_stage_limit = int(execution_controller.stage_budget(task.stage, task.capability))
                        if isinstance(stage_limit, int) and stage_limit > 0 and adaptive_stage_limit is not None:
                            stage_limit = min(stage_limit, adaptive_stage_limit)
                        elif adaptive_stage_limit is not None:
                            stage_limit = adaptive_stage_limit
                        if isinstance(stage_limit, int) and stage_limit > 0:
                            current_stage_running = sum(
                                1
                                for running_item, *_rest in running.values()
                                if running_item.definition.stage == task.stage
                            )
                            if current_stage_running >= stage_limit:
                                previous_reason = waiting_reason_by_task.get(key)
                                wait_reason = f"stage_concurrency_limit:{task.stage}"
                                if previous_reason != wait_reason:
                                    waiting_reason_by_task[key] = wait_reason
                                    context.audit.write(
                                        "task.waiting",
                                        {
                                            "task": task.key,
                                            "reason": wait_reason,
                                            "instance_key": item.instance_key,
                                        },
                                    )
                                    emit_runtime_event(
                                        context,
                                        "task.waiting",
                                        {"task": task.key, "label": task.label, "reason": wait_reason},
                                    )
                                continue

                        if execution_controller is not None and getattr(
                            execution_controller,
                            "is_enabled",
                            lambda: False,
                        )() and execution_controller.is_heavy_capability(task.capability):
                            heavy_running = sum(
                                1
                                for running_item, *_rest in running.values()
                                if execution_controller.is_heavy_capability(running_item.definition.capability)
                            )
                            heavy_limit = int(execution_controller.heavy_process_limit())
                            if heavy_running >= heavy_limit:
                                previous_reason = waiting_reason_by_task.get(key)
                                wait_reason = "adaptive_heavy_process_limit"
                                if previous_reason != wait_reason:
                                    waiting_reason_by_task[key] = wait_reason
                                    context.audit.write(
                                        "task.waiting",
                                        {
                                            "task": task.key,
                                            "reason": wait_reason,
                                            "instance_key": item.instance_key,
                                        },
                                    )
                                    emit_runtime_event(
                                        context,
                                        "task.waiting",
                                        {"task": task.key, "label": task.label, "reason": wait_reason},
                                    )
                                continue

                        started_at = now_utc()
                        context.audit.write(
                            "task.started",
                            {
                                "task": task.key,
                                "instance_key": item.instance_key,
                                "label": task.label,
                                "attempt": item.attempt + 1,
                                "iteration": item.iteration,
                                "task_inputs": list(item.task_inputs),
                                "run_id": run_data.metadata.run_id,
                            },
                        )
                        emit_runtime_event(
                            context,
                            "task.started",
                            {
                                "task": task.key,
                                "instance_key": item.instance_key,
                                "label": task.label,
                                "attempt": item.attempt + 1,
                                "reason": reason,
                                "iteration": item.iteration,
                                "task_inputs": list(item.task_inputs),
                            },
                        )
                        record_running_state(item, started_at, reason)
                        context.run_store.save_checkpoint(task.key, "running", run_data)
                        if progress is not None and progress_id is not None:
                            progress.update(progress_id, description=f"[cyan]{task.label}")
                        else:
                            if self.emit_plain_logs:
                                target_suffix = f" target={item.task_inputs[0]}" if item.task_inputs else ""
                                self.console.print(
                                    f"Starting: {task.label} (attempt={item.attempt + 1}{target_suffix})"
                                )
                        task_context = replace(
                            context,
                            task_instance_key=item.instance_key,
                            task_inputs=list(item.task_inputs),
                        )
                        future = executor.submit(task.runner, task_context, run_data)
                        running[future] = (item, started_at, reason)
                        if capability_run_token not in capability_run_tokens:
                            capability_runs[task.capability] = capability_runs.get(task.capability, 0) + 1
                            capability_run_tokens.add(capability_run_token)
                        pending.pop(key, None)
                        waiting_reason_by_task.pop(key, None)
                        scheduled_any = True
                        pause_notice_emitted = False
                        context.audit.write(
                            "task.queued",
                            {
                                "task": task.key,
                                "instance_key": item.instance_key,
                                "reason": reason,
                                "attempt": item.attempt + 1,
                                "iteration": item.iteration,
                                "input_signature": frontier_signature,
                                "task_inputs": list(item.task_inputs),
                            },
                        )
                        emit_runtime_event(
                            context,
                            "task.queued",
                            {
                                "task": task.key,
                                "instance_key": item.instance_key,
                                "label": task.label,
                                "reason": reason,
                                "attempt": item.attempt + 1,
                                "iteration": item.iteration,
                                "task_inputs": list(item.task_inputs),
                            },
                        )
                        update_live_metrics()

                    if not scheduled_any and not running and pending:
                        enqueue_repeatable_frontiers()
                        # First pass: skip condition-blocked tasks with satisfied dependencies.
                        # This allows downstream tasks to proceed in the next scheduling cycle.
                        skipped_any = False
                        for key in list(pending.keys()):
                            item = pending[key]
                            task = item.definition
                            if not all(dep in completed for dep in task.dependencies):
                                continue
                            frontier_signature = item.input_signature
                            if task.repeatable_on_new_inputs:
                                frontier_signature = current_input_signature(task)
                                if not frontier_signature:
                                    continue
                                item.input_signature = frontier_signature
                            matrix_allowed, matrix_reason = task_allowed_by_matrix(
                                task.key,
                                run_data,
                                context.config,
                            )
                            if not matrix_allowed:
                                timestamp = now_utc()
                                states.append(
                                    TaskExecutionState(
                                        key=task.key,
                                        label=task.label,
                                        status=TaskStatus.SKIPPED.value,
                                        started_at=timestamp,
                                        ended_at=timestamp,
                                        detail={
                                            "reason": matrix_reason,
                                            "capability": task.capability,
                                            "last_input_signature": frontier_signature,
                                            "iteration": item.iteration,
                                            "instance_key": item.instance_key,
                                            "task_inputs": list(item.task_inputs),
                                        },
                                    )
                                )
                                last_input_signature_by_task[task.key] = frontier_signature
                                last_iteration_by_task[task.key] = item.iteration
                                pending.pop(key, None)
                                waiting_reason_by_task.pop(key, None)
                                mark_task_completed_if_idle(task.key)
                                skipped_any = True
                                if progress is not None and progress_id is not None:
                                    progress.advance(progress_id, 1)
                                else:
                                    if self.emit_plain_logs:
                                        self.console.print(f"{task.label}: skipped ({matrix_reason})")
                                context.audit.write(
                                    "task.skipped",
                                    {
                                        "task": task.key,
                                        "reason": matrix_reason,
                                        "iteration": item.iteration,
                                        "input_signature": frontier_signature,
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                                continue
                            should_run, reason = task.should_run(run_data)
                            if should_run:
                                continue
                            timestamp = now_utc()
                            states.append(
                                TaskExecutionState(
                                    key=task.key,
                                    label=task.label,
                                    status=TaskStatus.SKIPPED.value,
                                    started_at=timestamp,
                                    ended_at=timestamp,
                                    detail={
                                        "reason": reason,
                                        "capability": task.capability,
                                        "last_input_signature": frontier_signature,
                                        "iteration": item.iteration,
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                            )
                            last_input_signature_by_task[task.key] = frontier_signature
                            last_iteration_by_task[task.key] = item.iteration
                            pending.pop(key, None)
                            waiting_reason_by_task.pop(key, None)
                            mark_task_completed_if_idle(task.key)
                            skipped_any = True
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                if self.emit_plain_logs:
                                    self.console.print(f"{task.label}: skipped ({reason})")
                            context.audit.write(
                                "task.skipped",
                                {
                                    "task": task.key,
                                    "reason": reason,
                                    "iteration": item.iteration,
                                    "input_signature": frontier_signature,
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                },
                            )

                        if skipped_any:
                            continue

                        # Second pass: true dependency deadlock for whatever remains.
                        for key in list(pending.keys()):
                            item = pending[key]
                            task = item.definition
                            frontier_signature = item.input_signature
                            timestamp = now_utc()
                            skipped_reason = "dependency_deadlock"
                            states.append(
                                TaskExecutionState(
                                    key=task.key,
                                    label=task.label,
                                    status=TaskStatus.SKIPPED.value,
                                    started_at=timestamp,
                                    ended_at=timestamp,
                                    detail={
                                        "reason": skipped_reason,
                                        "capability": task.capability,
                                        "last_input_signature": frontier_signature,
                                        "iteration": item.iteration,
                                        "instance_key": item.instance_key,
                                        "task_inputs": list(item.task_inputs),
                                    },
                                )
                            )
                            last_input_signature_by_task[task.key] = frontier_signature
                            last_iteration_by_task[task.key] = item.iteration
                            pending.pop(key, None)
                            waiting_reason_by_task.pop(key, None)
                            mark_task_completed_if_idle(task.key)
                            if progress is not None and progress_id is not None:
                                progress.advance(progress_id, 1)
                            else:
                                    if self.emit_plain_logs:
                                        self.console.print(f"{task.label}: skipped ({skipped_reason})")
                            context.audit.write(
                                "task.skipped",
                                {
                                    "task": task.key,
                                    "reason": skipped_reason,
                                    "iteration": item.iteration,
                                    "input_signature": frontier_signature,
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                },
                            )

                    if running:
                        wait(running.keys(), timeout=0.1)
                        process_done_futures()
                        enqueue_repeatable_frontiers()

                if self._cancel_event.is_set():
                    timestamp = now_utc()
                    for key in list(pending.keys()):
                        item = pending.pop(key)
                        task = item.definition
                        states.append(
                            TaskExecutionState(
                                key=task.key,
                                label=task.label,
                                status=TaskStatus.CANCELLED.value,
                                started_at=timestamp,
                                ended_at=timestamp,
                                detail={
                                    "reason": "orchestration_cancelled",
                                    "instance_key": item.instance_key,
                                    "task_inputs": list(item.task_inputs),
                                },
                            )
                        )
                        waiting_reason_by_task.pop(key, None)
                        mark_task_completed_if_idle(task.key)
                    if progress is not None and progress_id is not None:
                        progress.update(progress_id, description="[red]Workflow cancelled")
                        update_live_metrics()
                    else:
                        if self.emit_plain_logs:
                            self.console.print("Workflow cancelled")
                else:
                    if progress is not None and progress_id is not None:
                        progress.update(progress_id, description="[green]Workflow complete")
                        update_live_metrics()
                    else:
                        if self.emit_plain_logs:
                            self.console.print("Workflow complete")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
            self._restore_signal_handlers(previous_int, previous_term)

        return states
