from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from attackcastle.analysis import approval_class_for_task
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import RunData
from attackcastle.orchestration.rules import CONDITION_MAP, INPUT_SIGNATURE_MAP
from attackcastle.orchestration.task_graph import TaskDefinition

TaskRunner = Callable[[AdapterContext, RunData], AdapterResult | None]


@dataclass
class PlanItem:
    key: str
    label: str
    capability: str
    approval_class: str
    selected: bool
    reason: str
    noise_score: int
    cost_score: int
    dependencies: list[str] = field(default_factory=list)
    preview_commands: list[str] = field(default_factory=list)


@dataclass
class PlanResult:
    tasks: list[TaskDefinition]
    items: list[PlanItem]
    conflicts: list[str]


def _load_rule_set() -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "rules" / "default_rules.yaml"
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {"tasks": []}


def _profile_noise_limit(profile_name: str, config: dict[str, Any]) -> int:
    profile_noise = config.get("profile", {}).get("max_noise_score")
    if isinstance(profile_noise, int):
        return profile_noise
    configured = config.get("policy", {}).get("max_noise_score")
    if isinstance(configured, int):
        return configured
    if profile_name == "cautious":
        return 4
    if profile_name == "standard":
        return 7
    return 10


def _build_task_definition(
    rule_task: dict[str, Any],
    runner: TaskRunner,
    condition_name: str,
    approval_class: str,
    preview_callable: Callable[[AdapterContext, RunData], list[str]] | None = None,
) -> TaskDefinition:
    condition = CONDITION_MAP.get(condition_name, CONDITION_MAP["always"])
    return TaskDefinition(
        key=rule_task["key"],
        label=rule_task["label"],
        capability=rule_task["capability"],
        approval_class=approval_class,
        runner=runner,
        should_run=condition,
        input_entity_types=[str(item) for item in rule_task.get("input_entity_types", [])],
        produced_entity_types=[str(item) for item in rule_task.get("produced_entity_types", [])],
        dependencies=list(rule_task.get("dependencies", [])),
        can_run_many=bool(rule_task.get("can_run_many", False)),
        profile_sensitivity=str(rule_task.get("profile_sensitivity", "balanced")),
        network_intensity=str(rule_task.get("network_intensity", "medium")),
        noise_score=int(rule_task.get("noise_score", 1)),
        cost_score=int(rule_task.get("cost_score", 1)),
        retryable=bool(rule_task.get("retryable", True)),
        max_retries=int(rule_task.get("max_retries", 1)),
        backoff_seconds=float(rule_task.get("backoff_seconds", 0.5)),
        stage=rule_task.get("stage", "general"),
        preview_commands=preview_callable,
        repeatable_on_new_inputs=bool(rule_task.get("repeatable_on_new_inputs", False)),
        input_signature=INPUT_SIGNATURE_MAP.get(str(rule_task["key"])),
    )


def build_task_plan(
    adapters: dict[str, object],
    findings_runner: TaskRunner,
    report_runner: TaskRunner,
    run_data: RunData,
    profile_name: str,
    config: dict[str, Any],
    preview_context: AdapterContext | None = None,
) -> PlanResult:
    rules = _load_rule_set()
    tasks: list[TaskDefinition] = []
    items: list[PlanItem] = []
    conflicts: list[str] = []
    max_noise = _profile_noise_limit(profile_name, config)
    risk_mode = str(config.get("scan", {}).get("risk_mode", "safe-active"))
    risk_controls = config.get("risk_mode_controls", {})
    if not isinstance(risk_controls, dict):
        risk_controls = {}
    blocked_capabilities = {
        str(item)
        for item in risk_controls.get("blocked_capabilities", [])
        if str(item).strip()
    }

    adapter_runners: dict[str, tuple[TaskRunner, Callable[[AdapterContext, RunData], list[str]] | None]] = {}
    for key, adapter in adapters.items():
        adapter_runners[key] = (
            lambda context, data, _adapter=adapter: _adapter.run(context, data),
            getattr(adapter, "preview_commands", None),
        )
    adapter_runners["findings"] = (findings_runner, None)
    adapter_runners["report"] = (report_runner, None)

    for rule_task in rules.get("tasks", []):
        adapter_key = rule_task.get("adapter_key")
        condition_name = rule_task.get("condition", "always")
        noise_score = int(rule_task.get("noise_score", 1))
        approval_class = str(
            rule_task.get("approval_class")
            or approval_class_for_task(rule_task.get("key"), rule_task.get("capability"), config)
        )
        blocked_by_policy = False
        if adapter_key not in adapter_runners:
            items.append(
                PlanItem(
                    key=rule_task["key"],
                    label=rule_task["label"],
                    capability=rule_task["capability"],
                    approval_class=approval_class,
                    selected=False,
                    reason=f"adapter '{adapter_key}' unavailable",
                    noise_score=noise_score,
                    cost_score=int(rule_task.get("cost_score", 1)),
                    dependencies=list(rule_task.get("dependencies", [])),
                )
            )
            continue

        runner, preview_callable = adapter_runners[adapter_key]
        condition = CONDITION_MAP.get(condition_name, CONDITION_MAP["always"])
        should_run, condition_reason = condition(run_data)
        if rule_task.get("capability") in blocked_capabilities:
            should_run = False
            blocked_by_policy = True
            condition_reason = f"blocked by risk mode '{risk_mode}'"
            conflicts.append(
                f"Task '{rule_task['key']}' blocked by risk mode '{risk_mode}' capability controls"
            )
        if noise_score > max_noise:
            should_run = False
            blocked_by_policy = True
            conflict = (
                f"Task '{rule_task['key']}' noise score {noise_score} exceeds profile limit {max_noise}"
            )
            conflicts.append(conflict)
            condition_reason = "blocked by profile noise policy"

        preview_commands: list[str] = []
        if preview_context and preview_callable:
            try:
                preview_commands = preview_callable(preview_context, run_data)
            except Exception:
                preview_commands = []

        items.append(
            PlanItem(
                key=rule_task["key"],
                label=rule_task["label"],
                capability=rule_task["capability"],
                approval_class=approval_class,
                selected=not blocked_by_policy,
                reason=(
                    condition_reason
                    if blocked_by_policy
                    else condition_reason
                    if should_run
                    else f"deferred: {condition_reason}"
                ),
                noise_score=noise_score,
                cost_score=int(rule_task.get("cost_score", 1)),
                dependencies=list(rule_task.get("dependencies", [])),
                preview_commands=preview_commands,
            )
        )
        if blocked_by_policy:
            continue
        tasks.append(
            _build_task_definition(
                rule_task=rule_task,
                runner=runner,
                condition_name=condition_name,
                approval_class=approval_class,
                preview_callable=preview_callable,
            )
        )

    selected_keys = {task.key for task in tasks}
    for task in tasks:
        task.dependencies = [dependency for dependency in task.dependencies if dependency in selected_keys]

    return PlanResult(tasks=tasks, items=items, conflicts=conflicts)
