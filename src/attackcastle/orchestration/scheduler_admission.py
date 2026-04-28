from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from attackcastle.core.models import RunData
from attackcastle.orchestration.escalation import task_allowed_by_matrix
from attackcastle.orchestration.task_graph import TaskDefinition


@dataclass(frozen=True)
class AdmissionDecision:
    allow: bool
    reason: str


class TaskAdmissionController:
    """Evaluates whether a pending task can be dispatched now."""

    def dependencies_satisfied(self, task: TaskDefinition, completed: set[str]) -> AdmissionDecision:
        if all(dep in completed for dep in task.dependencies):
            return AdmissionDecision(True, "dependencies_satisfied")
        return AdmissionDecision(False, "waiting_for_dependencies")

    def matrix_allows(
        self,
        task: TaskDefinition,
        run_data: RunData,
        config: dict[str, Any],
    ) -> AdmissionDecision:
        allowed, reason = task_allowed_by_matrix(task.key, run_data, config)
        return AdmissionDecision(allowed, reason)

    def circuit_allows(self, task: TaskDefinition, circuit_failures: dict[str, int], max_failures: int) -> AdmissionDecision:
        if circuit_failures.get(task.capability, 0) >= max_failures:
            return AdmissionDecision(False, "circuit_breaker_open")
        return AdmissionDecision(True, "circuit_closed")
