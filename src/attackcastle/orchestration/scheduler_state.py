from __future__ import annotations

from dataclasses import dataclass

from attackcastle.orchestration.task_graph import TaskDefinition


@dataclass
class ScheduledTask:
    definition: TaskDefinition
    attempt: int = 0
    input_signature: str = ""
    iteration: int = 1
    instance_key: str = ""
    task_inputs: tuple[str, ...] = ()


class SchedulerRunState:
    """Mutable task queues for one scheduler execution."""

    def __init__(
        self,
        completed_task_keys: set[str] | None = None,
        completed_task_instances: set[tuple[str, str]] | None = None,
    ) -> None:
        self.completed = set(completed_task_keys or set())
        self.completed_instances = set(completed_task_instances or set())
        self.pending: dict[str, ScheduledTask] = {}
        self.running = {}
        self.waiting_reason_by_task: dict[str, str] = {}
        self.last_input_signature_by_task: dict[str, str] = {}
        self.last_iteration_by_task: dict[str, int] = {}

    def has_active_instances(self, task_key: str) -> bool:
        if any(item.definition.key == task_key for item in self.pending.values()):
            return True
        return any(item.definition.key == task_key for item, *_rest in self.running.values())

    def mark_task_completed_if_idle(self, task_key: str) -> None:
        if not self.has_active_instances(task_key):
            self.completed.add(task_key)
