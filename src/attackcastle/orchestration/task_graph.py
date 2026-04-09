from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData

ConditionResult = tuple[bool, str]


@dataclass
class TaskDefinition:
    key: str
    label: str
    capability: str
    runner: Callable[[AdapterContext, RunData], Any]
    should_run: Callable[[RunData], ConditionResult]
    input_entity_types: list[str] = field(default_factory=list)
    produced_entity_types: list[str] = field(default_factory=list)
    approval_class: str = "safe_auto"
    dependencies: list[str] = field(default_factory=list)
    can_run_many: bool = False
    profile_sensitivity: str = "balanced"
    network_intensity: str = "medium"
    noise_score: int = 1
    cost_score: int = 1
    retryable: bool = True
    max_retries: int = 1
    backoff_seconds: float = 0.5
    time_budget_seconds: int | None = None
    stage: str = "general"
    preview_commands: Callable[[AdapterContext, RunData], list[str]] | None = None


@dataclass
class TaskExecutionState:
    key: str
    label: str
    status: str
    started_at: datetime
    ended_at: datetime
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
