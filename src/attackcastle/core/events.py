from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from attackcastle.core.models import now_utc


@dataclass
class TaskEvent:
    task_name: str
    status: str
    timestamp: datetime = field(default_factory=now_utc)
    detail: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

