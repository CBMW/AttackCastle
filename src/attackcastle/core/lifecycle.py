from __future__ import annotations

from attackcastle.core.enums import RunState
from attackcastle.core.models import RunData, iso, now_utc

STATE_ORDER = {
    RunState.CREATED: 0,
    RunState.PLANNED: 1,
    RunState.RUNNING: 2,
    RunState.PAUSED: 2,
    RunState.COMPLETED: 3,
    RunState.FAILED: 3,
    RunState.CANCELLED: 3,
}


def transition_run_state(run_data: RunData, new_state: RunState, reason: str) -> None:
    current = run_data.metadata.state
    if isinstance(current, str):
        current = RunState(current)
    if STATE_ORDER.get(new_state, 0) < STATE_ORDER.get(current, 0):
        return
    run_data.metadata.state = new_state
    run_data.state_history.append(
        {
            "from": current.value,
            "to": new_state.value,
            "reason": reason,
            "timestamp": iso(now_utc()),
        }
    )
