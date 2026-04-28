from __future__ import annotations

import json
from typing import Any


class SchedulerControlHandler:
    """Normalizes operator control payloads read by the scheduler."""

    def signature(self, control_signal: dict[str, Any]) -> str:
        return json.dumps(control_signal, sort_keys=True, default=str)

    def action(self, control_signal: dict[str, Any]) -> str:
        return str(control_signal.get("action", "")).lower()

    def resource_limits(
        self,
        control_signal: dict[str, Any],
        *,
        current_grace_samples: int,
        current_cooldown_seconds: float,
    ) -> tuple[dict[str, object] | None, int, float]:
        limits_payload = control_signal.get("limits", {})
        if not isinstance(limits_payload, dict):
            return None, current_grace_samples, current_cooldown_seconds
        updated_limits = dict(limits_payload)
        grace_samples = max(1, int(updated_limits.get("grace_samples", current_grace_samples) or current_grace_samples))
        cooldown_seconds = max(
            5.0,
            float(updated_limits.get("cooldown_seconds", current_cooldown_seconds) or current_cooldown_seconds),
        )
        return updated_limits, grace_samples, cooldown_seconds
