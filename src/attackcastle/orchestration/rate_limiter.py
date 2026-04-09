from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Any


def _now() -> float:
    return time.monotonic()


@dataclass
class _AdaptiveState:
    failures: int = 0
    backoff_ms: float = 0.0
    last_wait_ms: float = 0.0
    mode: str = "aggressive"
    noisy_events: int = 0
    canary_failures: int = 0
    downgrade_count: int = 0
    clean_streak: int = 0
    request_count: int = 0
    generic_responses: int = 0
    last_status_code: int | None = None


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_mode(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    aliases = {
        "auto": "aggressive",
        "standard": "balanced",
        "safe-active": "balanced",
        "safe": "balanced",
        "cautious": "careful",
    }
    coerced = aliases.get(normalized, normalized)
    if coerced in {"aggressive", "balanced", "careful"}:
        return coerced
    return "aggressive"


class AdaptiveRateLimiter:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self.per_target_min_interval_ms = max(0.0, float(config.get("per_target_min_interval_ms", 0.0)))
        self.per_service_min_interval_ms = max(0.0, float(config.get("per_service_min_interval_ms", 0.0)))
        self.adaptive_enabled = bool(config.get("adaptive_backoff_enabled", True))
        self.adaptive_base_backoff_ms = max(0.0, float(config.get("adaptive_base_backoff_ms", 250.0)))
        self.adaptive_multiplier = max(1.0, float(config.get("adaptive_multiplier", 2.0)))
        self.adaptive_max_backoff_ms = max(
            self.adaptive_base_backoff_ms, float(config.get("adaptive_max_backoff_ms", 5000.0))
        )
        self.failure_threshold = max(1, int(config.get("failure_threshold", 1)))
        self.initial_mode = _coerce_mode(str(config.get("execution_mode", "auto")))
        self.jitter_ratio = max(0.0, _coerce_float(config.get("jitter_ratio", 0.08), 0.08))
        self.downgrade_after_noisy_events = max(1, int(config.get("downgrade_after_noisy_events", 2)))
        self.downgrade_after_canary_failures = max(1, int(config.get("downgrade_after_canary_failures", 1)))
        self.promote_after_clean_streak = max(1, int(config.get("promote_after_clean_streak", 4)))
        self.noisy_status_codes = {
            int(item)
            for item in config.get("noisy_status_codes", [403, 406, 429, 503])
            if str(item).isdigit()
        }
        self.mode_settings = self._build_mode_settings(config)

        self._next_target: dict[str, float] = {}
        self._next_service: dict[str, float] = {}
        self._adaptive_state: dict[str, _AdaptiveState] = {}
        self._lock = threading.Lock()

    def _build_mode_settings(self, config: dict[str, Any]) -> dict[str, dict[str, float]]:
        base_target = self.per_target_min_interval_ms
        base_service = self.per_service_min_interval_ms
        defaults: dict[str, dict[str, float]] = {
            "aggressive": {
                "target_interval_ms": base_target,
                "service_interval_ms": base_service,
                "jitter_ratio": self.jitter_ratio,
            },
            "balanced": {
                "target_interval_ms": max(base_target * 2.0, base_target + 75.0 if base_target else 120.0),
                "service_interval_ms": max(base_service * 2.0, base_service + 45.0 if base_service else 80.0),
                "jitter_ratio": max(self.jitter_ratio, 0.12),
            },
            "careful": {
                "target_interval_ms": max(base_target * 4.0, base_target + 350.0 if base_target else 400.0),
                "service_interval_ms": max(base_service * 4.0, base_service + 200.0 if base_service else 220.0),
                "jitter_ratio": max(self.jitter_ratio, 0.2),
            },
        }
        overrides = config.get("mode_settings", {})
        if not isinstance(overrides, dict):
            return defaults
        merged = defaults
        for mode_name, values in overrides.items():
            mode = _coerce_mode(str(mode_name))
            if not isinstance(values, dict):
                continue
            merged[mode] = {
                "target_interval_ms": max(
                    0.0,
                    _coerce_float(values.get("target_interval_ms"), merged[mode]["target_interval_ms"]),
                ),
                "service_interval_ms": max(
                    0.0,
                    _coerce_float(values.get("service_interval_ms"), merged[mode]["service_interval_ms"]),
                ),
                "jitter_ratio": max(
                    0.0,
                    _coerce_float(values.get("jitter_ratio"), merged[mode]["jitter_ratio"]),
                ),
            }
        return merged

    def _state(self, key: str) -> _AdaptiveState:
        state = self._adaptive_state.get(key)
        if state is None:
            state = _AdaptiveState(mode=self.initial_mode)
            self._adaptive_state[key] = state
        return state

    def _mode_index(self, mode: str) -> int:
        order = ["aggressive", "balanced", "careful"]
        try:
            return order.index(mode)
        except ValueError:
            return 0

    def _max_mode(self, *modes: str) -> str:
        selected = "aggressive"
        for mode in modes:
            if self._mode_index(mode) > self._mode_index(selected):
                selected = mode
        return selected

    def _downgrade(self, state: _AdaptiveState) -> None:
        if state.mode == "aggressive":
            state.mode = "balanced"
            state.downgrade_count += 1
            return
        if state.mode == "balanced":
            state.mode = "careful"
            state.downgrade_count += 1

    def _promote(self, state: _AdaptiveState) -> None:
        if state.mode == "careful":
            state.mode = "balanced"
            state.clean_streak = 0
            return
        if state.mode == "balanced":
            state.mode = "aggressive"
            state.clean_streak = 0

    def _effective_interval_ms(self, key_type: str, mode: str) -> float:
        settings = self.mode_settings.get(mode, self.mode_settings["aggressive"])
        interval_key = "service_interval_ms" if key_type == "service" else "target_interval_ms"
        base_value = float(settings.get(interval_key, 0.0))
        jitter_ratio = float(settings.get("jitter_ratio", 0.0))
        return max(0.0, base_value + (base_value * jitter_ratio * random.random()))

    def current_mode(self, target_key: str | None = None, service_key: str | None = None) -> str:
        with self._lock:
            modes = [self.initial_mode]
            for key in [item for item in (target_key, service_key) if item]:
                if key in self._adaptive_state:
                    modes.append(self._adaptive_state[str(key)].mode)
            return self._max_mode(*modes)

    def throttle(self, target_key: str | None = None, service_key: str | None = None) -> float:
        sleep_seconds = 0.0
        with self._lock:
            now = _now()
            deadlines: list[float] = []
            if target_key:
                deadlines.append(self._next_target.get(target_key, now))
            if service_key:
                deadlines.append(self._next_service.get(service_key, now))
            if deadlines:
                sleep_seconds = max(max(deadlines) - now, 0.0)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
        return sleep_seconds

    def record(
        self,
        target_key: str | None = None,
        service_key: str | None = None,
        success: bool = True,
        status_code: int | None = None,
        noisy_hint: bool = False,
        canary: bool = False,
        generic_response: bool = False,
    ) -> None:
        noisy = noisy_hint or (status_code in self.noisy_status_codes if status_code is not None else False)
        with self._lock:
            now = _now()
            keys = [
                ("target", str(target_key)) if target_key else None,
                ("service", str(service_key)) if service_key else None,
            ]
            for item in [entry for entry in keys if entry]:
                key_type, key = item
                state = self._state(str(key))
                state.request_count += 1
                state.last_status_code = status_code
                if generic_response:
                    state.generic_responses += 1
                if success and not noisy and not generic_response:
                    state.clean_streak += 1
                    state.failures = max(0, state.failures - 1)
                    state.backoff_ms = max(0.0, state.backoff_ms / self.adaptive_multiplier)
                    if state.clean_streak >= self.promote_after_clean_streak:
                        self._promote(state)
                else:
                    state.clean_streak = 0
                    if noisy:
                        state.noisy_events += 1
                    if canary and (noisy or generic_response or not success):
                        state.canary_failures += 1
                    if self.adaptive_enabled:
                        state.failures += 1
                        if state.failures >= self.failure_threshold:
                            if state.backoff_ms <= 0:
                                state.backoff_ms = self.adaptive_base_backoff_ms
                            else:
                                state.backoff_ms = min(
                                    self.adaptive_max_backoff_ms,
                                    state.backoff_ms * self.adaptive_multiplier,
                                )
                    if (
                        state.noisy_events >= self.downgrade_after_noisy_events
                        or state.canary_failures >= self.downgrade_after_canary_failures
                        or generic_response
                    ):
                        self._downgrade(state)

                wait_ms = self._effective_interval_ms(key_type, state.mode)
                if self.adaptive_enabled:
                    wait_ms += state.backoff_ms
                state.last_wait_ms = wait_ms
                wait_seconds = wait_ms / 1000.0
                if key_type == "target":
                    self._next_target[key] = max(self._next_target.get(key, now), now + wait_seconds)
                else:
                    self._next_service[key] = max(self._next_service.get(key, now), now + wait_seconds)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            adaptive = {
                key: {
                    "failures": state.failures,
                    "backoff_ms": round(state.backoff_ms, 2),
                    "last_wait_ms": round(state.last_wait_ms, 2),
                    "mode": state.mode,
                    "noisy_events": state.noisy_events,
                    "canary_failures": state.canary_failures,
                    "downgrade_count": state.downgrade_count,
                    "clean_streak": state.clean_streak,
                    "request_count": state.request_count,
                    "generic_responses": state.generic_responses,
                    "last_status_code": state.last_status_code,
                }
                for key, state in self._adaptive_state.items()
            }
            current_mode = self.initial_mode
            if adaptive:
                current_mode = self._max_mode(
                    self.initial_mode,
                    *[state["mode"] for state in adaptive.values()],
                )
            return {
                "per_target_min_interval_ms": self.per_target_min_interval_ms,
                "per_service_min_interval_ms": self.per_service_min_interval_ms,
                "adaptive_backoff_enabled": self.adaptive_enabled,
                "current_mode": current_mode,
                "mode_settings": self.mode_settings,
                "adaptive_state": adaptive,
                "summary": {
                    "tracked_keys": len(adaptive),
                    "downgraded_keys": len([item for item in adaptive.values() if item["downgrade_count"] > 0]),
                    "noisy_events": sum(int(item["noisy_events"]) for item in adaptive.values()),
                    "canary_failures": sum(int(item["canary_failures"]) for item in adaptive.values()),
                    "generic_responses": sum(int(item["generic_responses"]) for item in adaptive.values()),
                },
            }
