from __future__ import annotations

import ctypes
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from attackcastle.orchestration.adaptive_execution import detect_host_resources


SETTINGS_VERSION = 1


def _coerce_int(value: Any, default: int, minimum: int, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    return default


def default_performance_settings_path() -> Path:
    return Path.home() / ".attackcastle" / "gui_settings.json"


@dataclass(slots=True)
class PerformanceGuardSettings:
    enabled: bool = True
    cpu_alert_percent: int = 90
    memory_alert_percent: int = 90
    throttle_cpu_cores: int = 0
    throttle_min_request_delay_ms: int = 500
    throttle_tool_rate_ceiling: int = 250

    @classmethod
    def defaults(cls) -> "PerformanceGuardSettings":
        cpu_count = max(1, int(os.cpu_count() or 1))
        return cls(throttle_cpu_cores=max(1, min(cpu_count, max(1, cpu_count // 2))))

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "PerformanceGuardSettings":
        defaults = cls.defaults()
        payload = payload or {}
        cpu_count = max(1, int(os.cpu_count() or 1))
        return cls(
            enabled=_coerce_bool(payload.get("enabled"), defaults.enabled),
            cpu_alert_percent=_coerce_int(payload.get("cpu_alert_percent"), defaults.cpu_alert_percent, 50, 100),
            memory_alert_percent=_coerce_int(
                payload.get("memory_alert_percent"),
                defaults.memory_alert_percent,
                50,
                98,
            ),
            throttle_cpu_cores=_coerce_int(
                payload.get("throttle_cpu_cores"),
                defaults.throttle_cpu_cores,
                1,
                cpu_count,
            ),
            throttle_min_request_delay_ms=_coerce_int(
                payload.get("throttle_min_request_delay_ms"),
                defaults.throttle_min_request_delay_ms,
                0,
                10000,
            ),
            throttle_tool_rate_ceiling=_coerce_int(
                payload.get("throttle_tool_rate_ceiling"),
                defaults.throttle_tool_rate_ceiling,
                1,
                100000,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def throttle_payload(self) -> dict[str, Any]:
        return {
            "cpu_cores": self.throttle_cpu_cores,
            "max_workers": self.throttle_cpu_cores,
            "max_tool_threads": self.throttle_cpu_cores,
            "memory_usage_limit_percent": self.memory_alert_percent,
            "rate_limit_mode": "careful",
            "min_request_delay_ms": self.throttle_min_request_delay_ms,
            "tool_rate_ceiling": self.throttle_tool_rate_ceiling,
        }


def load_performance_guard_settings(path: Path | None = None) -> PerformanceGuardSettings:
    settings_path = path or default_performance_settings_path()
    if not settings_path.exists():
        return PerformanceGuardSettings.defaults()
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return PerformanceGuardSettings.defaults()
    if not isinstance(payload, dict):
        return PerformanceGuardSettings.defaults()
    guard = payload.get("performance_guard", payload)
    return PerformanceGuardSettings.from_dict(guard if isinstance(guard, dict) else {})


def save_performance_guard_settings(
    settings: PerformanceGuardSettings,
    path: Path | None = None,
) -> Path:
    settings_path = path or default_performance_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {"version": SETTINGS_VERSION, "performance_guard": settings.to_dict()}
    settings_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return settings_path


@dataclass(slots=True)
class SystemUsageSample:
    cpu_percent: float | None
    memory_used_percent: float | None
    memory_available_ratio: float | None
    total_memory_bytes: int | None
    available_memory_bytes: int | None
    memory_source: str


def _read_proc_cpu_times() -> tuple[int, int] | None:
    stat_path = Path("/proc/stat")
    if not stat_path.exists():
        return None
    try:
        first_line = stat_path.read_text(encoding="utf-8").splitlines()[0]
    except Exception:
        return None
    parts = first_line.split()
    if not parts or parts[0] != "cpu":
        return None
    values: list[int] = []
    for raw in parts[1:]:
        try:
            values.append(int(raw))
        except ValueError:
            values.append(0)
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return idle, total


def _read_windows_cpu_times() -> tuple[int, int] | None:
    if os.name != "nt":
        return None

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

    idle = FILETIME()
    kernel = FILETIME()
    user = FILETIME()
    try:
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
    except Exception:
        return None
    if not ok:
        return None

    def _to_int(filetime: FILETIME) -> int:
        return (int(filetime.dwHighDateTime) << 32) + int(filetime.dwLowDateTime)

    idle_time = _to_int(idle)
    total_time = _to_int(kernel) + _to_int(user)
    return idle_time, total_time


class SystemUsageSampler:
    def __init__(self) -> None:
        self._previous_cpu_times: tuple[int, int] | None = None

    def _cpu_percent(self) -> float | None:
        current = _read_proc_cpu_times() or _read_windows_cpu_times()
        if current is None:
            return None
        previous = self._previous_cpu_times
        self._previous_cpu_times = current
        if previous is None:
            return None
        previous_idle, previous_total = previous
        idle, total = current
        total_delta = total - previous_total
        idle_delta = idle - previous_idle
        if total_delta <= 0:
            return None
        busy_ratio = max(0.0, min(1.0, 1.0 - (float(idle_delta) / float(total_delta))))
        return round(busy_ratio * 100.0, 1)

    def sample(self) -> SystemUsageSample:
        resources = detect_host_resources(hard_worker_ceiling=max(1, int(os.cpu_count() or 1)))
        available_ratio = resources.available_memory_ratio
        memory_used_percent = None
        if available_ratio is not None:
            memory_used_percent = round((1.0 - available_ratio) * 100.0, 1)
        return SystemUsageSample(
            cpu_percent=self._cpu_percent(),
            memory_used_percent=memory_used_percent,
            memory_available_ratio=available_ratio,
            total_memory_bytes=resources.total_memory_bytes,
            available_memory_bytes=resources.available_memory_bytes,
            memory_source=resources.memory_source,
        )
