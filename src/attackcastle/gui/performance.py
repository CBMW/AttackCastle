from __future__ import annotations

import ctypes
import json
import math
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from attackcastle.orchestration.adaptive_execution import detect_host_resources

try:
    import psutil
except Exception:  # pragma: no cover - dependency is declared, fallback keeps old installs openable.
    psutil = None  # type: ignore[assignment]

SETTINGS_VERSION = 2


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
class ResourceLimitSettings:
    enabled: bool = True
    cpu_limit_percent: int = 100
    memory_limit_percent: int = 100
    sample_interval_seconds: int = 5
    grace_samples: int = 3
    cooldown_seconds: int = 60
    enforcement_mode: str = "graceful"
    throttle_min_request_delay_ms: int = 500
    throttle_tool_rate_ceiling: int = 250

    @classmethod
    def defaults(cls) -> "ResourceLimitSettings":
        return cls()

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "ResourceLimitSettings":
        defaults = cls.defaults()
        payload = payload or {}
        legacy_cpu = payload.get("cpu_alert_percent")
        legacy_memory = payload.get("memory_alert_percent")
        cpu_limit = payload.get("cpu_limit_percent", legacy_cpu if legacy_cpu is not None else defaults.cpu_limit_percent)
        memory_limit = payload.get(
            "memory_limit_percent",
            legacy_memory if legacy_memory is not None else defaults.memory_limit_percent,
        )
        mode = str(payload.get("enforcement_mode", defaults.enforcement_mode)).strip().lower()
        if mode not in {"graceful"}:
            mode = defaults.enforcement_mode
        return cls(
            enabled=_coerce_bool(payload.get("enabled"), defaults.enabled),
            cpu_limit_percent=_coerce_int(cpu_limit, defaults.cpu_limit_percent, 1, 100),
            memory_limit_percent=_coerce_int(memory_limit, defaults.memory_limit_percent, 1, 100),
            sample_interval_seconds=_coerce_int(
                payload.get("sample_interval_seconds"),
                defaults.sample_interval_seconds,
                1,
                60,
            ),
            grace_samples=_coerce_int(payload.get("grace_samples"), defaults.grace_samples, 1, 20),
            cooldown_seconds=_coerce_int(payload.get("cooldown_seconds"), defaults.cooldown_seconds, 5, 600),
            enforcement_mode=mode,
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

    def cpu_core_cap(self, cpu_count: int | None = None) -> int:
        detected_cpu_count = max(1, int(cpu_count or os.cpu_count() or 1))
        return max(1, min(detected_cpu_count, int(math.ceil(detected_cpu_count * (self.cpu_limit_percent / 100.0)))))

    def throttle_payload(self) -> dict[str, Any]:
        cpu_cores = self.cpu_core_cap()
        return {
            "cpu_cores": cpu_cores,
            "max_workers": cpu_cores,
            "max_tool_threads": cpu_cores,
            "max_heavy_processes": max(1, min(2, cpu_cores)),
            "memory_usage_limit_percent": self.memory_limit_percent,
            "rate_limit_mode": "careful",
            "min_request_delay_ms": self.throttle_min_request_delay_ms,
            "tool_rate_ceiling": self.throttle_tool_rate_ceiling,
            "cpu_limit_percent": self.cpu_limit_percent,
            "memory_limit_percent": self.memory_limit_percent,
            "grace_samples": self.grace_samples,
            "cooldown_seconds": self.cooldown_seconds,
            "enforcement_mode": self.enforcement_mode,
        }


PerformanceGuardSettings = ResourceLimitSettings


def load_performance_guard_settings(path: Path | None = None) -> ResourceLimitSettings:
    settings_path = path or default_performance_settings_path()
    if not settings_path.exists():
        return ResourceLimitSettings.defaults()
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ResourceLimitSettings.defaults()
    if not isinstance(payload, dict):
        return ResourceLimitSettings.defaults()
    guard = payload.get("performance_guard", payload)
    return ResourceLimitSettings.from_dict(guard if isinstance(guard, dict) else {})


def save_performance_guard_settings(
    settings: ResourceLimitSettings,
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


@dataclass(slots=True)
class ProcessTreeUsageSample:
    cpu_percent: float | None
    memory_used_percent: float | None
    memory_used_bytes: int
    total_memory_bytes: int | None
    process_count: int
    pids: list[int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_percent": self.cpu_percent,
            "memory_used_percent": self.memory_used_percent,
            "memory_used_bytes": self.memory_used_bytes,
            "total_memory_bytes": self.total_memory_bytes,
            "process_count": self.process_count,
            "pids": list(self.pids),
        }


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


class ProcessTreeUsageSampler:
    def __init__(self) -> None:
        self._previous_cpu_time: float | None = None
        self._previous_sample_time: float | None = None
        self._cpu_count = max(1, int(os.cpu_count() or 1))

    def _total_memory_bytes(self) -> int | None:
        if psutil is not None:
            try:
                return int(psutil.virtual_memory().total)
            except Exception:
                pass
        resources = detect_host_resources(hard_worker_ceiling=max(1, int(os.cpu_count() or 1)))
        return resources.total_memory_bytes

    def _collect_processes(self, root_pids: list[int]) -> list[Any]:
        if psutil is None:
            return []
        processes: list[Any] = []
        seen: set[int] = set()
        for raw_pid in root_pids:
            try:
                pid = int(raw_pid)
            except (TypeError, ValueError):
                continue
            if pid <= 0 or pid in seen:
                continue
            try:
                root = psutil.Process(pid)
            except Exception:
                continue
            stack = [root]
            try:
                stack.extend(root.children(recursive=True))
            except Exception:
                pass
            for process in stack:
                try:
                    process_pid = int(process.pid)
                except Exception:
                    continue
                if process_pid in seen:
                    continue
                seen.add(process_pid)
                processes.append(process)
        return processes

    def sample(self, root_pids: list[int]) -> ProcessTreeUsageSample:
        import time

        now = time.monotonic()
        processes = self._collect_processes(root_pids)
        total_process_cpu = 0.0
        total_rss = 0
        pids: list[int] = []
        for process in processes:
            try:
                with process.oneshot():
                    times = process.cpu_times()
                    memory = process.memory_info()
                    total_process_cpu += float(getattr(times, "user", 0.0)) + float(getattr(times, "system", 0.0))
                    total_rss += int(getattr(memory, "rss", 0) or 0)
                    pids.append(int(process.pid))
            except Exception:
                continue

        cpu_percent = None
        if self._previous_cpu_time is not None and self._previous_sample_time is not None:
            elapsed = max(now - self._previous_sample_time, 0.001)
            cpu_delta = max(total_process_cpu - self._previous_cpu_time, 0.0)
            cpu_percent = round(min(100.0, (cpu_delta / elapsed / float(self._cpu_count)) * 100.0), 1)
        self._previous_cpu_time = total_process_cpu
        self._previous_sample_time = now

        total_memory = self._total_memory_bytes()
        memory_percent = None
        if total_memory and total_memory > 0:
            memory_percent = round(min(100.0, (float(total_rss) / float(total_memory)) * 100.0), 1)
        return ProcessTreeUsageSample(
            cpu_percent=cpu_percent,
            memory_used_percent=memory_percent,
            memory_used_bytes=total_rss,
            total_memory_bytes=total_memory,
            process_count=len(pids),
            pids=sorted(pids),
        )
