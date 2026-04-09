from __future__ import annotations

import ctypes
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class HostResources:
    cpu_count: int
    cpu_cap: int
    total_memory_bytes: int | None = None
    available_memory_bytes: int | None = None
    memory_source: str = "unknown"
    load_ratio: float | None = None

    @property
    def available_memory_ratio(self) -> float | None:
        if not self.total_memory_bytes or self.available_memory_bytes is None:
            return None
        if self.total_memory_bytes <= 0:
            return None
        ratio = float(self.available_memory_bytes) / float(self.total_memory_bytes)
        return max(0.0, min(1.0, ratio))

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_count": self.cpu_count,
            "cpu_cap": self.cpu_cap,
            "total_memory_bytes": self.total_memory_bytes,
            "available_memory_bytes": self.available_memory_bytes,
            "available_memory_ratio": self.available_memory_ratio,
            "memory_source": self.memory_source,
            "load_ratio": round(self.load_ratio, 3) if self.load_ratio is not None else None,
        }


@dataclass(slots=True)
class _RecentMetrics:
    requests: int = 0
    successes: int = 0
    failures: int = 0
    noisy: int = 0
    timeouts: int = 0
    generic: int = 0
    latency_total_ms: float = 0.0
    latency_count: int = 0

    def record(
        self,
        *,
        success: bool,
        noisy: bool,
        timeout: bool,
        generic: bool,
        latency_ms: float | None,
    ) -> None:
        self.requests += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1
        if noisy:
            self.noisy += 1
        if timeout:
            self.timeouts += 1
        if generic:
            self.generic += 1
        if latency_ms is not None and latency_ms >= 0:
            self.latency_total_ms += float(latency_ms)
            self.latency_count += 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "successes": self.successes,
            "failures": self.failures,
            "noisy": self.noisy,
            "timeouts": self.timeouts,
            "generic": self.generic,
            "avg_latency_ms": round(self.latency_total_ms / self.latency_count, 2)
            if self.latency_count
            else None,
        }

    def reset(self) -> None:
        self.requests = 0
        self.successes = 0
        self.failures = 0
        self.noisy = 0
        self.timeouts = 0
        self.generic = 0
        self.latency_total_ms = 0.0
        self.latency_count = 0


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _coerce_positive_int(value: Any, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return max(minimum, default)


def _loadavg_ratio(cpu_cap: int) -> float | None:
    if cpu_cap <= 0 or not hasattr(os, "getloadavg"):
        return None
    try:
        one_minute, _five, _fifteen = os.getloadavg()
    except OSError:
        return None
    return max(0.0, float(one_minute) / float(max(cpu_cap, 1)))


def _read_linux_meminfo() -> tuple[int | None, int | None, str]:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None, None, "unavailable"
    values: dict[str, int] = {}
    try:
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, raw_value = line.split(":", 1)
            tokens = raw_value.strip().split()
            if not tokens or not tokens[0].isdigit():
                continue
            values[key.strip()] = int(tokens[0]) * 1024
    except Exception:
        return None, None, "unavailable"
    total = values.get("MemTotal")
    available = values.get("MemAvailable") or values.get("MemFree")
    return total, available, "procfs"


def _read_sysconf_memory() -> tuple[int | None, int | None, str]:
    names = getattr(os, "sysconf_names", {})
    if "SC_PHYS_PAGES" not in names or "SC_PAGE_SIZE" not in names:
        return None, None, "unavailable"
    try:
        total = int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
        available = None
        if "SC_AVPHYS_PAGES" in names:
            available = int(os.sysconf("SC_AVPHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
        return total, available, "sysconf"
    except (OSError, ValueError):
        return None, None, "unavailable"


def _read_windows_memory() -> tuple[int | None, int | None, str]:
    if os.name != "nt":
        return None, None, "unavailable"

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    try:
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) == 0:
            return None, None, "unavailable"
    except Exception:
        return None, None, "unavailable"
    return int(status.ullTotalPhys), int(status.ullAvailPhys), "globalmemorystatusex"


def detect_host_resources(
    *,
    hard_worker_ceiling: int,
    cpu_cap_override: int = 0,
) -> HostResources:
    cpu_count = max(1, int(os.cpu_count() or 1))
    cpu_cap = cpu_count
    if cpu_cap_override > 0:
        cpu_cap = min(cpu_cap, int(cpu_cap_override))
    if hard_worker_ceiling > 0:
        cpu_cap = min(cpu_cap, int(hard_worker_ceiling))

    total, available, source = _read_windows_memory()
    if total is None:
        total, available, source = _read_linux_meminfo()
    if total is None:
        total, available, source = _read_sysconf_memory()

    return HostResources(
        cpu_count=cpu_count,
        cpu_cap=max(1, cpu_cap),
        total_memory_bytes=total,
        available_memory_bytes=available,
        memory_source=source,
        load_ratio=_loadavg_ratio(max(1, cpu_cap)),
    )


class AdaptiveExecutionController:
    def __init__(self, config: dict[str, Any] | None = None, profile_config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.profile_config = profile_config or {}
        self.enabled = bool(self.config.get("enabled", True))
        self.sample_interval_seconds = max(0.25, float(self.config.get("sample_interval_seconds", 2.0)))
        self.cooldown_seconds = max(0.0, float(self.config.get("cooldown_seconds", 6.0)))
        self.healthy_samples_for_upgrade = _coerce_positive_int(
            self.config.get("healthy_samples_for_upgrade", 3),
            3,
        )
        self.memory_per_worker_mb = _coerce_positive_int(
            self.config.get("memory_per_worker_mb", 512),
            512,
        )
        self.memory_pressure_high_ratio = max(0.01, float(self.config.get("memory_pressure_high_ratio", 0.12)))
        self.memory_pressure_critical_ratio = max(
            0.01,
            float(self.config.get("memory_pressure_critical_ratio", 0.07)),
        )
        self.load_pressure_high_ratio = max(0.1, float(self.config.get("load_pressure_high_ratio", 1.05)))
        self.load_pressure_critical_ratio = max(
            self.load_pressure_high_ratio,
            float(self.config.get("load_pressure_critical_ratio", 1.35)),
        )
        self.noisy_ratio_threshold = max(0.0, float(self.config.get("noisy_ratio_threshold", 0.25)))
        self.timeout_ratio_threshold = max(0.0, float(self.config.get("timeout_ratio_threshold", 0.2)))
        self.generic_ratio_threshold = max(0.0, float(self.config.get("generic_ratio_threshold", 0.2)))
        self.latency_degrade_ms = max(1.0, float(self.config.get("latency_degrade_ms", 2500.0)))
        self.degrade_step = _coerce_positive_int(self.config.get("degrade_step", 1), 1)
        self.critical_degrade_step = _coerce_positive_int(self.config.get("critical_degrade_step", 2), 2)
        self.web_degrade_step = _coerce_positive_int(self.config.get("web_degrade_step", 1), 1)
        self.startup_ramp_fraction = max(0.1, min(1.0, float(self.config.get("startup_ramp_fraction", 0.5))))
        self.min_dispatch_workers = _coerce_positive_int(self.config.get("min_dispatch_workers", 1), 1)
        self.min_web_workers = _coerce_positive_int(self.config.get("min_web_workers", 1), 1)
        self.max_heavy_processes = _coerce_positive_int(self.config.get("max_heavy_processes", 2), 2)
        self.timeline_limit = _coerce_positive_int(self.config.get("timeline_limit", 200), 200)

        self.web_capabilities = {
            str(item)
            for item in self.config.get(
                "web_capabilities",
                [
                    "web_probe",
                    "vhost_discovery",
                    "web_discovery",
                    "tls_probe",
                    "service_exposure_checks",
                    "web_fingerprint",
                    "web_vuln_scan",
                    "web_template_scan",
                    "web_injection_scan",
                    "cms_wordpress_scan",
                ],
            )
            if str(item).strip()
        }
        self.heavy_process_capabilities = {
            str(item)
            for item in self.config.get(
                "heavy_process_capabilities",
                [
                    "network_fast_scan",
                    "network_port_scan",
                    "web_fingerprint",
                    "web_vuln_scan",
                    "web_template_scan",
                    "web_injection_scan",
                    "cms_wordpress_scan",
                    "cms_framework_scan",
                ],
            )
            if str(item).strip()
        }
        self.stage_worker_caps = self.config.get("stage_worker_caps", {}) if isinstance(
            self.config.get("stage_worker_caps", {}),
            dict,
        ) else {}
        self.capability_worker_caps = self.config.get("capability_worker_caps", {}) if isinstance(
            self.config.get("capability_worker_caps", {}),
            dict,
        ) else {}
        self.tool_overrides = self.config.get("tool_overrides", {}) if isinstance(
            self.config.get("tool_overrides", {}),
            dict,
        ) else {}

        self._global_recent = _RecentMetrics()
        self._web_recent = _RecentMetrics()
        self._timeline: list[dict[str, Any]] = []
        self._healthy_streak = 0
        self._web_healthy_streak = 0
        self._last_sample_monotonic = 0.0
        self._last_change_monotonic = 0.0

        hard_ceiling = max(1, int(self.profile_config.get("concurrency", 2)))
        cpu_cap_override = int(self.profile_config.get("cpu_cores", 0) or self.config.get("cpu_core_cap", 0) or 0)
        self.host_resources = detect_host_resources(
            hard_worker_ceiling=hard_ceiling,
            cpu_cap_override=max(0, cpu_cap_override),
        )

        memory_ceiling = hard_ceiling
        if self.host_resources.available_memory_bytes:
            available_mb = max(1, int(self.host_resources.available_memory_bytes // (1024 * 1024)))
            memory_ceiling = max(1, available_mb // max(1, self.memory_per_worker_mb))
        self.hard_max_workers = max(1, min(hard_ceiling, self.host_resources.cpu_cap, memory_ceiling))
        startup_budget = max(
            self.min_dispatch_workers,
            min(self.hard_max_workers, int(math.ceil(self.hard_max_workers * self.startup_ramp_fraction))),
        )
        self.startup_budget = startup_budget if self.enabled else hard_ceiling
        self.current_budget = self.startup_budget
        self.current_web_budget = max(self.min_web_workers, min(self.current_budget, self.startup_budget))
        self.latest_host_sample = self.host_resources

        self._append_timeline(
            event="startup",
            reason="controller_initialized",
            dispatch_budget=self.current_budget,
            web_budget=self.current_web_budget,
            host=self.host_resources.as_dict(),
        )

    def _append_timeline(self, *, event: str, reason: str, **payload: Any) -> None:
        entry = {
            "timestamp_monotonic": round(time.monotonic(), 3),
            "event": event,
            "reason": reason,
            **payload,
        }
        self._timeline.append(entry)
        if len(self._timeline) > self.timeline_limit:
            self._timeline = self._timeline[-self.timeline_limit :]

    def is_enabled(self) -> bool:
        return self.enabled

    def is_web_capability(self, capability: str) -> bool:
        return str(capability) in self.web_capabilities

    def is_heavy_capability(self, capability: str) -> bool:
        return str(capability) in self.heavy_process_capabilities

    def dispatch_budget(self) -> int:
        return max(1, self.current_budget if self.enabled else self.hard_max_workers)

    def heavy_process_limit(self) -> int:
        return max(1, min(self.max_heavy_processes, self.dispatch_budget()))

    def stage_budget(self, stage: str, capability: str | None = None) -> int:
        budget = self.dispatch_budget()
        stage_caps = self.stage_worker_caps.get(stage, {}) if isinstance(self.stage_worker_caps.get(stage, {}), dict) else {}
        stage_min = _coerce_positive_int(stage_caps.get("min", 1), 1)
        stage_max = _coerce_positive_int(stage_caps.get("max", budget), budget)
        budget = min(budget, stage_max)

        capability_text = str(capability or "")
        capability_caps = self.capability_worker_caps.get(capability_text, {}) if isinstance(
            self.capability_worker_caps.get(capability_text, {}),
            dict,
        ) else {}
        capability_min = _coerce_positive_int(capability_caps.get("min", 1), 1)
        capability_max = _coerce_positive_int(capability_caps.get("max", budget), budget)
        budget = min(budget, capability_max)
        if capability_text and self.is_web_capability(capability_text):
            budget = min(budget, self.current_web_budget)
            capability_min = max(capability_min, self.min_web_workers)
        return _clamp(budget, max(stage_min, capability_min), max(1, self.hard_max_workers))

    def worker_budget(
        self,
        capability: str,
        *,
        stage: str | None = None,
        pending_count: int = 0,
        ceiling: int | None = None,
    ) -> int:
        base = self.stage_budget(stage or "enumeration", capability)
        if pending_count > 0:
            base = min(base, max(1, int(pending_count)))
        if ceiling is not None:
            base = min(base, int(ceiling))
        return max(1, base)

    def tool_budget(self, capability: str, *, target_count: int = 1) -> dict[str, int]:
        capability_text = str(capability)
        stage = self._stage_for_capability(capability_text)
        workers = self.worker_budget(capability_text, stage=stage, pending_count=target_count)
        overrides = self.tool_overrides.get(capability_text, {}) if isinstance(
            self.tool_overrides.get(capability_text, {}),
            dict,
        ) else {}
        min_threads = _coerce_positive_int(overrides.get("min_threads", 1), 1)
        max_threads = _coerce_positive_int(overrides.get("max_threads", workers), workers)
        rate_per_worker = _coerce_positive_int(overrides.get("rate_per_worker", 800), 800)
        min_rate = _coerce_positive_int(overrides.get("min_rate", rate_per_worker), rate_per_worker)
        max_rate = _coerce_positive_int(overrides.get("max_rate", rate_per_worker * max_threads), rate_per_worker)
        rate = _clamp(rate_per_worker * max(1, workers), min_rate, max_rate)
        return {
            "workers": max(1, workers),
            "threads": _clamp(max(1, workers), min_threads, max_threads),
            "rate": rate,
        }

    def _stage_for_capability(self, capability: str) -> str:
        if capability in {"network_fast_scan", "network_port_scan", "subdomain_enumeration", "dns_resolution"}:
            return "recon"
        if capability in {"findings_engine", "vuln_enrichment"}:
            return "analysis"
        if capability == "reporting":
            return "output"
        return "enumeration"

    def record_event(
        self,
        *,
        capability: str,
        success: bool,
        latency_ms: float | None = None,
        noisy: bool = False,
        timeout: bool = False,
        generic: bool = False,
    ) -> None:
        self._global_recent.record(
            success=success,
            noisy=noisy,
            timeout=timeout,
            generic=generic,
            latency_ms=latency_ms,
        )
        if self.is_web_capability(capability):
            self._web_recent.record(
                success=success,
                noisy=noisy,
                timeout=timeout,
                generic=generic,
                latency_ms=latency_ms,
            )

    def record_task_result(
        self,
        *,
        capability: str,
        stage: str,
        duration_seconds: float,
        success: bool,
        timed_out: bool = False,
    ) -> None:
        self.record_event(
            capability=capability,
            success=success,
            latency_ms=max(0.0, float(duration_seconds)) * 1000.0,
            noisy=False,
            timeout=timed_out,
            generic=False,
        )
        self._append_timeline(
            event="task_result",
            reason="task_completed",
            capability=capability,
            stage=stage,
            success=success,
            duration_ms=round(max(0.0, float(duration_seconds)) * 1000.0, 2),
            timed_out=timed_out,
        )

    def _sample_host(self) -> HostResources:
        cpu_cap_override = int(self.profile_config.get("cpu_cores", 0) or self.config.get("cpu_core_cap", 0) or 0)
        return detect_host_resources(
            hard_worker_ceiling=max(1, int(self.profile_config.get("concurrency", self.hard_max_workers))),
            cpu_cap_override=max(0, cpu_cap_override),
        )

    def _can_upgrade(self, now_monotonic: float) -> bool:
        if self.current_budget >= self.hard_max_workers:
            return False
        if self._last_change_monotonic <= 0:
            return True
        return (now_monotonic - self._last_change_monotonic) >= self.cooldown_seconds

    def refresh(self, *, pending_count: int = 0, running_count: int = 0) -> bool:
        if not self.enabled:
            return False
        now_monotonic = time.monotonic()
        if (now_monotonic - self._last_sample_monotonic) < self.sample_interval_seconds:
            return False
        self._last_sample_monotonic = now_monotonic
        self.latest_host_sample = self._sample_host()
        global_metrics = self._global_recent.snapshot()
        web_metrics = self._web_recent.snapshot()

        noisy_ratio = (
            float(self._global_recent.noisy) / float(self._global_recent.requests)
            if self._global_recent.requests
            else 0.0
        )
        timeout_ratio = (
            float(self._global_recent.timeouts) / float(self._global_recent.requests)
            if self._global_recent.requests
            else 0.0
        )
        generic_ratio = (
            float(self._global_recent.generic) / float(self._global_recent.requests)
            if self._global_recent.requests
            else 0.0
        )
        avg_latency = (
            float(self._global_recent.latency_total_ms) / float(self._global_recent.latency_count)
            if self._global_recent.latency_count
            else 0.0
        )
        memory_ratio = self.latest_host_sample.available_memory_ratio
        load_ratio = self.latest_host_sample.load_ratio

        dispatch_before = self.current_budget
        web_before = self.current_web_budget
        change_reason = "steady_state"
        changed = False

        emergency_downgrade = bool(
            (memory_ratio is not None and memory_ratio <= self.memory_pressure_critical_ratio)
            or (load_ratio is not None and load_ratio >= self.load_pressure_critical_ratio)
        )
        regular_downgrade = bool(
            (memory_ratio is not None and memory_ratio <= self.memory_pressure_high_ratio)
            or (load_ratio is not None and load_ratio >= self.load_pressure_high_ratio)
            or noisy_ratio >= self.noisy_ratio_threshold
            or timeout_ratio >= self.timeout_ratio_threshold
            or generic_ratio >= self.generic_ratio_threshold
            or avg_latency >= self.latency_degrade_ms
        )

        if emergency_downgrade:
            self.current_budget = max(self.min_dispatch_workers, self.current_budget - self.critical_degrade_step)
            self.current_web_budget = max(self.min_web_workers, min(self.current_web_budget, self.current_budget))
            self._healthy_streak = 0
            self._web_healthy_streak = 0
            changed = self.current_budget != dispatch_before or self.current_web_budget != web_before
            change_reason = "critical_pressure"
        elif regular_downgrade:
            self.current_budget = max(self.min_dispatch_workers, self.current_budget - self.degrade_step)
            self.current_web_budget = max(
                self.min_web_workers,
                min(self.current_budget, self.current_web_budget - self.web_degrade_step),
            )
            self._healthy_streak = 0
            self._web_healthy_streak = 0
            changed = self.current_budget != dispatch_before or self.current_web_budget != web_before
            change_reason = "telemetry_pressure"
        else:
            self._healthy_streak += 1
            self._web_healthy_streak += 1
            if (
                pending_count > running_count
                and running_count >= max(0, dispatch_before - 1)
                and self._healthy_streak >= self.healthy_samples_for_upgrade
                and self._can_upgrade(now_monotonic)
            ):
                self.current_budget = min(self.hard_max_workers, self.current_budget + 1)
                changed = self.current_budget != dispatch_before
                if changed:
                    self._healthy_streak = 0
                    change_reason = "healthy_scale_up"
            if (
                self._web_healthy_streak >= self.healthy_samples_for_upgrade
                and self._can_upgrade(now_monotonic)
                and self.current_web_budget < self.current_budget
            ):
                self.current_web_budget = min(self.current_budget, self.current_web_budget + 1)
                changed = changed or self.current_web_budget != web_before
                if self.current_web_budget != web_before:
                    self._web_healthy_streak = 0
                    if change_reason == "steady_state":
                        change_reason = "web_recovery"

        if changed:
            self._last_change_monotonic = now_monotonic

        self._append_timeline(
            event="sample",
            reason=change_reason,
            dispatch_budget=self.current_budget,
            web_budget=self.current_web_budget,
            pending_count=pending_count,
            running_count=running_count,
            global_metrics=global_metrics,
            web_metrics=web_metrics,
            host=self.latest_host_sample.as_dict(),
        )
        self._global_recent.reset()
        self._web_recent.reset()
        return changed

    def snapshot(self) -> dict[str, Any]:
        downgrade_reasons = [
            entry["reason"]
            for entry in self._timeline
            if entry.get("event") == "sample"
            and str(entry.get("reason", "")).endswith("pressure")
        ]
        return {
            "enabled": self.enabled,
            "startup_budget": self.startup_budget,
            "hard_max_workers": self.hard_max_workers,
            "current_state": {
                "dispatch_budget": self.current_budget,
                "web_budget": self.current_web_budget,
                "heavy_process_limit": self.heavy_process_limit(),
                "host_resources": self.host_resources.as_dict(),
                "latest_host_sample": self.latest_host_sample.as_dict(),
            },
            "timeline": list(self._timeline),
            "downgrade_reasons": downgrade_reasons,
        }
