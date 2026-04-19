from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

from attackcastle.gui import performance
from attackcastle.gui.performance import (
    ProcessTreeUsageSampler,
    ResourceLimitSettings,
    load_performance_guard_settings,
    save_performance_guard_settings,
)


class _FakeProcess:
    def __init__(self, pid: int, *, cpu_total: float, rss: int, children: list["_FakeProcess"] | None = None) -> None:
        self.pid = pid
        self._cpu_total = cpu_total
        self._rss = rss
        self._children = children or []

    def children(self, recursive: bool = True) -> list["_FakeProcess"]:  # noqa: ARG002
        return list(self._children)

    def oneshot(self):
        return nullcontext()

    def cpu_times(self):
        return SimpleNamespace(user=self._cpu_total, system=0.0)

    def memory_info(self):
        return SimpleNamespace(rss=self._rss)


def test_resource_limit_settings_default_to_max() -> None:
    settings = ResourceLimitSettings.defaults()

    assert settings.enabled is True
    assert settings.cpu_limit_percent == 100
    assert settings.memory_limit_percent == 100
    assert settings.throttle_payload()["cpu_limit_percent"] == 100
    assert settings.throttle_payload()["memory_limit_percent"] == 100


def test_resource_limit_settings_migrates_v1_payload(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        '{"version": 1, "performance_guard": {"enabled": true, "cpu_alert_percent": 55, "memory_alert_percent": 77}}',
        encoding="utf-8",
    )

    settings = load_performance_guard_settings(path)

    assert settings.cpu_limit_percent == 55
    assert settings.memory_limit_percent == 77
    saved = save_performance_guard_settings(settings, path)
    assert saved == path


def test_process_tree_usage_sampler_aggregates_children(monkeypatch) -> None:
    monkeypatch.setattr(performance.os, "cpu_count", lambda: 4)
    times = iter([100.0, 102.0])
    monkeypatch.setattr("time.monotonic", lambda: next(times))
    call_count = {"count": 0}

    class _FakePsutil:
        @staticmethod
        def Process(pid: int) -> _FakeProcess:  # noqa: N802
            sample_index = min(call_count["count"], 1)
            call_count["count"] += 1
            root_cpu = [1.0, 5.0][sample_index]
            child_cpu = [1.0, 5.0][sample_index]
            return _FakeProcess(
                pid,
                cpu_total=root_cpu,
                rss=100,
                children=[_FakeProcess(pid + 1, cpu_total=child_cpu, rss=300)],
            )

        @staticmethod
        def virtual_memory():
            return SimpleNamespace(total=2000)

    monkeypatch.setattr(performance, "psutil", _FakePsutil)
    sampler = ProcessTreeUsageSampler()

    first = sampler.sample([123])
    second = sampler.sample([123])

    assert first.cpu_percent is None
    assert second.cpu_percent == 100.0
    assert second.memory_used_bytes == 400
    assert second.memory_used_percent == 20.0
    assert second.process_count == 2
