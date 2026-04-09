from __future__ import annotations

import subprocess
from pathlib import Path

from attackcastle.adapters.resolve_hosts.adapter import ResolveHostsAdapter, resolve_hostname
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.interfaces import AdapterResult
from attackcastle.core.models import Asset, RunData, RunMetadata, now_utc
from attackcastle.normalization.mapper import merge_adapter_result
from attackcastle.storage.run_store import RunStore


class _Audit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def write(self, event, payload):  # noqa: ANN001, D401
        self.events.append((event, payload))


class _Logger:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def info(self, message, *args) -> None:  # noqa: ANN001
        if args:
            message = message % args
        self.messages.append(str(message))


def _context(tmp_path: Path) -> tuple[AdapterContext, _Logger, _Audit]:
    run_store = RunStore(output_root=tmp_path, run_id="resolve-hosts-test")
    logger = _Logger()
    audit = _Audit()
    return (
        AdapterContext(
            profile_name="prototype",
            config={},
            profile_config={},
            run_store=run_store,
            logger=logger,
            audit=audit,
        ),
        logger,
        audit,
    )


def _context_with_events(tmp_path: Path) -> tuple[AdapterContext, list[tuple[str, dict]]]:
    run_store = RunStore(output_root=tmp_path, run_id="resolve-hosts-events")
    events: list[tuple[str, dict]] = []
    return (
        AdapterContext(
            profile_name="prototype",
            config={},
            profile_config={},
            run_store=run_store,
            logger=_Logger(),
            audit=_Audit(),
            event_emitter=lambda event, payload: events.append((str(event), dict(payload))),
        ),
        events,
    )


def _run_data(tmp_path: Path) -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="resolve-hosts-test",
            target_input="example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )


def test_resolve_hostname_extracts_only_ipv4_lines(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["dig", "example.com", "+short"],
            returncode=0,
            stdout="23.227.38.65\nexample.com.\n104.18.32.10\n104.18.32.10\n",
            stderr="",
        ),
    )

    assert resolve_hostname("example.com") == ["23.227.38.65", "104.18.32.10"]


def test_resolve_hosts_adapter_enriches_hostname_assets(monkeypatch, tmp_path: Path) -> None:
    context, logger, audit = _context(tmp_path)
    run_data = _run_data(tmp_path)
    run_data.assets.extend(
        [
            Asset(asset_id="asset_domain", kind="domain", name="api.example.com"),
            Asset(asset_id="asset_scope", kind="scope_target", name="api.example.com"),
            Asset(asset_id="asset_ip", kind="host", name="203.0.113.10", ip="203.0.113.10"),
        ]
    )

    monkeypatch.setattr("attackcastle.adapters.resolve_hosts.adapter.shutil.which", lambda _cmd: "dig")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["dig", "api.example.com", "+short"],
            returncode=0,
            stdout="203.0.113.10\n203.0.113.11\n",
            stderr="",
        ),
    )

    result = ResolveHostsAdapter().run(context, run_data)

    assert [asset.asset_id for asset in result.assets] == ["asset_domain", "asset_scope"]
    assert result.assets[0].ip == "203.0.113.10"
    assert result.assets[0].resolved_ips == ["203.0.113.10", "203.0.113.11"]
    assert result.assets[1].resolved_ips == ["203.0.113.10", "203.0.113.11"]
    assert all(observation.key == "dns.resolved_ips" for observation in result.observations)
    assert {observation.entity_id for observation in result.observations} == {"asset_domain", "asset_scope"}
    assert result.task_results[0].status == "completed"
    assert result.task_results[0].parsed_entities == [
        {"type": "ResolvedHost", "fqdn": "api.example.com", "ips": ["203.0.113.10", "203.0.113.11"]}
    ]
    assert any("[resolve-hosts] api.example.com -> 203.0.113.10" in message for message in logger.messages)
    assert audit.events[-1][0] == "adapter.completed"


def test_resolve_hosts_adapter_continues_after_timeout(monkeypatch, tmp_path: Path) -> None:
    context, logger, _audit = _context(tmp_path)
    run_data = _run_data(tmp_path)
    run_data.assets.extend(
        [
            Asset(asset_id="asset_slow", kind="domain", name="slow.example.com"),
            Asset(asset_id="asset_fast", kind="domain", name="fast.example.com"),
        ]
    )

    monkeypatch.setattr("attackcastle.adapters.resolve_hosts.adapter.shutil.which", lambda _cmd: "dig")

    def _fake_run(*args, **kwargs):  # noqa: ANN001
        hostname = args[0][1]
        if hostname == "slow.example.com":
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)
        return subprocess.CompletedProcess(
            args=["dig", hostname, "+short"],
            returncode=0,
            stdout="198.51.100.20\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    result = ResolveHostsAdapter().run(context, run_data)

    assert [task.status for task in result.task_results] == ["completed", "failed"]
    assert any(asset.asset_id == "asset_fast" and asset.resolved_ips == ["198.51.100.20"] for asset in result.assets)
    assert not any(asset.asset_id == "asset_slow" for asset in result.assets)
    assert any("[resolve-hosts] slow.example.com returned no IP" in message for message in logger.messages)


def test_merge_adapter_result_updates_existing_asset_in_place(tmp_path: Path) -> None:
    run_data = _run_data(tmp_path)
    run_data.assets.append(Asset(asset_id="asset_domain", kind="domain", name="api.example.com"))

    merge_adapter_result(
        run_data,
        AdapterResult(
            assets=[
                Asset(
                    asset_id="asset_domain",
                    kind="domain",
                    name="api.example.com",
                    ip="203.0.113.10",
                    resolved_ips=["203.0.113.10", "203.0.113.11"],
                )
            ]
        ),
    )

    assert len(run_data.assets) == 1
    assert run_data.assets[0].ip == "203.0.113.10"
    assert run_data.assets[0].resolved_ips == ["203.0.113.10", "203.0.113.11"]


def test_resolve_hosts_adapter_emits_live_runtime_events(monkeypatch, tmp_path: Path) -> None:
    context, events = _context_with_events(tmp_path)
    run_data = _run_data(tmp_path)
    run_data.assets.append(Asset(asset_id="asset_domain", kind="domain", name="api.example.com"))

    monkeypatch.setattr("attackcastle.adapters.resolve_hosts.adapter.shutil.which", lambda _cmd: "dig")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["dig", "api.example.com", "+short"],
            returncode=0,
            stdout="203.0.113.10\n",
            stderr="",
        ),
    )

    ResolveHostsAdapter().run(context, run_data)

    event_names = [event for event, _payload in events]
    assert "task.progress" in event_names
    assert "task_result.recorded" in event_names
    assert "tool_execution.recorded" in event_names
    assert "artifact.available" in event_names
    assert "entity.upserted" in event_names
