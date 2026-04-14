from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

from attackcastle.adapters.base import StreamCommandResult
from attackcastle.adapters.nikto.adapter import NiktoAdapter
from attackcastle.adapters.nuclei.adapter import NucleiAdapter
from attackcastle.adapters.web_probe.adapter import WebProbeAdapter
from attackcastle.adapters.wpscan.adapter import WPScanAdapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import (
    Asset,
    Observation,
    RunData,
    RunMetadata,
    ScanTarget,
    Service,
    WebApplication,
    now_utc,
)
from attackcastle.normalization.correlator import collect_web_targets
from attackcastle.normalization.mapper import merge_adapter_result
from attackcastle.scope.expansion import collect_host_scan_targets, collect_resolved_host_scan_targets
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, _event: str, _payload: dict[str, object]) -> None:
        return


def _context(tmp_path: Path, run_id: str, config: dict | None = None) -> AdapterContext:
    return AdapterContext(
        profile_name="prototype",
        config=config or {},
        profile_config={},
        run_store=RunStore(output_root=tmp_path, run_id=run_id),
        logger=logging.getLogger(run_id),
        audit=_Audit(),
    )


def _run_data(tmp_path: Path, target_input: str = "example.com") -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="web-asset-frontier",
            target_input=target_input,
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )


def _confirmed_web_run_data(tmp_path: Path, url: str = "https://app.example.com") -> RunData:
    run_data = _run_data(tmp_path, target_input=url)
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web-1",
            asset_id="asset-1",
            service_id="svc-1",
            url=url,
            status_code=200,
            title="Example",
        )
    )
    return run_data


def test_collect_host_scan_targets_unions_scope_and_discovered_hosts(tmp_path: Path) -> None:
    run_data = _run_data(tmp_path)
    run_data.scope.append(
        ScanTarget(
            target_id="target-1",
            raw="example.com",
            target_type=TargetType.DOMAIN,
            value="example.com",
            host="example.com",
        )
    )
    run_data.facts["subdomain_enum.discovered_hosts"] = ["api.example.com", "WWW.EXAMPLE.COM."]

    targets = collect_host_scan_targets(run_data)

    assert "example.com" in targets
    assert "api.example.com" in targets
    assert "www.example.com" in targets


def test_collect_resolved_host_scan_targets_excludes_unresolved_hosts(tmp_path: Path) -> None:
    run_data = _run_data(tmp_path)
    run_data.scope.append(
        ScanTarget(
            target_id="target-1",
            raw="example.com",
            target_type=TargetType.DOMAIN,
            value="example.com",
            host="example.com",
        )
    )
    run_data.facts["subdomain_enum.discovered_hosts"] = ["api.example.com", "shop.example.com"]
    run_data.assets.extend(
        [
            Asset(asset_id="asset-root", kind="domain", name="example.com", ip="198.51.100.10"),
            Asset(asset_id="asset-api", kind="host", name="api.example.com", ip="203.0.113.10"),
        ]
    )

    targets = collect_resolved_host_scan_targets(run_data)

    assert "example.com" in targets
    assert "api.example.com" in targets
    assert "shop.example.com" not in targets


def test_collect_web_targets_promotes_discovered_dns_hosts_with_asset_links(tmp_path: Path) -> None:
    run_data = _run_data(tmp_path)
    run_data.facts["subdomain_enum.discovered_hosts"] = ["api.example.com"]
    run_data.assets.append(Asset(asset_id="asset-api", kind="domain", name="api.example.com"))

    targets = collect_web_targets(run_data)
    by_url = {str(item["url"]): item for item in targets}

    assert by_url["https://api.example.com/"]["asset_id"] == "asset-api"
    assert by_url["http://api.example.com/"]["asset_id"] == "asset-api"
    assert by_url["https://api.example.com:8443/"]["asset_id"] == "asset-api"
    assert by_url["http://api.example.com:8080/"]["asset_id"] == "asset-api"


def test_web_probe_prefers_hostname_targets_and_creates_confirmed_web_app(
    tmp_path: Path,
    monkeypatch,
) -> None:
    context = _context(
        tmp_path,
        "web-probe-frontier",
        config={
            "scan": {"http_timeout_seconds": 1},
            "web_probe": {"enabled": True},
        },
    )
    run_data = _run_data(tmp_path, target_input="app.example.com")
    run_data.assets.extend(
        [
            Asset(asset_id="asset-root", kind="domain", name="example.com"),
            Asset(
                asset_id="asset-host",
                kind="host",
                name="app.example.com",
                ip="203.0.113.10",
                parent_asset_id="asset-root",
            ),
        ]
    )
    run_data.services.append(
        Service(
            service_id="svc-1",
            asset_id="asset-host",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
        )
    )
    captured: dict[str, list[str]] = {}

    def _fake_run_command_spec(context, command_spec, proxy_url=None):  # noqa: ANN001
        input_path = Path(command_spec.command[command_spec.command.index("-l") + 1])
        captured["targets"] = input_path.read_text(encoding="utf-8").splitlines()
        stdout_path = context.run_store.artifact_path("httpx", "stdout.txt")
        stdout_text = (
            '{"url":"https://app.example.com","input":"https://app.example.com",'
            '"final_url":"https://app.example.com","title":"App","status_code":200,"tech":["nginx"]}'
        )
        stdout_path.write_text(stdout_text, encoding="utf-8")
        return SimpleNamespace(
            execution=SimpleNamespace(),
            evidence_artifacts=[],
            task_result=SimpleNamespace(
                task_id="task-httpx",
                status="completed",
                parsed_entities=[],
                metrics={},
                warnings=[],
            ),
            stdout_text=stdout_text,
            stdout_path=stdout_path,
            execution_id="exec-httpx",
        )

    monkeypatch.setattr("attackcastle.adapters.web_probe.adapter.run_command_spec", _fake_run_command_spec)

    result = WebProbeAdapter().run(context, run_data)

    assert "https://app.example.com/" in captured["targets"]
    assert all("203.0.113.10" not in item for item in captured["targets"])
    assert [item.url for item in result.web_apps] == ["https://app.example.com"]
    assert result.web_apps[0].asset_id == "asset-host"
    assert result.web_apps[0].service_id == "svc-1"
    assert result.technologies[0].asset_id == "asset-host"
    assert result.facts["web_probe.scanned_urls"]


def test_web_probe_skips_already_checked_candidates(tmp_path: Path, monkeypatch) -> None:
    context = _context(
        tmp_path,
        "web-probe-skip-checked",
        config={
            "scan": {"http_timeout_seconds": 1},
            "web_probe": {"enabled": True},
        },
    )
    run_data = _run_data(tmp_path, target_input="api.example.com")
    run_data.facts["subdomain_enum.discovered_hosts"] = ["api.example.com"]
    run_data.assets.append(Asset(asset_id="asset-api", kind="domain", name="api.example.com"))
    run_data.facts["web_probe.scanned_urls"] = [
        "https://api.example.com",
        "http://api.example.com",
        "https://api.example.com:8443",
        "http://api.example.com:8080",
    ]

    def _unexpected_run_command_spec(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("httpx should not run for already checked website candidates")

    monkeypatch.setattr("attackcastle.adapters.web_probe.adapter.run_command_spec", _unexpected_run_command_spec)

    result = WebProbeAdapter().run(context, run_data)

    assert result.web_apps == []
    assert result.tool_executions == []


def test_web_probe_creates_service_for_confirmed_discovered_host(tmp_path: Path, monkeypatch) -> None:
    context = _context(
        tmp_path,
        "web-probe-create-service",
        config={
            "scan": {"http_timeout_seconds": 1},
            "web_probe": {"enabled": True},
        },
    )
    run_data = _run_data(tmp_path, target_input="api.example.com")
    run_data.facts["subdomain_enum.discovered_hosts"] = ["api.example.com"]
    run_data.assets.append(Asset(asset_id="asset-api", kind="domain", name="api.example.com"))

    def _fake_run_command_spec(context, command_spec, proxy_url=None):  # noqa: ANN001
        stdout_path = context.run_store.artifact_path("httpx", "stdout.txt")
        stdout_text = (
            '{"url":"https://api.example.com","input":"https://api.example.com/",'
            '"final_url":"https://api.example.com","title":"Forbidden","status_code":403,"tech":[]}'
        )
        stdout_path.write_text(stdout_text, encoding="utf-8")
        return SimpleNamespace(
            execution=SimpleNamespace(),
            evidence_artifacts=[],
            task_result=SimpleNamespace(
                task_id="task-httpx",
                status="completed",
                parsed_entities=[],
                metrics={},
                warnings=[],
            ),
            stdout_text=stdout_text,
            stdout_path=stdout_path,
            execution_id="exec-httpx",
        )

    monkeypatch.setattr("attackcastle.adapters.web_probe.adapter.run_command_spec", _fake_run_command_spec)

    result = WebProbeAdapter().run(context, run_data)

    assert len(result.services) == 1
    assert result.services[0].asset_id == "asset-api"
    assert result.services[0].port == 443
    assert result.services[0].name == "https"
    assert result.web_apps[0].asset_id == "asset-api"
    assert result.web_apps[0].service_id == result.services[0].service_id
    assert result.web_apps[0].status_code == 403


def test_nikto_and_nuclei_skip_cleanly_when_disabled(tmp_path: Path) -> None:
    run_data = _confirmed_web_run_data(tmp_path)
    context = _context(
        tmp_path,
        "disabled-web-followups",
        config={
            "nikto": {"enabled": False},
            "nuclei": {"enabled": False},
        },
    )

    nikto_result = NiktoAdapter().run(context, run_data)
    nuclei_result = NucleiAdapter().run(context, run_data)

    assert nikto_result.tool_executions[0].status == "skipped"
    assert nikto_result.facts["nikto.available"] is False
    assert nuclei_result.tool_executions[0].status == "skipped"
    assert nuclei_result.facts["nuclei.available"] is False


def test_nikto_and_nuclei_only_scan_new_confirmed_web_targets(tmp_path: Path, monkeypatch) -> None:
    run_data = _confirmed_web_run_data(tmp_path)
    context = _context(
        tmp_path,
        "enabled-web-followups",
        config={
            "nikto": {"enabled": True, "timeout_seconds": 1},
            "nuclei": {"enabled": True, "timeout_seconds": 1},
        },
    )
    nikto_calls: list[list[str]] = []
    nuclei_calls: list[list[str]] = []

    monkeypatch.setattr("attackcastle.adapters.nikto.adapter.shutil.which", lambda _name: "nikto")
    monkeypatch.setattr("attackcastle.adapters.nuclei.adapter.shutil.which", lambda _name: "nuclei")
    monkeypatch.setattr(
        "attackcastle.adapters.nikto.adapter.parse_nikto_json",
        lambda _path: {"issues": ["header missing"]},
    )
    monkeypatch.setattr(
        "attackcastle.adapters.nuclei.adapter.parse_nuclei_jsonl",
        lambda _path: [{"template_id": "demo-template", "name": "Demo finding", "severity": "medium"}],
    )

    def _fake_nikto_stream(command, **kwargs):  # noqa: ANN001
        nikto_calls.append(list(command))
        return StreamCommandResult(
            exit_code=0,
            stdout_text="nikto-ok",
            stderr_text="",
            error_message=None,
            termination_reason="completed",
            termination_detail=None,
            timed_out=False,
        )

    def _fake_nuclei_stream(command, **kwargs):  # noqa: ANN001
        nuclei_calls.append(list(command))
        return StreamCommandResult(
            exit_code=0,
            stdout_text='{"template-id":"demo-template"}\n',
            stderr_text="",
            error_message=None,
            termination_reason="completed",
            termination_detail=None,
            timed_out=False,
        )

    monkeypatch.setattr("attackcastle.adapters.nikto.adapter.stream_command", _fake_nikto_stream)
    monkeypatch.setattr("attackcastle.adapters.nuclei.adapter.stream_command", _fake_nuclei_stream)

    nikto_first = NiktoAdapter().run(context, run_data)
    merge_adapter_result(run_data, nikto_first)
    nikto_second = NiktoAdapter().run(context, run_data)

    nuclei_first = NucleiAdapter().run(context, run_data)
    merge_adapter_result(run_data, nuclei_first)
    nuclei_second = NucleiAdapter().run(context, run_data)

    assert nikto_first.facts["nikto.scanned_targets"] == 1
    assert nikto_second.facts["nikto.scanned_targets"] == 0
    assert nikto_second.tool_executions[0].command == "nikto (no new targets)"
    assert len(nikto_calls) == 1

    assert nuclei_first.facts["nuclei.scanned_targets"] == 1
    assert nuclei_second.facts["nuclei.scanned_targets"] == 0
    assert nuclei_second.tool_executions[0].command == "nuclei (no new targets)"
    assert len(nuclei_calls) == 1


def test_wpscan_only_runs_after_wordpress_detection(tmp_path: Path, monkeypatch) -> None:
    run_data = _confirmed_web_run_data(tmp_path)
    context = _context(
        tmp_path,
        "wpscan-frontier",
        config={"wpscan": {"enabled": True, "timeout_seconds": 1}},
    )
    stream_calls: list[list[str]] = []

    monkeypatch.setattr("attackcastle.adapters.wpscan.adapter.shutil.which", lambda _name: "wpscan")
    monkeypatch.setattr(
        "attackcastle.adapters.wpscan.adapter.parse_wpscan_json",
        lambda _path: {"wordpress_version": "6.5.1", "vulnerability_titles": ["Demo vuln"]},
    )

    def _fake_wpscan_stream(command, **kwargs):  # noqa: ANN001
        stream_calls.append(list(command))
        return StreamCommandResult(
            exit_code=0,
            stdout_text="wpscan-ok",
            stderr_text="",
            error_message=None,
            termination_reason="completed",
            termination_detail=None,
            timed_out=False,
        )

    monkeypatch.setattr("attackcastle.adapters.wpscan.adapter.stream_command", _fake_wpscan_stream)

    initial = WPScanAdapter().run(context, run_data)
    run_data.observations.append(
        Observation(
            observation_id="obs-wp",
            key="tech.wordpress.detected",
            value=True,
            entity_type="web_app",
            entity_id="web-1",
            source_tool="whatweb",
        )
    )
    detected = WPScanAdapter().run(context, run_data)

    assert initial.facts["wpscan.scanned_targets"] == 0
    assert initial.tool_executions[0].command == "wpscan (no new targets)"
    assert detected.facts["wpscan.scanned_targets"] == 1
    assert len(stream_calls) == 1
