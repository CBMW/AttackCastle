from pathlib import Path

from attackcastle.adapters.nmap.adapter import NmapAdapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import (
    Asset,
    Observation,
    RunData,
    RunMetadata,
    ScanTarget,
    WebApplication,
    now_utc,
)
from attackcastle.normalization.correlator import collect_wordpress_targets
from attackcastle.orchestration.rules import (
    has_network_scan_targets,
    has_service_scan_targets,
    has_wordpress_targets,
)
from attackcastle.storage.run_store import RunStore


def _build_run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="adaptive-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_has_network_scan_targets_uses_resolved_assets():
    run_data = _build_run_data()
    run_data.scope.append(
        ScanTarget(
            target_id="target_domain",
            raw="example.com",
            target_type=TargetType.DOMAIN,
            value="example.com",
            host="example.com",
        )
    )

    matched, _ = has_network_scan_targets(run_data)
    assert matched is False

    run_data.assets.append(
        Asset(
            asset_id="asset_host",
            kind="host",
            name="203.0.113.10",
            ip="203.0.113.10",
            source_tool="fixture",
        )
    )
    matched, _ = has_network_scan_targets(run_data)
    assert matched is True


def test_has_service_scan_targets_uses_masscan_fact_map():
    run_data = _build_run_data()
    run_data.scope.append(
        ScanTarget(
            target_id="target_ip",
            raw="203.0.113.10",
            target_type=TargetType.SINGLE_IP,
            value="203.0.113.10",
            host="203.0.113.10",
        )
    )
    run_data.facts["masscan.open_ports_by_host"] = {"203.0.113.10": []}
    matched, _ = has_service_scan_targets(run_data)
    assert matched is False

    run_data.facts["masscan.open_ports_by_host"] = {"203.0.113.10": [80, 443]}
    matched, _ = has_service_scan_targets(run_data)
    assert matched is True


def test_wordpress_target_collection_and_condition():
    run_data = _build_run_data()
    web_app = WebApplication(
        webapp_id="web_1",
        asset_id="asset_1",
        service_id="service_1",
        url="https://blog.example.com",
        source_tool="fixture",
    )
    run_data.web_apps.append(web_app)
    run_data.observations.append(
        Observation(
            observation_id="obs_wp",
            key="tech.wordpress.detected",
            value=True,
            entity_type="web_app",
            entity_id=web_app.webapp_id,
            source_tool="fixture",
            confidence=1.0,
        )
    )

    targets = collect_wordpress_targets(run_data)
    assert len(targets) == 1
    assert targets[0]["url"] == "https://blog.example.com"

    matched, _ = has_wordpress_targets(run_data)
    assert matched is True


def test_nmap_preview_uses_masscan_discovered_ports(tmp_path):
    run_data = _build_run_data()
    run_data.facts["masscan.open_ports_by_host"] = {"203.0.113.10": [443, 80]}

    run_store = RunStore(output_root=Path(tmp_path), run_id="adaptive_preview")
    context = AdapterContext(
        profile_name="standard",
        config={"scan": {"max_ports": 1000}, "nmap": {"args": []}},
        profile_config={"nmap_args": ["-sV"]},
        run_store=run_store,
        logger=None,
        audit=None,
    )

    preview = NmapAdapter().preview_commands(context, run_data)
    assert preview
    assert "203.0.113.10" in preview[0]
    assert "-p 80,443" in preview[0]
