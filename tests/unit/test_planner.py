from pathlib import Path

from attackcastle.app import _seed_scope_assets
from attackcastle.adapters import DNSAdapter, HTTPSecurityHeadersAdapter, NmapAdapter, TLSAdapter, WebProbeAdapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, now_utc
from attackcastle.orchestration.planner import build_task_plan
from attackcastle.storage.run_store import RunStore


def _noop(context, run_data):  # noqa: ANN001
    return None


def test_build_task_plan_includes_deferred_tasks(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    run_store = RunStore(output_root=Path(tmp_path), run_id="plan")
    context = AdapterContext(
        profile_name="cautious",
        config={"profile": {"max_noise_score": 10}},
        profile_config={"concurrency": 2},
        run_store=run_store,
        logger=None,
        audit=None,
    )
    adapters = {
        "dns": DNSAdapter(),
        "nmap": NmapAdapter(),
        "web_probe": WebProbeAdapter(),
        "http_security_headers": HTTPSecurityHeadersAdapter(),
        "tls": TLSAdapter(),
    }
    result = build_task_plan(
        adapters=adapters,
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="cautious",
        config={"profile": {"max_noise_score": 10}},
        preview_context=context,
    )
    keys = {task.key for task in result.tasks}
    assert "check-websites" in keys
    assert "check-http-security-headers" in keys
    assert "detect-tls" in keys


def test_build_task_plan_enforces_noise_limit(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="10.0.0.0/24",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    result = build_task_plan(
        adapters={"nmap": NmapAdapter()},
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="cautious",
        config={"profile": {"max_noise_score": 2}},
    )
    keys = {task.key for task in result.tasks}
    assert "run-nmap" not in keys
    assert result.conflicts


def test_build_task_plan_respects_nmap_service_detection_toggle(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="standard",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    result = build_task_plan(
        adapters={
            "nmap": NmapAdapter(scan_mode="port_discovery"),
            "nmap_service_detection": NmapAdapter(scan_mode="service_detection"),
        },
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="standard",
        config={
            "profile": {"max_noise_score": 10},
            "nmap": {"enabled": True, "port_discovery_enabled": True, "service_detection_enabled": False},
        },
    )
    keys = {task.key for task in result.tasks}
    service_item = next(item for item in result.items if item.key == "run-nmap-service-detection")

    assert "run-nmap" in keys
    assert "run-nmap-service-detection" not in keys
    assert service_item.selected is False
    assert "service_detection_enabled" in service_item.reason


def test_build_task_plan_respects_http_security_headers_toggle(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="https://example.com",
            profile="standard",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    result = build_task_plan(
        adapters={
            "web_probe": WebProbeAdapter(),
            "http_security_headers": HTTPSecurityHeadersAdapter(),
        },
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="standard",
        config={
            "profile": {"max_noise_score": 10},
            "http_security_headers": {"enabled": False},
        },
    )
    keys = {task.key for task in result.tasks}
    item = next(item for item in result.items if item.key == "check-http-security-headers")

    assert "check-http-security-headers" not in keys
    assert item.selected is False
    assert "http_security_headers.enabled" in item.reason


def test_seed_scope_assets_only_sets_ip_for_ip_literals(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com,1.2.3.4",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        scope=[
            ScanTarget(
                target_id="target_domain",
                raw="example.com",
                target_type=TargetType.DOMAIN,
                value="example.com",
                host="example.com",
            ),
            ScanTarget(
                target_id="target_ip",
                raw="1.2.3.4",
                target_type=TargetType.SINGLE_IP,
                value="1.2.3.4",
                host="1.2.3.4",
            ),
        ],
    )

    _seed_scope_assets(run_data)

    assets_by_id = {asset.asset_id: asset for asset in run_data.assets}
    assert assets_by_id["target_domain"].ip is None
    assert assets_by_id["target_ip"].ip == "1.2.3.4"
