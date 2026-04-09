from attackcastle.core.models import Asset, RunData, RunMetadata, Service, now_utc
from attackcastle.normalization.correlator import collect_web_targets
from attackcastle.reporting.viewmodel import build_view_model


def _run_data() -> RunData:
    run_data = RunData(
        metadata=RunMetadata(
            run_id="vhost",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )
    run_data.assets.extend(
        [
            Asset(asset_id="asset_host", kind="host", name="203.0.113.10", ip="203.0.113.10"),
            Asset(
                asset_id="asset_domain",
                kind="domain",
                name="portal.example.com",
                parent_asset_id="asset_host",
            ),
        ]
    )
    run_data.services.append(
        Service(
            service_id="service_1",
            asset_id="asset_host",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
        )
    )
    return run_data


def test_collect_web_targets_includes_vhost_candidates():
    run_data = _run_data()
    run_data.facts["vhost_discovery.url_candidates"] = [
        {"url": "https://admin.example.com", "asset_id": "asset_host", "service_id": "service_1"}
    ]

    targets = collect_web_targets(run_data)

    assert any(item["url"] == "https://admin.example.com" for item in targets)


def test_view_model_exposes_asset_groups():
    run_data = _run_data()

    view_model = build_view_model(run_data, audience="client")

    assert "asset_groups" in view_model
    assert view_model["asset_groups"]
