from attackcastle.analysis import build_evidence_bundles, build_priority_leads
from attackcastle.core.models import Asset, Evidence, Observation, RunData, RunMetadata, Service, WebApplication, now_utc


def _run_data() -> RunData:
    run_data = RunData(
        metadata=RunMetadata(
            run_id="priority",
            target_input="example.com",
            profile="cautious",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )
    run_data.assets.append(Asset(asset_id="asset_1", kind="host", name="portal.example.com", ip="203.0.113.10"))
    run_data.services.append(
        Service(
            service_id="service_1",
            asset_id="asset_1",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
            banner="nginx 1.18",
        )
    )
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web_1",
            asset_id="asset_1",
            service_id="service_1",
            url="https://portal.example.com",
            title="Portal Login",
            forms_count=1,
        )
    )
    run_data.evidence.append(
        Evidence(
            evidence_id="e1",
            source_tool="web_probe",
            kind="http_response",
            snippet="login portal",
            artifact_path="/tmp/portal.txt",
        )
    )
    return run_data


def test_priority_engine_builds_high_value_web_lead():
    run_data = _run_data()
    run_data.observations.extend(
        [
            Observation(
                observation_id="o1",
                key="web.login_portal",
                value=["password input field detected"],
                entity_type="web_app",
                entity_id="web_1",
                source_tool="web_probe",
                evidence_ids=["e1"],
            ),
            Observation(
                observation_id="o2",
                key="web.admin_interface",
                value=["/admin"],
                entity_type="web_app",
                entity_id="web_1",
                source_tool="web_probe",
                evidence_ids=["e1"],
            ),
        ]
    )

    leads = build_priority_leads(run_data)

    assert leads
    assert leads[0].priority_label in {"very-high", "high"}
    assert "login" in leads[0].title.lower() or "portal" in leads[0].title.lower()


def test_evidence_bundles_collect_related_artifacts():
    run_data = _run_data()
    run_data.observations.append(
        Observation(
            observation_id="o1",
            key="web.login_portal",
            value=["password input field detected"],
            entity_type="web_app",
            entity_id="web_1",
            source_tool="web_probe",
            evidence_ids=["e1"],
        )
    )
    run_data.leads = build_priority_leads(run_data)

    bundles = build_evidence_bundles(run_data)

    assert bundles
    assert any(bundle.entity_type == "web_app" for bundle in bundles)
    assert any("e1" in bundle.evidence_ids for bundle in bundles)
