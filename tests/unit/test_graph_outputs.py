from __future__ import annotations

from datetime import datetime, timezone

from attackcastle.core.models import (
    Asset,
    RunData,
    RunMetadata,
    Service,
    TLSAsset,
    Technology,
    ToolExecution,
    WebApplication,
    now_utc,
)
from attackcastle.normalization.identity_graph import build_identity_graph
from attackcastle.orchestration.instance_graph import build_task_instance_graph


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="graph-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_build_identity_graph_contains_expected_nodes_and_edges():
    run_data = _run_data()
    run_data.assets.extend(
        [
            Asset(asset_id="asset-1", kind="host", name="example.com", ip="203.0.113.10"),
            Asset(
                asset_id="asset-2",
                kind="host",
                name="api.example.com",
                parent_asset_id="asset-1",
                ip="203.0.113.11",
            ),
        ]
    )
    run_data.services.append(
        Service(
            service_id="svc-1",
            asset_id="asset-1",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
        )
    )
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web-1",
            asset_id="asset-1",
            service_id="svc-1",
            url="https://example.com",
        )
    )
    run_data.tls_assets.append(
        TLSAsset(
            tls_id="tls-1",
            asset_id="asset-1",
            service_id="svc-1",
            host="example.com",
            port=443,
            protocol="tls1.3",
        )
    )
    run_data.technologies.append(
        Technology(
            tech_id="tech-1",
            asset_id="asset-1",
            webapp_id="web-1",
            name="WordPress",
            version="6.5",
        )
    )
    run_data.alias_map["asset-1"] = ["target-raw-1"]

    graph = build_identity_graph(run_data)
    summary = graph["summary"]
    relations = {edge["relation"] for edge in graph["edges"]}

    assert summary["node_count"] == 6
    assert summary["edge_count"] >= 8
    assert summary["component_count"] >= 1
    assert "parent_asset" in relations
    assert "asset_service" in relations
    assert "service_web_app" in relations
    assert "service_tls" in relations
    assert "web_app_technology" in relations
    assert "alias" in relations


def test_build_task_instance_graph_links_tasks_executions_and_targets():
    run_data = _run_data()
    run_data.task_states = [
        {
            "key": "probe-web",
            "label": "Probing web services",
            "status": "completed",
            "started_at": "2026-01-01T00:00:00+00:00",
            "ended_at": "2026-01-01T00:00:01+00:00",
            "detail": {"capability": "web_probe", "stage": "enumeration", "attempt": 1},
        },
        {
            "key": "fingerprint-web",
            "label": "Fingerprinting web technologies",
            "status": "completed",
            "started_at": "2026-01-01T00:00:02+00:00",
            "ended_at": "2026-01-01T00:00:03+00:00",
            "detail": {"capability": "web_fingerprint", "stage": "enumeration", "attempt": 1},
        },
    ]
    run_data.tool_executions.append(
        ToolExecution(
            execution_id="exec-1",
            tool_name="whatweb",
            command="whatweb https://example.com",
            started_at=datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc),
            exit_code=0,
            status="completed",
            capability="web_fingerprint",
        )
    )
    run_data.facts["web_probe.scanned_urls"] = ["https://example.com"]
    run_data.facts["whatweb.scanned_urls"] = ["https://example.com"]

    graph = build_task_instance_graph(run_data)
    summary = graph["summary"]
    edges = {(edge["source"], edge["target"], edge["relation"]) for edge in graph["edges"]}

    assert summary["task_node_count"] == 2
    assert summary["execution_node_count"] == 1
    assert summary["target_node_count"] == 1
    assert ("probe-web", "fingerprint-web", "execution_order") in edges
    assert ("fingerprint-web", "exec:exec-1", "task_execution") in edges
    assert ("probe-web", "url:https://example.com", "task_target") in edges

