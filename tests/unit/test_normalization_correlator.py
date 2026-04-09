from attackcastle.core.models import (
    Asset,
    Evidence,
    EvidenceArtifact,
    NormalizedEntity,
    Observation,
    RunData,
    RunMetadata,
    Service,
    TaskArtifactRef,
    TaskResult,
    now_utc,
)
from attackcastle.core.interfaces import AdapterResult
from attackcastle.normalization.mapper import _merge_facts, merge_adapter_result


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="correlator-test",
            target_input="example.com",
            profile="standard",
            output_dir="/tmp",
            started_at=now_utc(),
        )
    )


def test_merge_facts_combines_lists_bools_numbers_and_scalar_overrides():
    merged = _merge_facts(
        {"ports": [80, 443], "tls": False, "scan_count": 1, "source": "nmap"},
        {"ports": [443, 8443], "tls": True, "scan_count": 3, "source": "manual"},
    )

    assert merged == {
        "ports": [80, 443, 8443],
        "tls": True,
        "scan_count": 3,
        "source": "manual",
    }


def test_merge_adapter_result_deduplicates_entities_and_creates_correlated_assertions():
    run_data = _run_data()
    run_data.assets.append(
        Asset(
            asset_id="asset-existing",
            kind="host",
            name="example.com",
            ip="203.0.113.10",
        )
    )

    first_result = AdapterResult(
        assets=[
            Asset(
                asset_id="asset-raw-1",
                kind="host",
                name="example.com",
                ip="203.0.113.10",
            )
        ],
        services=[
            Service(
                service_id="service-raw-1",
                asset_id="asset-raw-1",
                port=443,
                protocol="tcp",
                state="open",
                name="https",
            )
        ],
        evidence=[
            Evidence(
                evidence_id="evidence-raw-1",
                source_tool="nmap",
                kind="port_scan",
                snippet="443/tcp open https",
            )
        ],
        observations=[
            Observation(
                observation_id="obs-raw-1",
                key="service.detected",
                value=True,
                entity_type="service",
                entity_id="service-raw-1",
                source_tool="nmap",
                confidence=None,
                evidence_ids=["evidence-raw-1"],
            )
        ],
        facts={"ports": [443], "tls": True, "scan_count": 1, "source": "nmap"},
    )
    second_result = AdapterResult(
        assets=[
            Asset(
                asset_id="asset-raw-2",
                kind="host",
                name="example.com",
                ip="203.0.113.10",
            )
        ],
        services=[
            Service(
                service_id="service-raw-2",
                asset_id="asset-raw-2",
                port=443,
                protocol="tcp",
                state="open",
                name="https",
            )
        ],
        evidence=[
            Evidence(
                evidence_id="evidence-raw-2",
                source_tool="nmap",
                kind="port_scan",
                snippet="443/tcp open https",
            )
        ],
        observations=[
            Observation(
                observation_id="obs-raw-2",
                key="service.detected",
                value=True,
                entity_type="service",
                entity_id="service-raw-2",
                source_tool="nmap",
                evidence_ids=["evidence-raw-2"],
            )
        ],
        facts={"ports": [8443], "tls": False, "scan_count": 2, "source": "manual"},
    )

    merge_adapter_result(run_data, first_result)
    merge_adapter_result(run_data, second_result)

    assert len(run_data.assets) == 1
    assert len(run_data.services) == 1
    assert len(run_data.evidence) == 1
    assert len(run_data.observations) == 1
    assert len(run_data.assertions) == 1

    service = run_data.services[0]
    evidence = run_data.evidence[0]
    observation = run_data.observations[0]
    assertion = run_data.assertions[0]

    assert service.asset_id == "asset-existing"
    assert service.service_id.startswith("service_")
    assert evidence.evidence_id.startswith("evidence_")
    assert evidence.evidence_hash
    assert observation.entity_id == service.service_id
    assert observation.evidence_ids == [evidence.evidence_id]
    assert observation.confidence == 1.0
    assert assertion.key == "entity.detected"
    assert assertion.entity_refs == [{"entity_type": "service", "entity_id": service.service_id}]
    assert run_data.alias_map["asset-existing"] == ["asset-raw-1", "asset-raw-2"]
    assert run_data.alias_map[service.service_id] == ["service-raw-1", "service-raw-2"]
    assert run_data.facts == {
        "ports": [443, 8443],
        "tls": True,
        "scan_count": 2,
        "source": "manual",
    }


def test_merge_adapter_result_merges_normalized_entities_artifacts_and_task_results():
    run_data = _run_data()
    result = AdapterResult(
        normalized_entities=[
            NormalizedEntity(
                entity_id="entity_1",
                entity_type="Hostname",
                attributes={"fqdn": "api.example.com", "root_domain": "example.com"},
                evidence_ids=["evidence_1"],
                source_tool="subfinder",
                source_task_id="task_1",
                source_execution_id="exec_1",
            )
        ],
        evidence_artifacts=[
            EvidenceArtifact(
                artifact_id="artifact_1",
                kind="stdout",
                path="/tmp/stdout.txt",
                source_tool="subfinder",
                source_task_id="task_1",
                source_execution_id="exec_1",
            )
        ],
        task_results=[
            TaskResult(
                task_id="task_1",
                task_type="EnumerateSubdomains",
                status="completed",
                command="subfinder -silent -all -d example.com",
                exit_code=0,
                started_at=now_utc(),
                finished_at=now_utc(),
                raw_artifacts=[TaskArtifactRef(artifact_type="stdout", path="/tmp/stdout.txt")],
                parsed_entities=[{"type": "Hostname", "value": "api.example.com"}],
                metrics={"entities_created": 1},
            )
        ],
    )

    merge_adapter_result(run_data, result)

    assert len(run_data.normalized_entities) == 1
    assert run_data.normalized_entities[0].entity_type == "Hostname"
    assert len(run_data.evidence_artifacts) == 1
    assert run_data.evidence_artifacts[0].source_task_id == "task_1"
    assert len(run_data.task_results) == 1
    assert run_data.task_results[0].metrics["entities_created"] == 1
