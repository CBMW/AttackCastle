from __future__ import annotations

from attackcastle.core.models import Observation, RunData, RunMetadata, Technology, now_utc
from attackcastle.orchestration.escalation import task_allowed_by_matrix


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="matrix-test",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_task_allowed_by_matrix_allows_uncontrolled_tasks():
    run_data = _run_data()
    config = {"escalation": {"matrix": {"wordpress": {"tasks": ["run-wpscan"]}}}}
    allowed, reason = task_allowed_by_matrix("run-nmap", run_data, config)
    assert allowed is True
    assert reason == "task_not_controlled_by_matrix"


def test_task_allowed_by_matrix_allows_on_technology_match():
    run_data = _run_data()
    run_data.technologies.append(
        Technology(
            tech_id="tech-1",
            asset_id="asset-1",
            name="WordPress",
        )
    )
    config = {"escalation": {"matrix": {"wordpress": {"tasks": ["run-wpscan"]}}}}
    allowed, reason = task_allowed_by_matrix("run-wpscan", run_data, config)
    assert allowed is True
    assert reason.startswith("matrix_trigger_matched:")
    assert "wordpress" in reason


def test_task_allowed_by_matrix_matches_observation_trigger():
    run_data = _run_data()
    run_data.observations.append(
        Observation(
            observation_id="obs-1",
            key="tech.apache.detected",
            value=True,
            entity_type="asset",
            entity_id="asset-1",
            source_tool="fixture",
        )
    )
    config = {"escalation": {"matrix": {"apache": {"tasks": ["enrich-cve"]}}}}
    allowed, reason = task_allowed_by_matrix("enrich-cve", run_data, config)
    assert allowed is True
    assert reason.startswith("matrix_trigger_matched:")


def test_task_allowed_by_matrix_waits_when_trigger_not_detected():
    run_data = _run_data()
    config = {"escalation": {"matrix": {"wordpress": {"tasks": ["run-wpscan"]}}}}
    allowed, reason = task_allowed_by_matrix("run-wpscan", run_data, config)
    assert allowed is False
    assert reason.startswith("waiting_for_matrix_trigger:")

