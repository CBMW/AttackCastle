from __future__ import annotations

from pathlib import Path

from attackcastle.core.enums import RunState, Severity, TaskStatus
from attackcastle.core.models import (
    Evidence,
    Finding,
    Observation,
    RunData,
    RunMetadata,
    Service,
    ToolExecution,
    WebApplication,
    now_utc,
)
from attackcastle.gui.models import GuiProfile
from attackcastle.gui.runtime import profile_to_engine_overrides
from attackcastle.gui.runtime import load_run_snapshot
from attackcastle.storage.run_store import RunStore


def test_load_run_snapshot_reads_checkpoints_and_outputs(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="gui-test")
    started_at = now_utc()
    stdout_path = run_store.logs_dir / "nmap.stdout.txt"
    stderr_path = run_store.logs_dir / "nmap.stderr.txt"
    raw_artifact_path = run_store.artifact_path("nmap", "scan.xml")
    screenshot_path = run_store.artifact_path("web_probe", "home.png")
    response_path = run_store.artifact_path("web_probe", "response.txt")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text("nmap stdout", encoding="utf-8")
    stderr_path.write_text("nmap stderr", encoding="utf-8")
    raw_artifact_path.write_text("<xml />", encoding="utf-8")
    screenshot_path.write_text("png", encoding="utf-8")
    response_path.write_text("response", encoding="utf-8")
    run_data = RunData(
        metadata=RunMetadata(
            run_id="gui-test",
            target_input="example.com",
            profile="prototype",
            output_dir=str(run_store.run_dir),
            started_at=started_at,
            state=RunState.RUNNING,
        ),
        services=[
            Service(
                service_id="service_1",
                asset_id="asset_1",
                port=443,
                protocol="tcp",
                state="open",
                name="https",
            )
        ],
        web_apps=[
            WebApplication(
                webapp_id="webapp_1",
                asset_id="asset_1",
                service_id="service_1",
                url="https://example.com",
                status_code=200,
                title="Example Domain",
                source_tool="web_probe",
            )
        ],
        observations=[
            Observation(
                observation_id="obs_1",
                key="web.discovery.urls",
                value=["https://example.com", "https://example.com/login"],
                entity_type="web_app",
                entity_id="webapp_1",
                source_tool="web_discovery",
            )
        ],
        evidence=[
            Evidence(
                evidence_id="evidence_1",
                source_tool="web_probe",
                kind="web_screenshot",
                snippet="Homepage screenshot",
                artifact_path=str(screenshot_path),
            ),
            Evidence(
                evidence_id="evidence_2",
                source_tool="web_probe",
                kind="http_response",
                snippet="200 OK",
                artifact_path=str(response_path),
            ),
        ],
        findings=[
            Finding(
                finding_id="finding_1",
                template_id="TEST",
                title="Interesting issue",
                severity=Severity.MEDIUM,
                category="web",
                description="desc",
                impact="impact",
                likelihood="medium",
                recommendations=["fix it"],
                references=[],
                tags=["demo"],
                affected_entities=[],
                evidence_ids=[],
                status="confirmed",
            )
        ],
        tool_executions=[
            ToolExecution(
                execution_id="exec_1",
                tool_name="nmap",
                command="nmap -sV example.com",
                started_at=started_at,
                ended_at=started_at,
                exit_code=0,
                status="completed",
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                raw_artifact_paths=[str(raw_artifact_path)],
            )
        ],
        task_states=[
            {
                "key": "run-masscan",
                "label": "Masscan",
                "status": TaskStatus.FAILED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {"stage": "recon", "capability": "masscan"},
                "error": "masscan exited unexpectedly",
            }
        ],
        warnings=["masscan binary not found on PATH"],
        errors=["run-masscan: masscan exited unexpectedly"],
        facts={
            "gui.extensions": [
                {
                    "extension_id": "custom-tool",
                    "name": "Custom Tool",
                    "status": "completed",
                    "summary": "Custom output ready.",
                }
            ]
        },
    )
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "GUI Scan",
            "started_at": started_at.isoformat(),
            "run_id": "gui-test",
        },
    )
    run_store.write_json(
        "data/plan.json",
        {
            "items": [
                {"key": "run-masscan", "selected": True},
                {"key": "run-nmap", "selected": True},
            ]
        },
    )
    run_store.save_checkpoint("run-masscan", "running", run_data)

    snapshot = load_run_snapshot(run_store.run_dir)
    assert snapshot.scan_name == "GUI Scan"
    assert snapshot.total_tasks == 2
    assert snapshot.current_task == "run-masscan"
    assert len(snapshot.services) == 1
    assert len(snapshot.web_apps) == 1
    assert snapshot.web_apps[0]["url"] == "https://example.com"
    assert len(snapshot.site_map) == 2
    assert {row["url"] for row in snapshot.site_map} == {
        "https://example.com",
        "https://example.com/login",
    }
    assert len(snapshot.evidence) == 2
    assert {row["kind"] for row in snapshot.evidence} == {"web_screenshot", "http_response"}
    assert any(item["path"] == str(screenshot_path) for item in snapshot.screenshots)
    artifact_paths = {item["path"] for item in snapshot.artifacts}
    assert str(response_path) in artifact_paths
    assert str(stdout_path) in artifact_paths
    assert str(stderr_path) in artifact_paths
    assert str(raw_artifact_path) in artifact_paths
    assert len(snapshot.findings) == 1
    assert snapshot.extensions[0]["extension_id"] == "custom-tool"
    assert snapshot.execution_issues
    assert snapshot.execution_issues_summary["total_count"] >= 3
    assert snapshot.completeness_status in {"partial", "failed"}


def test_profile_to_engine_overrides_includes_wordlists() -> None:
    profile = GuiProfile(
        name="Wordlist Profile",
        adaptive_execution_enabled=False,
        cpu_cores=3,
        active_validation_mode="aggressive",
        request_replay_enabled=False,
        validation_budget_per_target=11,
        target_duration_hours=48,
        revisit_enabled=True,
        breadth_first=False,
        unauthenticated_only=True,
        enable_tls_playbooks=True,
        enable_service_playbooks=True,
        injection_preset_path="/tmp/injection.txt",
        endpoint_wordlist_path="/tmp/endpoints.txt",
        parameter_wordlist_path="/tmp/params.txt",
        payload_wordlist_path="/tmp/payloads.txt",
    )

    overrides = profile_to_engine_overrides(profile)

    assert overrides["web_discovery"]["endpoint_wordlist_path"] == "/tmp/endpoints.txt"
    assert overrides["web_discovery"]["parameter_wordlist_path"] == "/tmp/params.txt"
    assert overrides["web_discovery"]["payload_wordlist_path"] == "/tmp/payloads.txt"
    assert overrides["sqlmap"]["parameter_wordlist_path"] == "/tmp/params.txt"
    assert overrides["nuclei"]["payload_wordlist_path"] == "/tmp/payloads.txt"
    assert overrides["active_validation"]["mode"] == "aggressive"
    assert overrides["active_validation"]["request_replay_enabled"] is False
    assert overrides["active_validation"]["per_target_budget"] == 11
    assert overrides["active_validation"]["families"]["injection"]["preset_path"] == "/tmp/injection.txt"
    assert overrides["coverage_engine"]["mode"] == "aggressive"
    assert overrides["coverage_engine"]["target_duration_hours"] == 48
    assert overrides["coverage_engine"]["breadth_first"] is False
    assert overrides["coverage_engine"]["unauthenticated_only"] is True
    assert overrides["coverage_engine"]["groups"]["tls"]["enabled"] is True
    assert overrides["coverage_engine"]["groups"]["service"]["enabled"] is True
    assert overrides["adaptive_execution"]["enabled"] is False
    assert overrides["adaptive_execution"]["cpu_core_cap"] == 3
    assert overrides["profile"]["cpu_cores"] == 3
