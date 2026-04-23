from __future__ import annotations

from pathlib import Path

from attackcastle.core.enums import RunState, Severity, TargetType, TaskStatus
from attackcastle.core.models import (
    Evidence,
    EvidenceArtifact,
    EvidenceBundle,
    EntityRelationship,
    Finding,
    Observation,
    RunData,
    RunMetadata,
    ScanTarget,
    Service,
    TLSAsset,
    TaskArtifactRef,
    TaskResult,
    ToolExecution,
    WebApplication,
    now_utc,
    run_data_from_dict,
    to_serializable,
)
from attackcastle.gui.models import GuiProfile, RunSnapshot
from attackcastle.gui.runtime import profile_to_engine_overrides
from attackcastle.gui.runtime import build_run_debug_bundle
from attackcastle.gui.runtime import load_run_snapshot
from attackcastle.gui.runtime import resolve_current_task_debug_bundle
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
        scope=[
            ScanTarget(
                target_id="target_1",
                raw="example.com",
                target_type=TargetType.DOMAIN,
                value="example.com",
            )
        ],
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
        tls_assets=[
            TLSAsset(
                tls_id="tls_1",
                asset_id="asset_1",
                host="example.com",
                port=443,
                service_id="service_1",
                protocol="tls1.3",
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
        task_results=[
            TaskResult(
                task_id="task_result_1",
                task_type="run-nmap",
                status="failed",
                command="nmap -Pn --top-ports 1000 example.com",
                exit_code=1,
                started_at=started_at,
                finished_at=started_at,
                raw_artifacts=[TaskArtifactRef(artifact_type="xml", path=str(raw_artifact_path))],
                warnings=["nmap failed"],
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
        evidence_artifacts=[
            EvidenceArtifact(
                artifact_id="artifact_1",
                kind="http_response",
                path=str(response_path),
                source_tool="web_probe",
                caption="Response body",
                source_task_id="task_result_1",
                source_execution_id="exec_1",
            )
        ],
        evidence_bundles=[
            EvidenceBundle(
                bundle_id="bundle_1",
                label="Homepage bundle",
                entity_type="web_app",
                entity_id="webapp_1",
                asset_id="asset_1",
                screenshot_paths=[str(screenshot_path)],
            )
        ],
        relationships=[
            EntityRelationship(
                relationship_id="rel_1",
                source_entity_type="asset",
                source_entity_id="asset_1",
                target_entity_type="web_app",
                target_entity_id="webapp_1",
                relationship_type="discovered_by",
                source_tool="web_probe",
            )
        ],
        task_states=[
            {
                "key": "run-nmap",
                "label": "Nmap",
                "status": TaskStatus.FAILED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {"stage": "recon", "capability": "network_port_scan"},
                "error": "nmap exited unexpectedly",
            }
        ],
        warnings=["nmap binary not found on PATH"],
        errors=["run-nmap: nmap exited unexpectedly"],
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
                {"key": "run-nmap", "selected": True},
                {"key": "run-nmap", "selected": True},
            ]
        },
    )
    run_store.save_checkpoint("run-nmap", "running", run_data)

    snapshot = load_run_snapshot(run_store.run_dir)
    assert snapshot.scan_name == "GUI Scan"
    assert snapshot.total_tasks == 2
    assert snapshot.current_task == "Nmap"
    assert len(snapshot.services) == 1
    assert len(snapshot.web_apps) == 1
    assert snapshot.web_apps[0]["url"] == "https://example.com"
    assert snapshot.scope[0]["value"] == "example.com"
    assert snapshot.tls_assets[0]["host"] == "example.com"
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
    assert snapshot.task_results[0]["task_type"] == "run-nmap"
    assert snapshot.evidence_artifacts[0]["path"] == str(response_path)
    assert snapshot.evidence_bundles[0]["label"] == "Homepage bundle"
    assert snapshot.relationships[0]["relationship_type"] == "discovered_by"
    assert snapshot.extensions[0]["extension_id"] == "custom-tool"
    assert snapshot.execution_issues
    assert snapshot.execution_issues_summary["total_count"] >= 3
    assert snapshot.completeness_status in {"partial", "failed"}


def test_raw_command_and_task_instance_round_trip_and_match(tmp_path: Path) -> None:
    started_at = now_utc()
    run_data = RunData(
        metadata=RunMetadata(
            run_id="raw-command",
            target_input="https://example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=started_at,
        ),
        task_states=[
            {
                "key": "web-probe",
                "label": "Web Probe",
                "status": TaskStatus.COMPLETED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {
                    "capability": "web_probe",
                    "instance_key": "web-probe::iter1::abc",
                    "task_inputs": ["https://example.com/"],
                },
            }
        ],
        task_results=[
            TaskResult(
                task_id="task-httpx",
                task_type="web-probe",
                status=TaskStatus.COMPLETED.value,
                command="httpx -redacted",
                raw_command="httpx -silent -u https://example.com/",
                exit_code=0,
                started_at=started_at,
                finished_at=started_at,
                task_instance_key="web-probe::iter1::abc",
                task_inputs=["https://example.com/"],
            )
        ],
        tool_executions=[
            ToolExecution(
                execution_id="exec-httpx",
                tool_name="httpx",
                command="httpx -redacted",
                raw_command="httpx -silent -u https://example.com/",
                started_at=started_at,
                ended_at=started_at,
                exit_code=0,
                status=TaskStatus.COMPLETED.value,
                capability="web_probe",
                task_instance_key="web-probe::iter1::abc",
                task_inputs=["https://example.com/"],
            )
        ],
    )

    restored = run_data_from_dict(to_serializable(run_data))

    assert restored.tool_executions[0].raw_command == "httpx -silent -u https://example.com/"
    assert restored.task_results[0].raw_command == "httpx -silent -u https://example.com/"

    snapshot = RunSnapshot(
        run_id="raw-command",
        scan_name="Raw Command",
        run_dir=str(tmp_path),
        state="completed",
        elapsed_seconds=1,
        eta_seconds=0,
        current_task="Web Probe",
        total_tasks=1,
        completed_tasks=1,
        tasks=to_serializable(restored.task_states),
        task_results=to_serializable(restored.task_results),
        tool_executions=to_serializable(restored.tool_executions),
    )
    bundle = resolve_current_task_debug_bundle(snapshot, task_row=snapshot.tasks[0])

    assert bundle["tool_executions"][0]["raw_command"] == "httpx -silent -u https://example.com/"


def test_load_run_snapshot_merges_running_manifest_tasks_into_checkpoint_timeline(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="gui-running-merge")
    started_at = now_utc()
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "Running Merge",
            "started_at": started_at.isoformat(),
            "run_id": "gui-running-merge",
        },
    )
    run_store.write_json(
        "data/plan.json",
        {
            "items": [
                {"key": "run-subdomain-enum", "selected": True},
                {"key": "resolve-hosts", "selected": True},
            ]
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="gui-running-merge",
            target_input="example.com",
            profile="prototype",
            output_dir=str(run_store.run_dir),
            started_at=started_at,
            state=RunState.RUNNING,
        ),
        task_states=[
            {
                "key": "run-subdomain-enum",
                "label": "Enumerating subdomains",
                "status": TaskStatus.COMPLETED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {"stage": "recon", "capability": "subdomain_enumeration"},
            }
        ],
    )
    run_store.save_checkpoint("run-subdomain-enum", "completed", run_data)
    run_store.save_checkpoint("resolve-hosts", "running", run_data)

    snapshot = load_run_snapshot(run_store.run_dir)

    statuses_by_key = {
        str(item.get("key")): str(item.get("status"))
        for item in snapshot.tasks
    }
    assert statuses_by_key["run-subdomain-enum"] == "completed"
    assert statuses_by_key["resolve-hosts"] == "running"
    assert snapshot.current_task == "resolve-hosts"


def test_load_run_snapshot_ignores_running_manifest_rows_for_terminal_runs(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="gui-terminal-stale-running")
    started_at = now_utc()
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "Terminal Stale Running",
            "started_at": started_at.isoformat(),
            "run_id": "gui-terminal-stale-running",
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="gui-terminal-stale-running",
            target_input="example.com",
            profile="prototype",
            output_dir=str(run_store.run_dir),
            started_at=started_at,
            ended_at=started_at,
            state=RunState.COMPLETED,
        ),
        task_states=[
            {
                "key": "run-nmap",
                "label": "Running Nmap",
                "status": TaskStatus.COMPLETED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {"instance_key": "run-nmap::iter1::done"},
            }
        ],
    )
    run_store.save_checkpoint("run-nmap", "running", run_data)

    snapshot = load_run_snapshot(run_store.run_dir)

    assert [row["status"] for row in snapshot.tasks] == ["completed"]
    assert snapshot.current_task == "Running Nmap"


def test_load_run_snapshot_ignores_stale_running_manifest_when_instances_are_terminal(tmp_path: Path) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="gui-running-stale-instance")
    started_at = now_utc()
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "Running Stale Instance",
            "started_at": started_at.isoformat(),
            "run_id": "gui-running-stale-instance",
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="gui-running-stale-instance",
            target_input="example.com",
            profile="prototype",
            output_dir=str(run_store.run_dir),
            started_at=started_at,
            state=RunState.RUNNING,
        ),
        task_states=[
            {
                "key": "run-nmap",
                "label": "Running Nmap",
                "status": TaskStatus.COMPLETED.value,
                "started_at": started_at.isoformat(),
                "ended_at": started_at.isoformat(),
                "detail": {"instance_key": "run-nmap::iter1::done", "task_inputs": ["198.51.100.10"]},
            }
        ],
    )
    run_store.save_checkpoint(
        "run-nmap",
        "running",
        run_data,
        instance_key="run-nmap::iter1::stale",
        task_inputs=["198.51.100.11"],
    )

    snapshot = load_run_snapshot(run_store.run_dir)

    assert [row["status"] for row in snapshot.tasks] == ["completed"]
    assert snapshot.current_task == "Running Nmap"


def test_build_run_debug_bundle_includes_literal_output_and_run_log(tmp_path: Path) -> None:
    started_at = now_utc()
    snapshot = load_run_snapshot(
        _write_debug_run_fixture(
            tmp_path,
            "debug",
            started_at,
            transcript_text="stdout contents\nstderr contents\n",
            stdout_text="stdout contents",
            stderr_text="stderr contents",
            raw_text='{"ok": true}',
            run_log_text="run log contents",
        )
    )

    bundle = build_run_debug_bundle(snapshot)

    assert "command: httpx -json example.com" in bundle["combined_log"]
    assert "termination_reason: completed" in bundle["combined_log"]
    assert "terminal transcript:" in bundle["combined_log"]
    assert "stdout contents" in bundle["combined_log"]
    assert "stderr contents" in bundle["combined_log"]
    assert '{"ok": true}' in bundle["combined_log"]
    assert "run log contents" in bundle["combined_log"]


def test_build_run_debug_bundle_starts_with_run_health_summary(tmp_path: Path) -> None:
    started_at = now_utc()
    snapshot = load_run_snapshot(
        _write_debug_run_fixture(
            tmp_path,
            "debug-health",
            started_at,
            transcript_text="probe transcript",
            stdout_text="probe stdout",
        )
    )
    snapshot.tool_executions.append(
        {
            "execution_id": "exec-failed",
            "tool_name": "nmap",
            "command": "nmap example.com",
            "status": "failed",
            "exit_code": 1,
            "started_at": started_at.isoformat(),
            "ended_at": started_at.isoformat(),
            "timed_out": True,
        }
    )
    snapshot.scope = [
        {"value": "198.51.100.10"},
        {"value": "198.51.100.11"},
        {"value": "198.51.100.12"},
    ]
    snapshot.facts["nmap.scanned_targets"] = ["198.51.100.10", "198.51.100.11"]

    bundle = build_run_debug_bundle(snapshot)

    assert bundle["combined_log"].startswith("Run Health")
    assert "- tool_failures: 1" in bundle["combined_log"]
    assert "- tool_timeouts: 1" in bundle["combined_log"]
    assert "- nmap_coverage: scanned=2, pending=1" in bundle["combined_log"]
    assert "nmap(status=failed, exit=1)" in bundle["combined_log"]


def test_build_run_debug_bundle_surfaces_missing_files_instead_of_silently_skipping(tmp_path: Path) -> None:
    started_at = now_utc()
    snapshot = load_run_snapshot(
        _write_debug_run_fixture(
            tmp_path,
            "missing",
            started_at,
        )
    )

    bundle = build_run_debug_bundle(snapshot)

    assert "[missing file]" in bundle["combined_log"]
    assert "probe.stdout.txt" in bundle["combined_log"]


def test_build_run_debug_bundle_synthesizes_timeline_from_task_results_when_task_rows_missing(tmp_path: Path) -> None:
    started_at = now_utc()
    snapshot = load_run_snapshot(
        _write_debug_run_fixture(
            tmp_path,
            "timeline-fallback",
            started_at,
            transcript_text="probe transcript",
            stdout_text="probe stdout",
        )
    )
    snapshot.tasks = []

    bundle = build_run_debug_bundle(snapshot)

    assert "No task rows recorded." not in bundle["combined_log"]
    assert "- web-probe | status=running" in bundle["combined_log"]


def test_resolve_current_task_debug_bundle_prefers_active_task_then_latest(tmp_path: Path) -> None:
    started_at = now_utc()
    snapshot = load_run_snapshot(
        _write_debug_run_fixture(
            tmp_path,
            "current-task",
            started_at,
            stdout_text="live stdout",
            stderr_text="",
            raw_text="artifact body",
        )
    )
    stdout_path = Path(snapshot.tool_executions[0]["stdout_path"])
    stderr_path = Path(snapshot.tool_executions[0]["stderr_path"])
    raw_path = Path(snapshot.tool_executions[0]["raw_artifact_paths"][0])
    snapshot.tasks = [
        {
            "key": "resolve-hosts",
            "label": "Resolve Hosts",
            "status": "completed",
            "started_at": started_at.isoformat(),
            "ended_at": started_at.isoformat(),
            "detail": {"capability": "dns"},
        },
        {
            "key": "web-probe",
            "label": "Web Probe",
            "status": "running",
            "started_at": started_at.isoformat(),
            "ended_at": "",
            "detail": {"capability": "httpx"},
        },
    ]
    snapshot.current_task = "Web Probe"
    snapshot.task_results = [
        {
            "task_id": "task-web-probe",
            "task_type": "web-probe",
            "status": "running",
            "command": "httpx -json example.com",
            "exit_code": None,
            "started_at": started_at.isoformat(),
            "finished_at": "",
            "raw_artifacts": [{"artifact_type": "json", "path": str(raw_path)}],
        }
    ]
    snapshot.tool_executions = [
        {
            "execution_id": "exec-httpx",
            "tool_name": "httpx",
            "capability": "httpx",
            "command": "httpx -json example.com",
            "status": "running",
            "exit_code": None,
            "started_at": started_at.isoformat(),
            "ended_at": "",
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "raw_artifact_paths": [str(raw_path)],
        }
    ]
    snapshot.evidence_artifacts = [
        {
            "artifact_id": "artifact-httpx",
            "kind": "http_response",
            "path": str(raw_path),
            "source_tool": "httpx",
            "caption": "HTTP output",
            "source_task_id": "task-web-probe",
            "source_execution_id": "exec-httpx",
        }
    ]

    active_bundle = resolve_current_task_debug_bundle(snapshot)

    assert active_bundle["task"]["key"] == "web-probe"
    assert "Current Task Debug Log: Web Probe" == active_bundle["title"]
    assert "live stdout" in active_bundle["text"]

    snapshot.tasks[1]["status"] = "completed"
    snapshot.tasks[1]["ended_at"] = started_at.isoformat()
    latest_bundle = resolve_current_task_debug_bundle(snapshot)

    assert latest_bundle["task"]["key"] == "web-probe"


def _write_debug_run_fixture(
    output_root: Path,
    run_id: str,
    started_at,
    *,
    transcript_text: str | None = None,
    stdout_text: str | None = None,
    stderr_text: str | None = None,
    raw_text: str | None = None,
    run_log_text: str | None = None,
) -> Path:
    run_store = RunStore(output_root=output_root, run_id=run_id)
    transcript_path = run_store.logs_dir / "probe.transcript.txt"
    stdout_path = run_store.logs_dir / "probe.stdout.txt"
    stderr_path = run_store.logs_dir / "probe.stderr.txt"
    raw_path = run_store.artifacts_dir / "probe.json"
    if transcript_text is not None:
        transcript_path.write_text(transcript_text, encoding="utf-8")
    if stdout_text is not None:
        stdout_path.write_text(stdout_text, encoding="utf-8")
    if stderr_text is not None:
        stderr_path.write_text(stderr_text, encoding="utf-8")
    if raw_text is not None:
        raw_path.write_text(raw_text, encoding="utf-8")
    if run_log_text is not None:
        (run_store.logs_dir / "run.log").write_text(run_log_text, encoding="utf-8")
    run_store.write_json(
        "data/gui_session.json",
        {
            "scan_name": "Debug Fixture",
            "started_at": started_at.isoformat(),
            "run_id": run_id,
            "target_input": "example.com",
        },
    )
    run_store.write_json("data/plan.json", {"items": [{"key": "web-probe", "selected": True}]})
    run_data = RunData(
        metadata=RunMetadata(
            run_id=run_id,
            target_input="example.com",
            profile="prototype",
            output_dir=str(run_store.run_dir),
            started_at=started_at,
            state=RunState.RUNNING,
        ),
        task_states=[
            {
                "key": "web-probe",
                "label": "Web Probe",
                "status": "running",
                "started_at": started_at.isoformat(),
                "ended_at": "",
                "detail": {"capability": "httpx"},
            }
        ],
        task_results=[
            TaskResult(
                task_id="task-web-probe",
                task_type="web-probe",
                status="running",
                command="httpx -json example.com",
                exit_code=None,
                started_at=started_at,
                finished_at=started_at,
                transcript_path=str(transcript_path),
                raw_artifacts=[TaskArtifactRef(artifact_type="json", path=str(raw_path))],
                termination_reason="completed",
            )
        ],
        tool_executions=[
            ToolExecution(
                execution_id="exec-httpx",
                tool_name="httpx",
                command="httpx -json example.com",
                started_at=started_at,
                ended_at=started_at,
                exit_code=0,
                status="completed",
                capability="httpx",
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                transcript_path=str(transcript_path),
                raw_artifact_paths=[str(raw_path)],
                termination_reason="completed",
            )
        ],
        evidence_artifacts=[
            EvidenceArtifact(
                artifact_id="artifact-httpx",
                kind="http_response",
                path=str(raw_path),
                source_tool="httpx",
                caption="Probe output",
                source_task_id="task-web-probe",
                source_execution_id="exec-httpx",
            )
        ],
    )
    run_store.save_checkpoint("web-probe", "running", run_data)
    return run_store.run_dir


def test_profile_to_engine_overrides_includes_wordlists() -> None:
    profile = GuiProfile(
        name="Wordlist Profile",
        adaptive_execution_enabled=False,
        cpu_cores=3,
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
    assert overrides["active_validation"] == {"enabled": False}
    assert overrides["coverage_engine"] == {"enabled": False}
    assert overrides["request_capture"] == {"enabled": False}
    assert overrides["adaptive_execution"]["enabled"] is False
    assert overrides["adaptive_execution"]["cpu_core_cap"] == 3
    assert overrides["profile"]["cpu_cores"] == 3


def test_profile_to_engine_overrides_scopes_reused_nmap_rows() -> None:
    profile = GuiProfile(
        name="Scoped Nmap",
        enable_nmap=True,
        tool_coverage_overrides={"service_detection.nmap": False},
    )

    overrides = profile_to_engine_overrides(profile)

    assert overrides["nmap"]["enabled"] is True
    assert overrides["nmap"]["port_discovery_enabled"] is True
    assert overrides["nmap"]["service_detection_enabled"] is False


def test_profile_to_engine_overrides_applies_performance_guard_caps() -> None:
    profile = GuiProfile(
        name="Aggressive Local",
        concurrency=16,
        cpu_cores=0,
        adaptive_execution_enabled=True,
    )

    overrides = profile_to_engine_overrides(
        profile,
        {
            "enabled": True,
            "throttle_cpu_cores": 2,
            "memory_alert_percent": 75,
        },
    )

    assert overrides["profile"]["concurrency"] == 2
    assert overrides["profile"]["cpu_cores"] == 2
    assert overrides["adaptive_execution"]["cpu_core_cap"] == 2
    assert overrides["adaptive_execution"]["memory_pressure_high_ratio"] == 0.25


def test_profile_to_engine_overrides_leaves_max_resource_limits_unrestricted() -> None:
    profile = GuiProfile(
        name="Default Local",
        concurrency=8,
        cpu_cores=0,
        adaptive_execution_enabled=True,
    )

    overrides = profile_to_engine_overrides(
        profile,
        {
            "enabled": True,
            "cpu_limit_percent": 100,
            "memory_limit_percent": 100,
        },
    )

    assert overrides["profile"]["concurrency"] == 8
    assert overrides["profile"]["cpu_cores"] == 0
    assert overrides["adaptive_execution"]["cpu_core_cap"] == 0
    assert "memory_pressure_high_ratio" not in overrides["adaptive_execution"]
    assert overrides["adaptive_execution"]["resource_limits"]["cpu_limit_percent"] == 100
    assert overrides["adaptive_execution"]["resource_limits"]["memory_limit_percent"] == 100
