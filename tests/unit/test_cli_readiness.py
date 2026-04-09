from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackcastle.app import ScanOutcome
from attackcastle.cli import app
from attackcastle.logging.audit import AuditLogger
from attackcastle.readiness import DependencyInstallSupport, ReadinessReport


def _outcome(tmp_path: Path) -> ScanOutcome:
    return ScanOutcome(
        run_id="readiness-run",
        run_dir=tmp_path,
        json_path=None,
        report_path=None,
        warning_count=0,
        error_count=0,
        finding_count=0,
        state="completed",
        duration_seconds=0.1,
    )


def _readiness(
    status: str,
    *,
    can_launch: bool,
    partial_run: bool,
    missing_tools: list[str],
) -> ReadinessReport:
    return ReadinessReport(
        status=status,
        can_launch=can_launch,
        partial_run=partial_run,
        risk_mode="safe-active",
        missing_tools=missing_tools,
        tool_impact=(
            [
                {
                    "tool": "nmap",
                    "capabilities": ["network_port_scan"],
                    "task_labels": ["Running Nmap"],
                }
            ]
            if missing_tools
            else []
        ),
        blocked_capabilities=["network_port_scan"] if missing_tools else [],
        recommended_actions=(
            ["Install missing tools with `attackcastle doctor --install-missing --yes`."]
            if missing_tools
            else ["Current environment is ready for the selected workflow."]
        ),
        selected_task_count=4,
        runnable_task_count=3 if partial_run else 4,
        blocked_task_count=1 if partial_run else 0,
        assessment_mode="targeted",
    )


def _missing_nmap_rows() -> list[dict[str, object]]:
    return [
        {
            "check": "nmap_binary",
            "command": "nmap",
            "apt_package": "nmap",
            "suggestion": "Install nmap for service detection coverage.",
            "available": False,
            "resolved_path": None,
        }
    ]


def _create_run_dir(tmp_path: Path, audit_content: str) -> Path:
    run_dir = tmp_path / "output" / "run_20260318T000000Z_readiness"
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "checkpoints").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    (run_dir / "data" / "run_summary.json").write_text(json.dumps({"state": "completed"}), encoding="utf-8")
    (run_dir / "data" / "scan_data.json").write_text(json.dumps({"scope": []}), encoding="utf-8")
    (run_dir / "checkpoints" / "manifest.json").write_text(json.dumps({"checkpoints": []}), encoding="utf-8")
    (run_dir / "logs" / "audit.jsonl").write_text(audit_content, encoding="utf-8")
    return run_dir


def test_scan_skips_apt_prompt_when_auto_install_is_unsupported(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr("attackcastle.cli._external_dependency_rows", _missing_nmap_rows)
    monkeypatch.setattr(
        "attackcastle.cli.dependency_install_support",
        lambda: DependencyInstallSupport(
            supported=False,
            reason="Automatic dependency installs are only supported on Linux/POSIX hosts with apt-get.",
            platform="nt",
        ),
    )
    monkeypatch.setattr(
        "attackcastle.cli.assess_readiness",
        lambda **kwargs: _readiness("partial", can_launch=True, partial_run=True, missing_tools=["nmap"]),
    )
    monkeypatch.setattr(
        "attackcastle.cli.Confirm.ask",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Confirm.ask should not be called")),
    )
    monkeypatch.setattr("attackcastle.cli.run_scan", lambda **kwargs: _outcome(tmp_path))

    result = runner.invoke(app, ["scan", "-t", "example.com", "-o", str(tmp_path)])

    assert result.exit_code == 0, result.stdout
    assert "Automatic dependency installs are only supported on Linux/POSIX hosts with apt-get." in result.stdout
    assert "Launch Readiness" in result.stdout


def test_guided_scan_shows_launch_readiness_panel(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    answers = iter(
        [
            "example.com",
            str(tmp_path),
            "prototype",
            "safe-active",
            "",
        ]
    )
    monkeypatch.setattr("attackcastle.cli.Prompt.ask", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr("attackcastle.cli.Confirm.ask", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        "attackcastle.cli.assess_readiness",
        lambda **kwargs: _readiness("partial", can_launch=True, partial_run=True, missing_tools=["nmap"]),
    )
    monkeypatch.setattr("attackcastle.cli.run_scan", lambda **kwargs: _outcome(tmp_path))

    result = runner.invoke(app, ["guided-scan"])

    assert result.exit_code == 0, result.stdout
    assert "Launch Readiness" in result.stdout
    assert "Missing Tools" in result.stdout
    assert "nmap" in result.stdout


def test_doctor_renders_environment_readiness_panel(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr("attackcastle.cli._external_dependency_rows", lambda: [])
    monkeypatch.setattr(
        "attackcastle.cli.assess_readiness",
        lambda **kwargs: _readiness("ready", can_launch=True, partial_run=False, missing_tools=[]),
    )

    result = runner.invoke(app, ["doctor", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0, result.stdout
    assert "Environment Readiness" in result.stdout
    assert "Status" in result.stdout
    assert "ready" in result.stdout.lower()


def test_plugins_doctor_renders_plugin_readiness_panel(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr("attackcastle.cli._external_dependency_rows", _missing_nmap_rows)
    monkeypatch.setattr(
        "attackcastle.cli.assess_readiness",
        lambda **kwargs: _readiness("partial", can_launch=True, partial_run=True, missing_tools=["nmap"]),
    )

    result = runner.invoke(app, ["plugins", "doctor"])

    assert result.exit_code == 3, result.stdout
    assert "Plugin Readiness" in result.stdout
    assert "Running Nmap" in result.stdout


def test_run_doctor_accepts_hashed_audit_logs(tmp_path: Path) -> None:
    runner = CliRunner()
    audit_path = tmp_path / "hashed_audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.write("event.one", {"value": 1})
    logger.write("event.two", {"value": 2})
    run_dir = _create_run_dir(tmp_path, audit_path.read_text(encoding="utf-8"))

    result = runner.invoke(app, ["run", "doctor", "--run-dir", str(run_dir), "--output-format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    audit_check = next(item for item in payload["checks"] if item["check"] == "audit_chain")
    assert json.loads(audit_check["detail"])["format"] == "hashed"


def test_run_doctor_accepts_legacy_unhashed_audit_logs(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = _create_run_dir(
        tmp_path,
        '{"timestamp":"2026-03-09T02:21:46.761533+00:00","event_type":"task.started","payload":{"task":"resolve-hosts"}}\n',
    )

    result = runner.invoke(app, ["run", "doctor", "--run-dir", str(run_dir), "--output-format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    audit_check = next(item for item in payload["checks"] if item["check"] == "audit_chain")
    assert json.loads(audit_check["detail"])["format"] == "legacy_unhashed"


def test_run_doctor_warns_on_tampered_hashed_audit_logs(tmp_path: Path) -> None:
    runner = CliRunner()
    audit_path = tmp_path / "tampered_audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.write("event.one", {"value": 1})
    logger.write("event.two", {"value": 2})
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"value": 2', '"value": 999')
    run_dir = _create_run_dir(tmp_path, "\n".join(lines) + "\n")

    result = runner.invoke(app, ["run", "doctor", "--run-dir", str(run_dir), "--output-format", "json"])

    assert result.exit_code == 3, result.stdout
    payload = json.loads(result.stdout)
    audit_check = next(item for item in payload["checks"] if item["check"] == "audit_chain")
    detail = json.loads(audit_check["detail"])
    assert detail["format"] == "hashed"
    assert "event hash mismatch" in " ".join(detail["errors"])
