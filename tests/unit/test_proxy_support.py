from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from typer.testing import CliRunner

from attackcastle.adapters.framework_checks.adapter import FrameworkChecksAdapter
from attackcastle.adapters.nikto.adapter import NiktoAdapter
from attackcastle.adapters.nuclei.adapter import NucleiAdapter
from attackcastle.adapters.sqlmap.adapter import SQLMapAdapter
from attackcastle.adapters.web_discovery.adapter import WebDiscoveryAdapter
from attackcastle.adapters.web_probe.adapter import WebProbeAdapter
from attackcastle.adapters.whatweb.adapter import WhatWebAdapter
from attackcastle.adapters.wpscan.adapter import WPScanAdapter
from attackcastle.app import ScanOptions, ScanOutcome, build_scan_plan
from attackcastle.cli import app
from attackcastle.config_loader import load_config
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, now_utc
from attackcastle.proxy import build_subprocess_env, build_urllib_opener, command_text
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path: Path, config: dict | None = None) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="proxy-test")
    return AdapterContext(
        profile_name="prototype",
        config=config or {},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def _run_data_with_url(tmp_path: Path, url: str = "https://example.com") -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="proxy-test",
            target_input=url,
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        scope=[
            ScanTarget(
                target_id="target_1",
                raw=url,
                target_type=TargetType.URL,
                value=url,
                host="example.com",
            )
        ],
    )


def _outcome(tmp_path: Path) -> ScanOutcome:
    return ScanOutcome(
        run_id="proxy-run",
        run_dir=tmp_path,
        json_path=None,
        report_path=None,
        warning_count=0,
        error_count=0,
        finding_count=0,
        state="completed",
        duration_seconds=0.1,
    )


def test_load_config_reads_proxy_env_override(monkeypatch) -> None:
    monkeypatch.setenv("ATTACKCASTLE__PROXY__URL", "http://127.0.0.1:8080")

    config = load_config(profile="prototype")

    assert config["proxy"]["url"] == "http://127.0.0.1:8080"


def test_build_scan_plan_proxy_cli_override_beats_config(tmp_path: Path) -> None:
    config_path = tmp_path / "proxy-config.yaml"
    config_path.write_text("proxy:\n  url: http://127.0.0.1:8080\n", encoding="utf-8")
    options = ScanOptions(
        target_input="example.com",
        output_directory=str(tmp_path / "output"),
        profile="prototype",
        user_config_path=str(config_path),
        proxy_url="http://127.0.0.1:8081",
    )

    bundle, _run_store = build_scan_plan(
        options,
        console=Console(file=io.StringIO(), force_terminal=False, color_system=None),
    )

    assert bundle["config"]["proxy"]["url"] == "http://127.0.0.1:8081"


def test_build_scan_plan_no_proxy_disables_configured_proxy(tmp_path: Path) -> None:
    config_path = tmp_path / "proxy-config.yaml"
    config_path.write_text("proxy:\n  url: http://127.0.0.1:8080\n", encoding="utf-8")
    options = ScanOptions(
        target_input="example.com",
        output_directory=str(tmp_path / "output"),
        profile="prototype",
        user_config_path=str(config_path),
        disable_proxy=True,
    )

    bundle, _run_store = build_scan_plan(
        options,
        console=Console(file=io.StringIO(), force_terminal=False, color_system=None),
    )

    assert bundle["config"]["proxy"]["url"] == ""


def test_scan_cli_passes_proxy_options(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}

    monkeypatch.setattr("attackcastle.cli._external_dependency_rows", lambda: [])
    monkeypatch.setattr("attackcastle.cli._missing_dependency_message", lambda rows: "")

    def _fake_run_scan(**kwargs):
        captured.update(kwargs)
        return _outcome(tmp_path)

    monkeypatch.setattr("attackcastle.cli.run_scan", _fake_run_scan)

    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--proxy",
            "http://127.0.0.1:8080",
            "--no-proxy",
            "--output-format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert captured["proxy_url"] == "http://127.0.0.1:8080"
    assert captured["disable_proxy"] is True


def test_plan_cli_passes_proxy_options(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}

    def _fake_build_scan_plan(options, console):  # noqa: ANN001
        captured["proxy_url"] = options.proxy_url
        captured["disable_proxy"] = options.disable_proxy
        run_store = RunStore(output_root=tmp_path, run_id="plan-proxy")
        bundle = {
            "plan_payload": {
                "run_id": "plan-proxy",
                "profile": options.profile,
                "risk_mode": options.risk_mode or "safe-active",
                "max_noise_limit": 10,
                "conflicts": [],
                "safety": {},
                "scope_compiler": {"compiled_target_count": 1},
                "items": [
                    {
                        "key": "probe-web",
                        "label": "Probe Web",
                        "capability": "web_probe",
                        "selected": True,
                        "noise_score": 1,
                        "cost_score": 1,
                        "reason": "Selected for test",
                        "preview_commands": ["GET https://example.com"],
                    }
                ],
            },
            "config": {
                "profile": {"concurrency": 2},
                "orchestration": {
                    "capability_budgets": {},
                    "retry_ceiling_by_capability": {},
                    "max_total_retries": 1,
                },
            },
        }
        return bundle, run_store

    monkeypatch.setattr("attackcastle.cli.build_scan_plan", _fake_build_scan_plan)

    result = runner.invoke(
        app,
        [
            "plan",
            "--target",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--proxy",
            "http://127.0.0.1:8080",
            "--no-proxy",
            "--output-format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert captured["proxy_url"] == "http://127.0.0.1:8080"
    assert captured["disable_proxy"] is True


def test_guided_scan_passes_proxy(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    answers = iter(
        [
            "example.com",
            str(tmp_path),
            "prototype",
            "safe-active",
            "http://127.0.0.1:8080",
        ]
    )
    captured: dict[str, object] = {}

    monkeypatch.setattr("attackcastle.cli.Prompt.ask", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr("attackcastle.cli.Confirm.ask", lambda *args, **kwargs: True)

    def _fake_run_scan(**kwargs):
        captured.update(kwargs)
        return _outcome(tmp_path)

    monkeypatch.setattr("attackcastle.cli.run_scan", _fake_run_scan)

    result = runner.invoke(app, ["guided-scan"])

    assert result.exit_code == 0, result.stdout
    assert captured["proxy_url"] == "http://127.0.0.1:8080"


def test_proxy_helpers_redact_and_build_env() -> None:
    proxy_url = "http://alice:secret@127.0.0.1:8080"

    rendered = command_text(
        ["sqlmap", "--proxy=http://alice:secret@127.0.0.1:8080"],
        proxy_url,
    )
    env = build_subprocess_env(proxy_url, base_env={"NO_PROXY": "localhost"})
    opener = build_urllib_opener(proxy_url)

    assert "alice:secret" not in rendered
    assert "http://alice:secret@127.0.0.1:8080" not in rendered
    assert "[redacted-secret]" in rendered
    assert env["HTTP_PROXY"] == proxy_url
    assert env["HTTPS_PROXY"] == proxy_url
    assert env["NO_PROXY"] == ""
    assert any(type(handler).__name__ == "ProxyHandler" for handler in opener.handlers)


def test_http_tool_commands_include_proxy_arguments(tmp_path: Path) -> None:
    proxy_url = "http://alice:secret@127.0.0.1:8080"

    whatweb_command = WhatWebAdapter()._build_command(
        "whatweb",
        "https://example.com",
        tmp_path / "whatweb.json",
        {},
        {},
        proxy_url=proxy_url,
    )
    nikto_command = NiktoAdapter()._build_command(
        "nikto",
        "https://example.com",
        tmp_path / "nikto.json",
        {},
        {},
        proxy_url=proxy_url,
    )
    nuclei_command = NucleiAdapter()._build_command(
        "nuclei",
        "https://example.com",
        tmp_path / "nuclei.jsonl",
        {},
        {},
        {"allow_heavy_templates": True},
        proxy_url=proxy_url,
    )
    framework_command = FrameworkChecksAdapter()._build_command(
        "nuclei",
        "https://example.com",
        tmp_path / "framework.jsonl",
        ["wordpress"],
        {},
        {},
        {"allow_heavy_templates": True},
        proxy_url=proxy_url,
    )
    sqlmap_command = SQLMapAdapter()._build_command(
        "sqlmap",
        "https://example.com/item?id=1",
        tmp_path / "sqlmap",
        {},
        {},
        thread_override=2,
        proxy_url=proxy_url,
    )
    wpscan_command = WPScanAdapter()._build_command(
        "wpscan",
        "https://example.com",
        tmp_path / "wpscan.json",
        {},
        {},
        {"allow_heavy_templates": True, "allow_auth_bruteforce": False},
        proxy_url=proxy_url,
    )

    assert "--proxy" in whatweb_command
    assert "127.0.0.1:8080" in whatweb_command
    assert "--proxy-user" in whatweb_command
    assert "alice:secret" in whatweb_command
    assert "-useproxy" in nikto_command and proxy_url in nikto_command
    assert "-p" in nuclei_command and proxy_url in nuclei_command
    assert "-p" in framework_command and proxy_url in framework_command
    assert "--proxy=http://127.0.0.1:8080" in sqlmap_command
    assert "--proxy-cred" in sqlmap_command and "alice:secret" in sqlmap_command
    assert "--proxy" in wpscan_command and "http://127.0.0.1:8080" in wpscan_command
    assert "--proxy-auth" in wpscan_command and "alice:secret" in wpscan_command


def test_web_discovery_passes_proxy_to_fetch_document(tmp_path: Path, monkeypatch) -> None:
    proxy_calls: list[str | None] = []

    def _fake_fetch(self, url, timeout_seconds, user_agent, body_limit_bytes, proxy_url=None):  # noqa: ANN001
        proxy_calls.append(proxy_url)
        return {
            "status_code": 200,
            "headers": {},
            "body_text": "<html><title>Demo</title></html>",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(WebDiscoveryAdapter, "_fetch_document", _fake_fetch)

    context = _context(
        tmp_path,
        config={
            "scan": {"user_agent": "AttackCastle/Test"},
            "proxy": {"url": "http://127.0.0.1:8080"},
            "web_discovery": {
                "timeout_seconds": 1,
                "crawl_limit": 1,
                "careful_crawl_limit": 1,
                "same_host_only": True,
            },
        },
    )

    WebDiscoveryAdapter().run(context, _run_data_with_url(tmp_path))

    assert proxy_calls
    assert set(proxy_calls) == {"http://127.0.0.1:8080"}


def test_web_probe_screenshot_uses_proxy(tmp_path: Path, monkeypatch) -> None:
    screenshot_runs: list[dict[str, object]] = []

    def _fake_fetch_with_redirects(  # noqa: ANN001
        url,
        user_agent,
        timeout_seconds,
        body_capture_bytes,
        max_redirects=5,
        proxy_url=None,
    ):
        return {
            "status_code": 200,
            "headers": {"server": "demo"},
            "body_text": "<html><title>Demo</title><body>Hello</body></html>",
            "raw_body": b"<html><title>Demo</title><body>Hello</body></html>",
            "final_url": url,
            "redirect_chain": [],
            "error": None,
        }

    def _fake_subprocess_run(command, **kwargs):  # noqa: ANN001
        screenshot_runs.append({"command": list(command), "env": dict(kwargs.get("env") or {})})
        for item in command:
            if str(item).startswith("--screenshot="):
                Path(str(item).split("=", 1)[1]).write_text("png", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("attackcastle.adapters.web_probe.adapter._fetch_with_redirects", _fake_fetch_with_redirects)
    monkeypatch.setattr(
        "attackcastle.adapters.web_probe.adapter.shutil.which",
        lambda name: "chromium" if name in {"chromium", "google-chrome", "chrome"} else None,
    )
    monkeypatch.setattr("attackcastle.adapters.web_probe.adapter.subprocess.run", _fake_subprocess_run)

    context = _context(
        tmp_path,
        config={
            "scan": {
                "http_timeout_seconds": 1,
                "user_agent": "AttackCastle/Test",
            },
            "proxy": {"url": "http://127.0.0.1:8080"},
            "web_probe": {
                "capture_screenshots": True,
                "capture_important_only": False,
                "screenshot_timeout_seconds": 1,
                "response_capture_bytes": 2048,
                "max_redirects": 1,
            },
        },
    )

    WebProbeAdapter().run(context, _run_data_with_url(tmp_path))

    assert screenshot_runs
    screenshot_command = screenshot_runs[0]["command"]
    screenshot_env = screenshot_runs[0]["env"]
    assert "--proxy-server=http://127.0.0.1:8080" in screenshot_command
    assert screenshot_env["HTTP_PROXY"] == "http://127.0.0.1:8080"
