from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

from attackcastle.adapters.http_security_headers.adapter import (
    HTTPSecurityHeadersAdapter,
    build_linux_fallback_command,
    build_linux_head_command,
    build_windows_fallback_command,
    build_windows_head_command,
)
from attackcastle.adapters.http_security_headers.parser import (
    build_header_analysis,
    parse_raw_response_headers,
)
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, TaskResult, ToolExecution, WebApplication, now_utc
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, _event: str, _payload: dict[str, object]) -> None:
        return


def _context(tmp_path: Path, run_id: str) -> AdapterContext:
    return AdapterContext(
        profile_name="prototype",
        config={
            "scan": {"http_timeout_seconds": 5},
            "http_security_headers": {"enabled": True, "timeout_seconds": 5},
        },
        profile_config={},
        run_store=RunStore(output_root=tmp_path, run_id=run_id),
        logger=logging.getLogger(run_id),
        audit=_Audit(),
    )


def _run_data(tmp_path: Path, url: str = "https://example.com") -> RunData:
    run_data = RunData(
        metadata=RunMetadata(
            run_id="http-headers",
            target_input=url,
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    run_data.web_apps.append(
        WebApplication(
            webapp_id="web-1",
            asset_id="asset-1",
            service_id="svc-1",
            url=url,
            status_code=200,
            title="Example",
        )
    )
    return run_data


def test_linux_http_security_header_commands_match_expected_patterns() -> None:
    assert build_linux_head_command("https://example.com") == [
        "curl",
        "-skI",
        "--max-redirs",
        "0",
        "https://example.com",
    ]
    assert build_linux_fallback_command("https://example.com") == [
        "curl",
        "-skD",
        "-",
        "-o",
        "/dev/null",
        "--max-redirs",
        "0",
        "https://example.com",
    ]


def test_windows_http_security_header_commands_use_invoke_web_request_head_and_get() -> None:
    head_command = build_windows_head_command("https://example.com", shell_path="powershell")
    get_command = build_windows_fallback_command("https://example.com", shell_path="powershell")

    assert head_command[:3] == ["powershell", "-NoProfile", "-NonInteractive"]
    assert "Invoke-WebRequest -Uri 'https://example.com' -Method Head -MaximumRedirection 0" in head_command[-1]
    assert "Invoke-WebRequest -Uri 'https://example.com' -Method Get -MaximumRedirection 0" in get_command[-1]


def test_parse_raw_response_headers_prefers_last_non_informational_block() -> None:
    parsed = parse_raw_response_headers(
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: https://example.com/\r\n"
        "Server: nginx\r\n\r\n"
    )

    assert parsed.status_code == 301
    assert parsed.headers["location"] == "https://example.com/"
    assert parsed.headers["server"] == "nginx"


def test_build_header_analysis_flags_missing_weak_and_exposed_headers() -> None:
    analysis = build_header_analysis(
        url="https://example.com",
        status_code=200,
        headers={
            "strict-transport-security": "max-age=300",
            "content-security-policy": "default-src * 'unsafe-inline'",
            "x-frame-options": "ALLOW-FROM https://example.com",
            "x-content-type-options": "nosniff",
            "referrer-policy": "origin",
            "server": "nginx/1.24.0",
            "x-powered-by": "PHP/8.2",
        },
        raw_headers="HTTP/1.1 200 OK",
    )

    by_header = {row["header"]: row for row in analysis["headers"]}
    assert by_header["Strict-Transport-Security"]["status"] == "Weak"
    assert by_header["Content-Security-Policy"]["status"] == "Weak"
    assert by_header["X-Frame-Options"]["status"] == "Weak"
    assert by_header["X-Content-Type-Options"]["status"] == "Present"
    assert by_header["Referrer-Policy"]["status"] == "Weak"
    assert by_header["Permissions-Policy"]["status"] == "Missing"
    assert by_header["Server"]["status"] == "Exposed"
    assert by_header["X-Powered-By"]["status"] == "Exposed"
    assert analysis["trigger_finding"] is True


def test_http_security_headers_collects_candidate_scope_targets(tmp_path: Path) -> None:
    context = _context(tmp_path, "http-header-candidates")
    run_data = RunData(
        metadata=RunMetadata(
            run_id="http-header-candidates",
            target_input="example.com,203.0.113.10",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        scope=[
            ScanTarget(
                target_id="target-domain",
                raw="example.com",
                target_type=TargetType.DOMAIN,
                value="example.com",
                host="example.com",
            ),
            ScanTarget(
                target_id="target-ip",
                raw="203.0.113.10",
                target_type=TargetType.SINGLE_IP,
                value="203.0.113.10",
                host="203.0.113.10",
            ),
        ],
    )

    urls = {item["url"] for item in HTTPSecurityHeadersAdapter()._collect_targets(context, run_data)}

    assert "https://example.com/" in urls
    assert "http://example.com/" in urls
    assert "https://203.0.113.10/" in urls
    assert "http://203.0.113.10/" in urls


def test_http_security_headers_adapter_records_results_and_observations(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path, "http-header-adapter")
    run_data = _run_data(tmp_path)

    def _fake_run_command_spec(context, spec, proxy_url=None):  # noqa: ANN001
        if "_head" in spec.artifact_prefix:
            stdout_text = json.dumps(
                {
                    "method": "Head",
                    "status_code": 200,
                    "headers": [
                        {"name": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains"},
                        {"name": "Content-Security-Policy", "value": "default-src 'self'"},
                        {"name": "X-Frame-Options", "value": "SAMEORIGIN"},
                        {"name": "X-Content-Type-Options", "value": "nosniff"},
                        {"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
                    ],
                    "raw_headers": "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains",
                }
            )
        else:
            raise AssertionError("Fallback should not run for a usable HEAD response")
        return SimpleNamespace(
            execution=ToolExecution(
                execution_id="exec-head",
                tool_name="http_security_headers",
                command="head-command",
                started_at=now_utc(),
                ended_at=now_utc(),
                exit_code=0,
                status="completed",
            ),
            task_result=TaskResult(
                task_id="task-head",
                task_type="CheckHttpSecurityHeaders",
                status="completed",
                command="head-command",
                exit_code=0,
                started_at=now_utc(),
                finished_at=now_utc(),
            ),
            evidence_artifacts=[],
            stdout_text=stdout_text,
            stderr_text="",
            exit_code=0,
            error_message=None,
            command_text="head-command",
            stdout_path=context.run_store.artifact_path("http_security_headers", "stdout.txt"),
            stderr_path=context.run_store.artifact_path("http_security_headers", "stderr.txt"),
            transcript_path=context.run_store.artifact_path("http_security_headers", "transcript.txt"),
            execution_id="exec-head",
        )

    monkeypatch.setattr("attackcastle.adapters.http_security_headers.adapter.run_command_spec", _fake_run_command_spec)

    result = HTTPSecurityHeadersAdapter().run(context, run_data)

    assert result.facts["http_security_headers.scanned_targets"] == 1
    assert result.facts["http_security_headers.affected_urls"] == []
    assert result.evidence
    assert result.observations
    assert result.observations[0].key == "web.http_security_headers.analysis"
