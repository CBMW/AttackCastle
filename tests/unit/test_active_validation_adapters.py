from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from attackcastle.adapters.active_validation import adapter as active_validation_module
from attackcastle.adapters.active_validation.adapter import ActiveValidationAdapter
from attackcastle.adapters.request_capture.adapter import RequestCaptureAdapter
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import Observation, ReplayRequest, RunData, RunMetadata, WebApplication, now_utc
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path: Path, config: dict | None = None) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="active-validation-test")
    return AdapterContext(
        profile_name="prototype",
        config=config or {},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def test_request_capture_builds_surface_inventory(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        config={
            "scan": {"user_agent": "AttackCastle/Test"},
            "active_validation": {"request_replay_enabled": True},
            "request_capture": {"max_saved_requests_per_webapp": 10, "max_total_requests": 20},
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="capture",
            target_input="https://example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        web_apps=[
            WebApplication(
                webapp_id="web-1",
                asset_id="asset-1",
                service_id="svc-1",
                url="https://example.com",
            )
        ],
        observations=[
            Observation(
                observation_id="obs-urls",
                key="web.discovery.urls",
                value=["https://example.com/login?id=7", "https://example.com/admin"],
                entity_type="web_app",
                entity_id="web-1",
                source_tool="web_discovery",
            ),
            Observation(
                observation_id="obs-params",
                key="web.input.parameters",
                value=["username", "password"],
                entity_type="web_app",
                entity_id="web-1",
                source_tool="web_probe",
            ),
            Observation(
                observation_id="obs-login",
                key="web.login_portal",
                value=["password-form"],
                entity_type="web_app",
                entity_id="web-1",
                source_tool="web_probe",
            ),
            Observation(
                observation_id="obs-forms",
                key="web.forms.detected",
                value=True,
                entity_type="web_app",
                entity_id="web-1",
                source_tool="web_probe",
            ),
        ],
    )

    result = RequestCaptureAdapter().run(context, run_data)

    assert len(result.endpoints) == 3
    assert len(result.replay_requests) == 3
    assert any(item.tags for item in result.replay_requests)
    assert {item.name for item in result.parameters} >= {"id", "username", "password"}
    assert len(result.forms) >= 1
    assert len(result.login_surfaces) >= 1
    assert result.facts["request_capture.count"] == 3
    assert Path(result.evidence[0].artifact_path).exists()


def test_active_validation_confirms_safe_active_findings(tmp_path: Path, monkeypatch) -> None:
    context = _context(
        tmp_path,
        config={
            "scan": {"user_agent": "AttackCastle/Test"},
            "active_validation": {
                "mode": "safe-active",
                "request_replay_enabled": True,
                "per_target_budget": 5,
                "timeout_seconds": 1,
            },
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="safe-active",
            target_input="https://example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        web_apps=[WebApplication(webapp_id="web-1", asset_id="asset-1", service_id="svc-1", url="https://example.com")],
        replay_requests=[
            ReplayRequest(
                replay_request_id="replay-1",
                webapp_id="web-1",
                asset_id="asset-1",
                service_id="svc-1",
                url="https://example.com/admin/docs?id=7",
                parameter_names=["id"],
                tags=["admin", "docs", "api"],
            )
        ],
    )

    def _fake_fetch(url: str, **kwargs):  # noqa: ANN001
        method = kwargs.get("method", "GET")
        if method == "OPTIONS":
            return {
                "status_code": 200,
                "headers": {"allow": "GET, POST, DELETE"},
                "body_text": "",
                "final_url": url,
                "error": None,
            }
        query = parse_qs(urlsplit(url).query)
        if query.get("id") == ["8"]:
            return {
                "status_code": 200,
                "headers": {},
                "body_text": "neighbor object",
                "final_url": url,
                "error": None,
            }
        return {
            "status_code": 200,
            "headers": {"access-control-allow-origin": "*"},
            "body_text": "baseline response",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(active_validation_module, "_fetch_exchange", _fake_fetch)

    result = ActiveValidationAdapter().run(context, run_data)

    observation_keys = {item.key for item in result.observations}
    validator_keys = {item.validator_key for item in result.validation_results}

    assert "web.api.docs.exposed" in observation_keys
    assert "web.admin_interface" in observation_keys
    assert "web.missing_security_headers" in observation_keys
    assert "web.cors.misconfigured" in observation_keys
    assert "web.http_methods.permissive" in observation_keys
    assert "web.idor.candidate" in observation_keys
    assert {"api_docs", "admin_surface", "missing_headers", "cors", "methods", "idor_candidate"} <= validator_keys
    assert result.facts["active_validation.mode"] == "safe-active"
    assert result.facts["active_validation.validation_counts"]["confirmed"] >= 5
    assert result.facts["active_validation.validation_counts"]["candidate"] >= 1
    assert any(item.playbook_key for item in result.validation_results)
    assert any(item.attack_path_id for item in result.validation_results if item.validator_key == "idor_candidate")
    assert result.evidence


def test_active_validation_confirms_aggressive_injection_signals(tmp_path: Path, monkeypatch) -> None:
    context = _context(
        tmp_path,
        config={
            "scan": {"user_agent": "AttackCastle/Test"},
            "active_validation": {
                "mode": "aggressive",
                "request_replay_enabled": True,
                "per_target_budget": 5,
                "timeout_seconds": 1,
            },
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="aggressive",
            target_input="https://example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        web_apps=[WebApplication(webapp_id="web-1", asset_id="asset-1", service_id="svc-1", url="https://example.com")],
        replay_requests=[
            ReplayRequest(
                replay_request_id="replay-1",
                webapp_id="web-1",
                asset_id="asset-1",
                service_id="svc-1",
                url="https://example.com/search?q=test",
                parameter_names=["q"],
                tags=["parameterized"],
            )
        ],
    )

    def _fake_fetch(url: str, **kwargs):  # noqa: ANN001
        method = kwargs.get("method", "GET")
        if method == "OPTIONS":
            return {"status_code": 200, "headers": {"allow": "GET, POST"}, "body_text": "", "final_url": url, "error": None}
        query = parse_qs(urlsplit(url).query)
        q_value = (query.get("q") or [""])[0]
        if "attackcastle_xss_" in q_value:
            return {
                "status_code": 200,
                "headers": {"content-security-policy": "default-src 'self'"},
                "body_text": f"echo:{q_value}",
                "final_url": url,
                "error": None,
            }
        if q_value == "'":
            return {
                "status_code": 500,
                "headers": {"content-security-policy": "default-src 'self'"},
                "body_text": "SQL syntax error near '''",
                "final_url": url,
                "error": None,
            }
        return {
            "status_code": 200,
            "headers": {"content-security-policy": "default-src 'self'"},
            "body_text": "baseline",
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(active_validation_module, "_fetch_exchange", _fake_fetch)

    result = ActiveValidationAdapter().run(context, run_data)

    observation_keys = {item.key for item in result.observations}
    validator_keys = {item.validator_key for item in result.validation_results}

    assert "web.xss.reflected" in observation_keys
    assert "web.sqli.error_based" in observation_keys
    assert {"reflected_xss", "sqli_error"} <= validator_keys
    assert result.facts["active_validation.mode"] == "aggressive"
    assert any(item.playbook_key == "input_reflection_injection" for item in result.validation_results)
    assert result.proof_outcomes
