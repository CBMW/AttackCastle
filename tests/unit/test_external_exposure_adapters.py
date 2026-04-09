from pathlib import Path

from attackcastle.adapters.dns.adapter import DNSAdapter
from attackcastle.adapters.service_exposure import adapter as service_adapter
from attackcastle.adapters.surface_intel.adapter import SurfaceIntelAdapter
from attackcastle.adapters.tls import adapter as tls_adapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import Asset, Evidence, RunData, RunMetadata, ScanTarget, Service, WebApplication, new_id, now_utc
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path, config=None):
    run_store = RunStore(output_root=Path(tmp_path), run_id="test")
    return AdapterContext(
        profile_name="external_pentest",
        config=config or {},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def _run_data(tmp_path) -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="external_pentest",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )


def test_dns_adapter_emits_takeover_and_mail_policy_gap(tmp_path, monkeypatch):
    run_data = _run_data(tmp_path)
    run_data.scope.append(
        ScanTarget(
            target_id="target_1",
            raw="app.example.com",
            target_type=TargetType.DOMAIN,
            value="app.example.com",
            host="app.example.com",
        )
    )
    context = _context(
        tmp_path,
        config={"scan": {"dns_timeout_seconds": 1}, "dns": {"common_dkim_selectors": ["default"]}},
    )

    monkeypatch.setattr("attackcastle.adapters.dns.adapter.resolve_host", lambda host: [])
    monkeypatch.setattr("attackcastle.adapters.dns.adapter.resolve_mx", lambda host, timeout_seconds=0: ["10 mx1.example.com"])
    monkeypatch.setattr("attackcastle.adapters.dns.adapter.resolve_txt", lambda host, timeout_seconds=0: [])
    monkeypatch.setattr("attackcastle.adapters.dns.adapter.resolve_ns", lambda host, timeout_seconds=0: ["ns1.example.net"])
    monkeypatch.setattr(
        "attackcastle.adapters.dns.adapter.resolve_cname",
        lambda host, timeout_seconds=0: ["abandoned.github.io"] if host == "app.example.com" else [],
    )

    result = DNSAdapter().run(context, run_data)
    keys = {obs.key for obs in result.observations}
    assert "dns.takeover.candidate" in keys
    assert "mail.transport_policy.gap" in keys


def test_service_exposure_adapter_emits_mail_validation_observations(tmp_path, monkeypatch):
    run_data = _run_data(tmp_path)
    run_data.assets.append(Asset(asset_id="asset_1", kind="host", name="mail.example.com"))
    run_data.services.append(
        Service(
            service_id="service_1",
            asset_id="asset_1",
            port=25,
            protocol="tcp",
            state="open",
            name="smtp",
        )
    )
    context = _context(
        tmp_path,
        config={"service_exposure": {"enable_open_relay_probe": True, "timeout_seconds": 1}},
    )

    monkeypatch.setattr(service_adapter, "_tcp_connect", lambda host, port, timeout_seconds: (True, ""))
    monkeypatch.setattr(
        service_adapter,
        "_probe_smtp",
        lambda host, port, timeout_seconds, validate_open_relay: {
            "banner": "220 smtp.example.com ESMTP Postfix 3.5",
            "starttls": True,
            "relay_possible": True,
            "validated": True,
        },
    )

    result = service_adapter.ServiceExposureAdapter().run(context, run_data)
    keys = {obs.key for obs in result.observations}
    assert "mail.starttls.supported" in keys
    assert "mail.open_relay.possible" in keys
    assert "smtp.open_relay.confirmed" in keys
    assert "service.version.disclosed" in keys
    assert any(item.validator_key == "smtp_open_relay" and item.status == "confirmed" for item in result.validation_results)
    assert any(item.playbook_key == "smtp_exposure" for item in result.proof_outcomes)


def test_tls_adapter_emits_deep_tls_observations(tmp_path, monkeypatch):
    run_data = _run_data(tmp_path)
    run_data.assets.append(Asset(asset_id="asset_1", kind="host", name="app.example.com"))
    run_data.services.append(
        Service(
            service_id="service_1",
            asset_id="asset_1",
            port=443,
            protocol="tcp",
            state="open",
            name="https",
        )
    )
    context = _context(
        tmp_path,
        config={"scan": {"tls_timeout_seconds": 1, "user_agent": "AttackCastle/Test"}},
    )

    handshake = {
        "protocol": "TLSv1.2",
        "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "alpn": "http/1.1",
        "ocsp_stapled": False,
        "fingerprint_sha256": "abc123",
        "cert": {
            "subject": ((("commonName", "wrong.example.com"),),),
            "issuer": ((("commonName", "wrong.example.com"),),),
            "notAfter": "Jun 30 12:00:00 2030 GMT",
            "subjectAltName": [("DNS", "wrong.example.com")],
        },
    }
    monkeypatch.setattr(tls_adapter, "_handshake", lambda host, port, timeout_seconds, use_sni: handshake)
    monkeypatch.setattr(tls_adapter, "_https_headers", lambda host, port, timeout_seconds, user_agent: {})

    result = tls_adapter.TLSAdapter().run(context, run_data)
    keys = {obs.key for obs in result.observations}
    assert "tls.weak_cipher" in keys
    assert "tls.san.mismatch" in keys
    assert "tls.self_signed" in keys
    validator_keys = {item.validator_key for item in result.validation_results}
    assert {"tls_weak_cipher", "tls_san_mismatch", "tls_self_signed"} <= validator_keys


def test_service_exposure_adapter_confirms_ftp_anonymous_access(tmp_path, monkeypatch):
    run_data = _run_data(tmp_path)
    run_data.assets.append(Asset(asset_id="asset_1", kind="host", name="files.example.com"))
    run_data.services.append(
        Service(
            service_id="service_ftp",
            asset_id="asset_1",
            port=21,
            protocol="tcp",
            state="open",
            name="ftp",
        )
    )
    context = _context(tmp_path, config={"service_exposure": {"timeout_seconds": 1}})

    monkeypatch.setattr(service_adapter, "_tcp_connect", lambda host, port, timeout_seconds: (True, ""))
    monkeypatch.setattr(
        service_adapter,
        "_probe_ftp",
        lambda host, port, timeout_seconds: {
            "banner": "220 FTP Server 2.0",
            "auth_tls": True,
            "anonymous_login": True,
            "validated": True,
            "user_response": "331 Guest login ok",
            "pass_response": "230 Login successful",
        },
    )

    result = service_adapter.ServiceExposureAdapter().run(context, run_data)

    assert any(obs.key == "ftp.anonymous.enabled" for obs in result.observations)
    assert any(item.validator_key == "ftp_anonymous_access" and item.status == "confirmed" for item in result.validation_results)
    assert any(item.playbook_key == "ftp_exposure" for item in result.proof_outcomes)


def test_surface_intel_adapter_extracts_admin_and_api_signals(tmp_path):
    run_data = _run_data(tmp_path)
    webapp_id = "web_1"
    run_data.web_apps.append(
        WebApplication(
            webapp_id=webapp_id,
            asset_id="asset_1",
            url="https://ci.example.com/swagger.json",
            title="Jenkins Dashboard",
        )
    )
    run_data.evidence.append(
        Evidence(
            evidence_id=new_id("evidence"),
            source_tool="test",
            kind="http_response",
            snippet="https://ci.example.com/swagger.json refs https://github.com/acme/platform",
        )
    )

    context = _context(tmp_path)
    result = SurfaceIntelAdapter().run(context, run_data)
    keys = {obs.key for obs in result.observations}
    assert "web.admin_interface" in keys
    assert "web.api.docs.exposed" in keys
    assert "thirdparty.github.reference" in keys
