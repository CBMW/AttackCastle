from __future__ import annotations

from pathlib import Path

from attackcastle.adapters.web_discovery.adapter import WebDiscoveryAdapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, Service, WebApplication, now_utc
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path: Path, config: dict | None = None) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="web-discovery-test")
    return AdapterContext(
        profile_name="prototype",
        config=config or {},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def test_web_discovery_uses_wordlists_for_seeded_candidates(tmp_path, monkeypatch) -> None:
    endpoint_wordlist = tmp_path / "endpoints.txt"
    parameter_wordlist = tmp_path / "params.txt"
    payload_wordlist = tmp_path / "payloads.txt"
    endpoint_wordlist.write_text("admin\napi/search\n", encoding="utf-8")
    parameter_wordlist.write_text("id\nq\n", encoding="utf-8")
    payload_wordlist.write_text("test-payload\n", encoding="utf-8")

    context = _context(
        tmp_path,
        config={
            "scan": {"user_agent": "AttackCastle/Test"},
            "web_discovery": {
                "timeout_seconds": 1,
                "crawl_limit": 12,
                "careful_crawl_limit": 6,
                "same_host_only": True,
                "endpoint_wordlist_path": str(endpoint_wordlist),
                "parameter_wordlist_path": str(parameter_wordlist),
                "payload_wordlist_path": str(payload_wordlist),
                "synthesized_url_limit": 20,
            },
        },
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="web-discovery-test",
            target_input="https://example.com",
            profile="prototype",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        scope=[
            ScanTarget(
                target_id="target_1",
                raw="https://example.com",
                target_type=TargetType.URL,
                value="https://example.com",
                host="example.com",
            )
        ],
        services=[
            Service(
                service_id="svc-1",
                asset_id="target_1",
                port=443,
                protocol="tcp",
                state="open",
                name="https",
            )
        ],
        web_apps=[
            WebApplication(
                webapp_id="web-1",
                asset_id="target_1",
                service_id="svc-1",
                url="https://example.com",
                status_code=200,
                title="Example",
            )
        ],
    )

    def _fake_fetch(self, url, timeout_seconds, user_agent, body_limit_bytes):  # noqa: ANN001
        return {
            "status_code": 200,
            "headers": {},
            "body_text": '<a href="/login">Login</a><a href="/search">Search</a>',
            "final_url": url,
            "error": None,
        }

    monkeypatch.setattr(WebDiscoveryAdapter, "_fetch_document", _fake_fetch)

    result = WebDiscoveryAdapter().run(context, run_data)
    candidates = {str(item["url"]) for item in result.facts["web_discovery.url_candidates"]}

    assert "https://example.com/admin" in candidates
    assert "https://example.com/api/search" in candidates
    assert any("id=test-payload" in item for item in candidates)
    assert any("q=test-payload" in item for item in candidates)
    assert result.facts["web_discovery.wordlist_endpoint_count"] == 2
    assert result.facts["web_discovery.wordlist_parameter_count"] == 2
    assert result.facts["web_discovery.wordlist_payload_count"] == 1
