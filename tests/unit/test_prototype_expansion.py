from __future__ import annotations

from pathlib import Path

from attackcastle.adapters.nmap.adapter import NmapAdapter
from attackcastle.adapters.nuclei.parser import parse_nuclei_jsonl
from attackcastle.core.enums import TargetType
from attackcastle.core.errors import ValidationError
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, WebApplication, now_utc
from attackcastle.normalization.correlator import collect_sqlmap_targets
from attackcastle.scope.validators import validate_targets


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="prototype-test",
            target_input="example.com",
            profile="prototype",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_nmap_collect_scope_targets_normalizes_url_and_host_port():
    run_data = _run_data()
    run_data.scope.extend(
        [
            ScanTarget(
                target_id="target-url",
                raw="https://app.example.com/login",
                target_type=TargetType.URL,
                value="https://app.example.com/login",
                host="app.example.com",
            ),
            ScanTarget(
                target_id="target-host-port",
                raw="api.example.com:8443",
                target_type=TargetType.HOST_PORT,
                value="api.example.com:8443",
                host="api.example.com",
                port=8443,
            ),
        ]
    )
    targets = NmapAdapter()._collect_scope_targets(run_data)
    assert "app.example.com" in targets
    assert "api.example.com" in targets
    assert "https://app.example.com/login" not in targets
    assert "api.example.com:8443" not in targets


def test_collect_sqlmap_targets_uses_forms_and_query_signals():
    run_data = _run_data()
    run_data.web_apps.extend(
        [
            WebApplication(
                webapp_id="web-1",
                asset_id="asset-1",
                url="https://example.com/search?q=test",
                forms_count=0,
            ),
            WebApplication(
                webapp_id="web-2",
                asset_id="asset-2",
                url="https://example.com/login",
                forms_count=1,
            ),
        ]
    )
    targets = collect_sqlmap_targets(run_data)
    urls = {item["url"] for item in targets}
    assert "https://example.com/search?q=test" in urls
    assert "https://example.com/login" in urls


def test_validate_targets_blocks_private_scope_when_disabled():
    targets = [
        ScanTarget(
            target_id="target-private-ip",
            raw="10.10.10.10",
            target_type=TargetType.SINGLE_IP,
            value="10.10.10.10",
            host="10.10.10.10",
        )
    ]
    try:
        validate_targets(targets, allow_private_scope=False)
    except ValidationError as exc:
        assert "non-public scope" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for private target scope")


def test_parse_nuclei_jsonl_returns_normalized_findings(tmp_path: Path):
    sample = tmp_path / "nuclei.jsonl"
    sample.write_text(
        '{"template-id":"cve-2024-0001","matched-at":"https://example.com","info":{"name":"Test Finding","severity":"high"}}\n',
        encoding="utf-8",
    )
    rows = parse_nuclei_jsonl(sample)
    assert len(rows) == 1
    assert rows[0]["template_id"] == "cve-2024-0001"
    assert rows[0]["severity"] == "high"
