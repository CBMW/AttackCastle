from __future__ import annotations

import logging
from pathlib import Path

from attackcastle.adapters.cve_enricher.adapter import CVEEnricherAdapter
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, Service, Technology, now_utc
from attackcastle.storage.run_store import RunStore


class _AuditStub:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def write(self, event_type: str, payload: dict[str, object]) -> None:
        self.events.append((event_type, payload))


def _context(tmp_path: Path, audit: _AuditStub) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="cve-enricher-test")
    return AdapterContext(
        profile_name="standard",
        config={},
        profile_config={},
        run_store=run_store,
        logger=logging.getLogger("test-cve-enricher"),
        audit=audit,
    )


def _run_data() -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="cve-enricher-run",
            target_input="example.com",
            profile="standard",
            output_dir=".",
            started_at=now_utc(),
        )
    )


def test_cve_enricher_generates_candidates_and_artifact(tmp_path: Path):
    run_data = _run_data()
    run_data.services.append(
        Service(
            service_id="svc-1",
            asset_id="asset-1",
            port=80,
            protocol="tcp",
            state="open",
            name="Apache httpd",
        )
    )
    run_data.technologies.append(
        Technology(
            tech_id="tech-1",
            asset_id="asset-1",
            name="WordPress",
            version="6.5",
        )
    )
    audit = _AuditStub()
    adapter = CVEEnricherAdapter()
    result = adapter.run(_context(tmp_path, audit), run_data)

    assert result.facts["cve_enricher.candidate_count"] >= 2
    assert result.facts["cve_enricher.asset_count"] == 1
    assert result.evidence
    artifact_path = Path(result.evidence[0].artifact_path or "")
    assert artifact_path.exists()
    observation_keys = {item.key for item in result.observations}
    assert "vuln.cpe.candidate" in observation_keys
    assert "vuln.cve.candidates" in observation_keys
    assert result.tool_executions
    assert result.tool_executions[0].tool_name == "cve_enricher"
    assert any(event[0] == "adapter.completed" for event in audit.events)


def test_cve_enricher_handles_empty_inputs(tmp_path: Path):
    run_data = _run_data()
    audit = _AuditStub()
    adapter = CVEEnricherAdapter()
    result = adapter.run(_context(tmp_path, audit), run_data)

    assert result.facts["cve_enricher.candidate_count"] == 0
    assert result.evidence == []
    assert len(result.tool_executions) == 1
    assert result.tool_executions[0].status == "completed"

