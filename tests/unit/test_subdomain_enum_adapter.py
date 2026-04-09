from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from attackcastle.adapters.subdomain_enum.adapter import SubdomainEnumAdapter
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, ScanTarget, now_utc
from attackcastle.scope.domains import registrable_domain
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path: Path, config: dict | None = None) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="subdomain-enum-test")
    return AdapterContext(
        profile_name="full",
        config=config or {},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def _run_data(tmp_path: Path) -> RunData:
    return RunData(
        metadata=RunMetadata(
            run_id="subdomain-enum-test",
            target_input="https://store.cambridgeclothing.com.au\nwww.cambridgeclothing.co.nz",
            profile="full",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        ),
        scope=[
            ScanTarget(
                target_id="target_url_1",
                raw="https://store.cambridgeclothing.com.au",
                target_type=TargetType.URL,
                value="https://store.cambridgeclothing.com.au",
                host="store.cambridgeclothing.com.au",
                scheme="https",
            ),
            ScanTarget(
                target_id="target_domain_1",
                raw="www.cambridgeclothing.co.nz",
                target_type=TargetType.DOMAIN,
                value="www.cambridgeclothing.co.nz",
                host="www.cambridgeclothing.co.nz",
            ),
        ],
    )


def test_registrable_domain_handles_multi_label_public_suffixes() -> None:
    assert registrable_domain("store.cambridgeclothing.com.au") == "cambridgeclothing.com.au"
    assert registrable_domain("portal.cambridgeclothing.co.nz") == "cambridgeclothing.co.nz"
    assert registrable_domain("www.example.com") == "example.com"


def test_subdomain_enum_adapter_groups_targets_by_registrable_domain(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path, config={"subdomain_enum": {"timeout_seconds": 60}})
    run_data = _run_data(tmp_path)
    adapter = SubdomainEnumAdapter()
    commands: list[list[str]] = []

    def _fake_run_command_spec(_context, spec, proxy_url=None):  # noqa: ANN001
        commands.append(list(spec.command))
        stdout_path = tmp_path / f"{spec.artifact_prefix}_stdout.txt"
        stdout_path.write_text("", encoding="utf-8")
        root = spec.command[4]
        hosts = {
            "cambridgeclothing.com.au": "api.cambridgeclothing.com.au\nwww.cambridgeclothing.com.au\n",
            "cambridgeclothing.co.nz": "outlet.cambridgeclothing.co.nz\n",
        }[root]
        return SimpleNamespace(
            execution=SimpleNamespace(),
            evidence_artifacts=[],
            task_result=SimpleNamespace(
                task_id=f"task_{root}",
                status="completed",
                parsed_entities=[],
                metrics={},
                warnings=[],
                termination_reason="completed",
                termination_detail=None,
            ),
            stdout_text=hosts,
            stdout_path=stdout_path,
            execution_id=f"exec_{root}",
        )

    monkeypatch.setattr("attackcastle.adapters.subdomain_enum.adapter.run_command_spec", _fake_run_command_spec)

    result = adapter.run(context, run_data)

    enumerated_roots = [command[4] for command in commands]
    assert enumerated_roots == ["cambridgeclothing.co.nz", "cambridgeclothing.com.au"]
    assert result.facts["subdomain_enum.domain_count"] == 2
    assert result.facts["subdomain_enum.discovered_by_root"]["cambridgeclothing.com.au"] == [
        "api.cambridgeclothing.com.au",
        "www.cambridgeclothing.com.au",
    ]
    assert result.facts["subdomain_enum.execution_plan"] == [
        {
            "root_domain": "cambridgeclothing.co.nz",
            "source_targets": ["www.cambridgeclothing.co.nz"],
            "source_target_ids": ["target_domain_1"],
            "source_target_types": ["domain"],
        },
        {
            "root_domain": "cambridgeclothing.com.au",
            "source_targets": ["https://store.cambridgeclothing.com.au"],
            "source_target_ids": ["target_url_1"],
            "source_target_types": ["url"],
        },
    ]


def test_subdomain_enum_adapter_reports_errors_when_all_roots_fail(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path, config={"subdomain_enum": {"timeout_seconds": 60}})
    run_data = _run_data(tmp_path)

    def _fake_run_command_spec(_context, spec, proxy_url=None):  # noqa: ANN001
        stdout_path = tmp_path / f"{spec.artifact_prefix}_stdout.txt"
        stdout_path.write_text("", encoding="utf-8")
        return SimpleNamespace(
            execution=SimpleNamespace(),
            evidence_artifacts=[],
            task_result=SimpleNamespace(
                task_id=f"task_{spec.command[4]}",
                status="failed",
                parsed_entities=[],
                metrics={},
                warnings=[],
                termination_reason="timeout",
                termination_detail="command exceeded timeout of 60s",
            ),
            stdout_text="",
            stdout_path=stdout_path,
            execution_id=f"exec_{spec.command[4]}",
        )

    monkeypatch.setattr("attackcastle.adapters.subdomain_enum.adapter.run_command_spec", _fake_run_command_spec)

    result = SubdomainEnumAdapter().run(context, run_data)

    assert len(result.errors) == 1
    assert "subdomain enumeration failed" in result.errors[0]
    assert len(result.facts["subdomain_enum.failed_roots"]) == 2
