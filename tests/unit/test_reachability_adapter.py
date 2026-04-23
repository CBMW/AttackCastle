from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from attackcastle.adapters.reachability.adapter import TargetReachabilityAdapter
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, now_utc
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def test_reachability_adapter_records_unreachable_without_failing_task(tmp_path: Path, monkeypatch) -> None:
    run_store = RunStore(output_root=tmp_path, run_id="reachability-test")
    context = AdapterContext(
        profile_name="standard",
        config={"target_reachability": {"ping_timeout_seconds": 1}},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
        task_instance_key="check-target-reachability::iter1::abc",
        task_inputs=["up.example.com", "down.example.com"],
    )
    run_data = RunData(
        metadata=RunMetadata(
            run_id="reachability-test",
            target_input="up.example.com\ndown.example.com",
            profile="standard",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )

    monkeypatch.setattr("attackcastle.adapters.reachability.adapter.shutil.which", lambda _name: "ping")

    def _fake_run(command, **_kwargs):  # noqa: ANN001
        target = command[-1]
        return SimpleNamespace(
            returncode=0 if target == "up.example.com" else 1,
            stdout=f"{target} output",
            stderr="",
        )

    monkeypatch.setattr("attackcastle.adapters.reachability.adapter.subprocess.run", _fake_run)

    result = TargetReachabilityAdapter().run(context, run_data)

    assert result.errors == []
    assert result.facts["target_reachability.checked_targets"] == ["up.example.com", "down.example.com"]
    assert result.facts["target_reachability.reachable_targets"] == ["up.example.com"]
    assert result.facts["target_reachability.unreachable_targets"] == ["down.example.com"]
    assert all(task.status == "completed" for task in result.task_results)
