from pathlib import Path

from attackcastle.adapters import DNSAdapter, NmapAdapter, TLSAdapter, WebProbeAdapter
from attackcastle.core.interfaces import AdapterContext
from attackcastle.core.models import RunData, RunMetadata, now_utc
from attackcastle.orchestration.planner import build_task_plan
from attackcastle.storage.run_store import RunStore


def _noop(context, run_data):  # noqa: ANN001
    return None


def test_build_task_plan_includes_deferred_tasks(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="example.com",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    run_store = RunStore(output_root=Path(tmp_path), run_id="plan")
    context = AdapterContext(
        profile_name="cautious",
        config={"profile": {"max_noise_score": 10}},
        profile_config={"concurrency": 2},
        run_store=run_store,
        logger=None,
        audit=None,
    )
    adapters = {
        "dns": DNSAdapter(),
        "nmap": NmapAdapter(),
        "web_probe": WebProbeAdapter(),
        "tls": TLSAdapter(),
    }
    result = build_task_plan(
        adapters=adapters,
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="cautious",
        config={"profile": {"max_noise_score": 10}},
        preview_context=context,
    )
    keys = {task.key for task in result.tasks}
    assert "probe-web" in keys
    assert "detect-tls" in keys


def test_build_task_plan_enforces_noise_limit(tmp_path):
    run_data = RunData(
        metadata=RunMetadata(
            run_id="test",
            target_input="10.0.0.0/24",
            profile="cautious",
            output_dir=str(tmp_path),
            started_at=now_utc(),
        )
    )
    result = build_task_plan(
        adapters={"nmap": NmapAdapter()},
        findings_runner=_noop,
        report_runner=_noop,
        run_data=run_data,
        profile_name="cautious",
        config={"profile": {"max_noise_score": 2}},
    )
    keys = {task.key for task in result.tasks}
    assert "run-nmap" not in keys
    assert result.conflicts

