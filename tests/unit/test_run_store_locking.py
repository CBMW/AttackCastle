from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from attackcastle.storage.run_store import RunStore


def test_unlock_if_stale_requires_age_or_dead_process(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="locktest")
    run_store.acquire_lock()
    unlocked, reason, _details = run_store.unlock_if_stale(max_age_minutes=10_000)
    assert unlocked is False
    assert reason == "lock_not_stale"
    run_store.release_lock()


def test_unlock_if_stale_removes_old_lock(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="locktest2")
    run_store.acquire_lock()
    old_time = datetime.now(timezone.utc) - timedelta(minutes=90)
    timestamp = old_time.timestamp()
    run_store.lock_path.touch()
    # Force lock age to exceed threshold.
    import os

    os.utime(run_store.lock_path, (timestamp, timestamp))
    unlocked, reason, details = run_store.unlock_if_stale(max_age_minutes=30)
    assert unlocked is True
    assert reason == "unlocked"
    assert details.get("removed") is True
    assert not run_store.lock_exists()


def test_load_latest_checkpoint_skips_missing_and_invalid_entries(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-fallback")
    valid_path = run_store.checkpoints_dir / "task-valid.json"
    invalid_json_path = run_store.checkpoints_dir / "task-invalid.json"
    valid_path.write_text('{"task_key":"task-valid","run_data":{}}', encoding="utf-8")
    invalid_json_path.write_text("{not-json", encoding="utf-8")
    (run_store.checkpoints_dir / "manifest.json").write_text(
        json.dumps(
            {
                "checkpoints": [
                    {"task_key": "task-valid", "status": "completed", "path": str(valid_path)},
                    {
                        "task_key": "task-missing",
                        "status": "completed",
                        "path": str(run_store.checkpoints_dir / "missing.json"),
                    },
                    {"task_key": "task-invalid", "status": "running", "path": str(invalid_json_path)},
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = run_store.load_latest_checkpoint()

    assert payload == {"task_key": "task-valid", "run_data": {}}


def test_load_latest_checkpoint_returns_none_for_invalid_manifest_shape(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-invalid-shape")
    (run_store.checkpoints_dir / "manifest.json").write_text('{"checkpoints":{}}', encoding="utf-8")

    assert run_store.load_latest_checkpoint() is None
    assert run_store.list_completed_checkpoints() == set()


def test_load_latest_checkpoint_ignores_manifest_entries_outside_run_dir(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-outside-run")
    outside_path = tmp_path / "outside-checkpoint.json"
    outside_path.write_text('{"task_key":"outside","run_data":{"escaped":true}}', encoding="utf-8")
    valid_path = run_store.checkpoints_dir / "task-valid.json"
    valid_path.write_text('{"task_key":"task-valid","run_data":{"ok":true}}', encoding="utf-8")
    (run_store.checkpoints_dir / "manifest.json").write_text(
        json.dumps(
            {
                "checkpoints": [
                    {"task_key": "outside", "status": "completed", "path": str(outside_path)},
                    {"task_key": "task-valid", "status": "completed", "path": str(valid_path)},
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = run_store.load_latest_checkpoint()

    assert payload == {"task_key": "task-valid", "run_data": {"ok": True}}


def test_list_completed_checkpoints_ignores_invalid_entries(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-completed")
    (run_store.checkpoints_dir / "manifest.json").write_text(
        json.dumps(
            {
                "checkpoints": [
                    {"task_key": "task-a", "status": "completed", "path": "a.json"},
                    {"task_key": "", "status": "completed", "path": "empty.json"},
                    {"task_key": 7, "status": "completed", "path": "bad.json"},
                    {"task_key": "task-b", "status": "running", "path": "b.json"},
                    "junk",
                ]
            }
        ),
        encoding="utf-8",
    )

    assert run_store.list_completed_checkpoints() == {"task-a"}
