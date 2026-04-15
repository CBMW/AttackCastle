from __future__ import annotations

import json
import os
from pathlib import Path

from attackcastle.storage.run_store import RunStore


def test_run_store_control_round_trip(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="control-test")
    assert run_store.read_control() is None

    control_path = run_store.write_control("pause", {"reason": "operator_test"})
    assert control_path.exists()
    payload = run_store.read_control()
    assert payload is not None
    assert payload["action"] == "pause"
    assert payload["reason"] == "operator_test"

    run_store.clear_control()
    assert run_store.read_control() is None


def test_run_store_read_control_ignores_invalid_json(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="control-invalid-json")
    run_store.control_path.write_text("{not-json", encoding="utf-8")
    assert run_store.read_control() is None


def test_run_store_write_control_preserves_existing_payload_when_replace_fails(
    tmp_path: Path,
    monkeypatch,
):
    run_store = RunStore(output_root=tmp_path, run_id="control-atomic-failure")
    run_store.write_control("pause", {"reason": "existing"})

    def failing_replace(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("attackcastle.storage.run_store.os.replace", failing_replace)

    try:
        run_store.write_control("stop", {"reason": "new"})
    except OSError as exc:
        assert "simulated replace failure" in str(exc)
    else:
        raise AssertionError("Expected write_control to propagate replace failure")

    payload = run_store.read_control()
    assert payload is not None
    assert payload["action"] == "pause"
    assert payload["reason"] == "existing"
    assert list(run_store.control_dir.glob("*.tmp")) == []


def test_save_checkpoint_recovers_from_invalid_manifest_json(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-invalid-json")
    manifest_path = run_store.checkpoints_dir / "manifest.json"
    manifest_path.write_text("{not-json", encoding="utf-8")

    checkpoint_path = run_store.save_checkpoint("task-1", "running", {"value": 1})

    assert checkpoint_path.exists()
    repaired = run_store.read_json("checkpoints/manifest.json")
    assert len(repaired["checkpoints"]) == 1
    assert repaired["checkpoints"][0]["path"] == str(checkpoint_path)
    assert repaired["checkpoints"][0]["status"] == "running"
    assert repaired["checkpoints"][0]["task_key"] == "task-1"
    assert repaired["checkpoints"][0]["updated_at"]


def test_save_checkpoint_filters_invalid_manifest_rows_when_updating_task(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-invalid-rows")
    old_path = run_store.checkpoints_dir / "task-1-old.json"
    old_path.write_text("{}", encoding="utf-8")
    manifest_path = run_store.checkpoints_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "checkpoints": [
                    {"task_key": "task-1", "status": "completed", "path": str(old_path)},
                    "bad-row",
                    {"status": "completed", "path": "missing-task-key"},
                ]
            }
        ),
        encoding="utf-8",
    )

    checkpoint_path = run_store.save_checkpoint("task-1", "running", {"value": 2})

    repaired = run_store.read_json("checkpoints/manifest.json")
    assert repaired["checkpoints"][0] == {"status": "completed", "path": "missing-task-key"}
    assert repaired["checkpoints"][1]["path"] == str(checkpoint_path)
    assert repaired["checkpoints"][1]["status"] == "running"
    assert repaired["checkpoints"][1]["task_key"] == "task-1"
    assert repaired["checkpoints"][1]["updated_at"]


def test_save_checkpoint_tracks_fanout_instances_independently(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="checkpoint-instances")

    first = run_store.save_checkpoint(
        "run-nmap",
        "completed",
        {"value": 1},
        instance_key="run-nmap::iter1::first",
        task_inputs=["198.51.100.10"],
    )
    second = run_store.save_checkpoint(
        "run-nmap",
        "running",
        {"value": 2},
        instance_key="run-nmap::iter1::second",
        task_inputs=["198.51.100.11"],
    )

    manifest = run_store.read_json("checkpoints/manifest.json")
    rows = manifest["checkpoints"]
    assert {row["instance_key"] for row in rows} == {
        "run-nmap::iter1::first",
        "run-nmap::iter1::second",
    }
    assert first != second
    assert run_store.list_completed_checkpoint_instances() == {("run-nmap", "run-nmap::iter1::first")}
    assert "run-nmap" not in run_store.list_completed_checkpoints()

    run_store.save_checkpoint(
        "run-nmap",
        "completed",
        {"value": 3},
        instance_key="run-nmap::iter1::second",
        task_inputs=["198.51.100.11"],
    )

    assert run_store.list_completed_checkpoint_instances() == {
        ("run-nmap", "run-nmap::iter1::first"),
        ("run-nmap", "run-nmap::iter1::second"),
    }
    assert "run-nmap" not in run_store.list_completed_checkpoints()


def test_run_store_rejects_paths_that_escape_run_directory(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="path-escape")

    for operation in (
        lambda: run_store.resolve("../outside.json"),
        lambda: run_store.write_text("../outside.txt", "bad"),
        lambda: run_store.write_json("../outside.json", {"bad": True}),
        lambda: run_store.write_bytes("../outside.bin", b"bad"),
    ):
        try:
            operation()
        except ValueError as exc:
            assert "within" in str(exc)
        else:
            raise AssertionError("Expected path validation to reject escaping writes")


def test_run_store_rejects_absolute_paths_for_write_targets(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="absolute-path")

    try:
        run_store.write_text(str(tmp_path / "absolute.txt"), "bad")
    except ValueError as exc:
        assert "relative" in str(exc)
    else:
        raise AssertionError("Expected absolute write path to be rejected")


def test_run_store_rejects_artifact_and_log_paths_that_escape_base_dir(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="artifact-paths")

    for operation in (
        lambda: run_store.artifact_path("../bad-tool", "artifact.txt"),
        lambda: run_store.artifact_path("nmap", "../artifact.txt"),
        lambda: run_store.log_path("../run.log"),
    ):
        try:
            operation()
        except ValueError as exc:
            assert "within" in str(exc)
        else:
            raise AssertionError("Expected path validation to reject escaping artifact/log path")
