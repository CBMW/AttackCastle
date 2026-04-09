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
    assert repaired == {
        "checkpoints": [
            {
                "path": str(checkpoint_path),
                "status": "running",
                "task_key": "task-1",
            }
        ]
    }


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
    assert repaired == {
        "checkpoints": [
            {"status": "completed", "path": "missing-task-key"},
            {
                "path": str(checkpoint_path),
                "status": "running",
                "task_key": "task-1",
            },
        ]
    }


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
