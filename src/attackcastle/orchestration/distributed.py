from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ShardAssignment:
    shard_id: int
    targets: list[str]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_shard_plan(target_input: str, shards: int) -> dict[str, Any]:
    lines = [line.strip() for line in target_input.replace(",", "\n").splitlines() if line.strip()]
    shard_count = max(1, int(shards))
    buckets: list[list[str]] = [[] for _ in range(shard_count)]
    for index, target in enumerate(lines):
        buckets[index % shard_count].append(target)

    assignments = [
        {
            "shard_id": shard_id,
            "targets": items,
            "target_input": "\n".join(items),
        }
        for shard_id, items in enumerate(buckets)
        if items
    ]
    return {
        "shard_count": shard_count,
        "target_count": len(lines),
        "assignments": assignments,
    }


def _queue_path(queue_dir: Path) -> Path:
    return queue_dir / "distributed_queue.json"


def _lock_path(queue_dir: Path) -> Path:
    return queue_dir / ".queue.lock"


def _acquire_lock(lock_path: Path, timeout_seconds: int = 10) -> int:
    start = time.monotonic()
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            return fd
        except FileExistsError:
            if time.monotonic() - start > timeout_seconds:
                raise TimeoutError(f"Could not acquire queue lock: {lock_path}")
            time.sleep(0.05)


def _release_lock(fd: int, lock_path: Path) -> None:
    try:
        os.close(fd)
    finally:
        lock_path.unlink(missing_ok=True)


def _read_queue(queue_dir: Path) -> dict[str, Any]:
    path = _queue_path(queue_dir)
    if not path.exists():
        return {"assignments": []}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return {"assignments": []}
    return loaded


def _write_queue(queue_dir: Path, payload: dict[str, Any]) -> Path:
    path = _queue_path(queue_dir)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def initialize_worker_queue(plan: dict[str, Any], queue_dir: Path) -> Path:
    queue_dir.mkdir(parents=True, exist_ok=True)
    assignments = []
    for assignment in plan.get("assignments", []):
        if not isinstance(assignment, dict):
            continue
        assignments.append(
            {
                "shard_id": int(assignment.get("shard_id", 0)),
                "targets": list(assignment.get("targets", [])),
                "target_input": str(assignment.get("target_input", "")),
                "state": "pending",
                "worker_id": None,
                "claimed_at": None,
                "completed_at": None,
                "result": None,
            }
        )
    payload = {
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "shard_count": int(plan.get("shard_count", len(assignments))),
        "target_count": int(plan.get("target_count", 0)),
        "assignments": assignments,
    }
    return _write_queue(queue_dir, payload)


def claim_next_shard(queue_dir: Path, worker_id: str) -> dict[str, Any] | None:
    queue_dir.mkdir(parents=True, exist_ok=True)
    lock = _lock_path(queue_dir)
    fd = _acquire_lock(lock)
    try:
        queue = _read_queue(queue_dir)
        for assignment in queue.get("assignments", []):
            if not isinstance(assignment, dict):
                continue
            if assignment.get("state") != "pending":
                continue
            assignment["state"] = "running"
            assignment["worker_id"] = worker_id
            assignment["claimed_at"] = _now_iso()
            queue["updated_at"] = _now_iso()
            _write_queue(queue_dir, queue)
            return assignment
    finally:
        _release_lock(fd, lock)
    return None


def complete_shard(
    queue_dir: Path,
    shard_id: int,
    worker_id: str,
    status: str,
    result: dict[str, Any] | None = None,
) -> bool:
    normalized_status = str(status).strip().lower()
    if normalized_status not in {"completed", "failed", "skipped", "cancelled"}:
        normalized_status = "completed"
    queue_dir.mkdir(parents=True, exist_ok=True)
    lock = _lock_path(queue_dir)
    fd = _acquire_lock(lock)
    try:
        queue = _read_queue(queue_dir)
        updated = False
        for assignment in queue.get("assignments", []):
            if not isinstance(assignment, dict):
                continue
            if int(assignment.get("shard_id", -1)) != int(shard_id):
                continue
            if assignment.get("state") not in {"running", "pending"}:
                continue
            if assignment.get("worker_id") not in {None, worker_id}:
                continue
            assignment["state"] = normalized_status
            assignment["worker_id"] = worker_id
            assignment["completed_at"] = _now_iso()
            assignment["result"] = result or {}
            queue["updated_at"] = _now_iso()
            updated = True
            break
        if updated:
            _write_queue(queue_dir, queue)
        return updated
    finally:
        _release_lock(fd, lock)


def queue_status(queue_dir: Path) -> dict[str, Any]:
    queue = _read_queue(queue_dir)
    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0, "cancelled": 0}
    for assignment in queue.get("assignments", []):
        if not isinstance(assignment, dict):
            continue
        state = str(assignment.get("state", "pending"))
        if state not in counts:
            counts[state] = 0
        counts[state] += 1
    return {
        "shard_count": int(queue.get("shard_count", 0)),
        "target_count": int(queue.get("target_count", 0)),
        "updated_at": queue.get("updated_at"),
        "counts": counts,
        "assignments": queue.get("assignments", []),
    }

