from __future__ import annotations

from attackcastle.orchestration.distributed import (
    build_shard_plan,
    claim_next_shard,
    complete_shard,
    initialize_worker_queue,
    queue_status,
)


def test_distributed_queue_lifecycle(tmp_path):
    plan = build_shard_plan("a\nb\nc", shards=2)
    queue_dir = tmp_path / "queue"
    initialize_worker_queue(plan, queue_dir)

    first = claim_next_shard(queue_dir, worker_id="w1")
    assert first is not None
    assert first["state"] == "running"

    updated = complete_shard(queue_dir, shard_id=int(first["shard_id"]), worker_id="w1", status="completed")
    assert updated is True

    status = queue_status(queue_dir)
    assert status["counts"]["completed"] == 1
    assert status["counts"]["pending"] >= 0

