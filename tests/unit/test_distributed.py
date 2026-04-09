from __future__ import annotations

from attackcastle.orchestration.distributed import build_shard_plan


def test_build_shard_plan_round_robin_distribution():
    plan = build_shard_plan("a\nb\nc\nd\ne", shards=2)
    assert plan["shard_count"] == 2
    assert plan["target_count"] == 5
    assert len(plan["assignments"]) == 2
    assert plan["assignments"][0]["targets"] == ["a", "c", "e"]
    assert plan["assignments"][1]["targets"] == ["b", "d"]


def test_build_shard_plan_parses_commas_and_ignores_empty_entries():
    plan = build_shard_plan("one,,two\n\nthree", shards=4)
    assert plan["target_count"] == 3
    assert [item["targets"] for item in plan["assignments"]] == [["one"], ["two"], ["three"]]


def test_build_shard_plan_enforces_minimum_one_shard():
    plan = build_shard_plan("x,y", shards=0)
    assert plan["shard_count"] == 1
    assert len(plan["assignments"]) == 1
    assert plan["assignments"][0]["targets"] == ["x", "y"]

