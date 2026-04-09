from __future__ import annotations

from collections import defaultdict
from typing import Any

from attackcastle.core.models import RunData, parse_datetime


def _task_time(task_state: dict[str, Any]) -> str:
    ended = parse_datetime(task_state.get("ended_at"))
    started = parse_datetime(task_state.get("started_at"))
    value = ended or started
    return value.isoformat() if value else ""


def build_task_instance_graph(run_data: RunData) -> dict[str, Any]:
    task_states = [
        item for item in run_data.task_states if isinstance(item, dict) and item.get("key")
    ]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}

    for state in task_states:
        key = str(state.get("key"))
        detail = state.get("detail", {}) if isinstance(state.get("detail"), dict) else {}
        node = {
            "id": key,
            "type": "task",
            "label": str(state.get("label") or key),
            "status": str(state.get("status") or "unknown"),
            "capability": str(detail.get("capability") or "unknown"),
            "stage": str(detail.get("stage") or "general"),
            "attempt": int(detail.get("attempt", 1) or 1),
            "time": _task_time(state),
        }
        nodes.append(node)
        by_key[key] = node

    sorted_states = sorted(task_states, key=_task_time)
    for index in range(len(sorted_states) - 1):
        left = str(sorted_states[index].get("key"))
        right = str(sorted_states[index + 1].get("key"))
        if left and right and left != right:
            edges.append({"source": left, "target": right, "relation": "execution_order"})

    capability_to_tasks: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        capability = str(node.get("capability", "unknown"))
        capability_to_tasks[capability].append(str(node.get("id")))

    for execution in run_data.tool_executions:
        instance_id = f"exec:{execution.execution_id}"
        nodes.append(
            {
                "id": instance_id,
                "type": "execution",
                "label": execution.tool_name,
                "status": execution.status,
                "capability": execution.capability or "unknown",
                "time": execution.ended_at.isoformat(),
            }
        )
        for task_id in capability_to_tasks.get(execution.capability or "unknown", []):
            edges.append({"source": task_id, "target": instance_id, "relation": "task_execution"})

    target_facts = {
        "web_probe.scanned_urls": "url",
        "web_discovery.scanned_urls": "url",
        "web_discovery.discovered_urls": "url",
        "whatweb.scanned_urls": "url",
        "nikto.scanned_urls": "url",
        "nuclei.scanned_urls": "url",
        "wpscan.scanned_urls": "url",
        "sqlmap.scanned_urls": "url",
        "tls_probe.scanned_endpoints": "endpoint",
    }
    for fact_key, node_kind in target_facts.items():
        values = run_data.facts.get(fact_key, [])
        if not isinstance(values, list):
            continue
        capability = fact_key.split(".", 1)[0]
        source_task_ids = capability_to_tasks.get(capability, [])
        for item in values:
            target_id = f"{node_kind}:{item}"
            nodes.append({"id": target_id, "type": node_kind, "label": str(item), "status": "seen"})
            for source_id in source_task_ids:
                edges.append({"source": source_id, "target": target_id, "relation": "task_target"})

    unique_nodes: dict[str, dict[str, Any]] = {}
    for node in nodes:
        unique_nodes[str(node["id"])] = node
    dedupe_edges: set[tuple[str, str, str]] = set()
    unique_edges: list[dict[str, Any]] = []
    for edge in edges:
        source = str(edge.get("source"))
        target = str(edge.get("target"))
        relation = str(edge.get("relation"))
        triple = (source, target, relation)
        if triple in dedupe_edges:
            continue
        dedupe_edges.add(triple)
        unique_edges.append({"source": source, "target": target, "relation": relation})

    return {
        "summary": {
            "task_node_count": len([item for item in unique_nodes.values() if item.get("type") == "task"]),
            "execution_node_count": len(
                [item for item in unique_nodes.values() if item.get("type") == "execution"]
            ),
            "target_node_count": len(
                [
                    item
                    for item in unique_nodes.values()
                    if item.get("type") in {"url", "endpoint"}
                ]
            ),
            "edge_count": len(unique_edges),
        },
        "nodes": list(unique_nodes.values()),
        "edges": unique_edges,
    }
