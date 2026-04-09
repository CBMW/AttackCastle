from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from attackcastle.core.models import RunData


def build_identity_graph(run_data: RunData) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for asset in run_data.assets:
        nodes[asset.asset_id] = {
            "id": asset.asset_id,
            "type": "asset",
            "kind": asset.kind,
            "label": asset.name,
            "ip": asset.ip,
        }
        if asset.parent_asset_id:
            edges.append(
                {
                    "source": asset.parent_asset_id,
                    "target": asset.asset_id,
                    "relation": "parent_asset",
                }
            )

    for service in run_data.services:
        nodes[service.service_id] = {
            "id": service.service_id,
            "type": "service",
            "kind": service.name or "unknown",
            "label": f"{service.port}/{service.protocol}",
            "port": service.port,
            "protocol": service.protocol,
        }
        edges.append(
            {
                "source": service.asset_id,
                "target": service.service_id,
                "relation": "asset_service",
            }
        )

    for web_app in run_data.web_apps:
        nodes[web_app.webapp_id] = {
            "id": web_app.webapp_id,
            "type": "web_app",
            "label": web_app.url,
        }
        edges.append(
            {"source": web_app.asset_id, "target": web_app.webapp_id, "relation": "asset_web_app"}
        )
        if web_app.service_id:
            edges.append(
                {"source": web_app.service_id, "target": web_app.webapp_id, "relation": "service_web_app"}
            )

    for tls_asset in run_data.tls_assets:
        nodes[tls_asset.tls_id] = {
            "id": tls_asset.tls_id,
            "type": "tls",
            "label": f"{tls_asset.host}:{tls_asset.port}",
            "protocol": tls_asset.protocol,
        }
        edges.append({"source": tls_asset.asset_id, "target": tls_asset.tls_id, "relation": "asset_tls"})
        if tls_asset.service_id:
            edges.append(
                {"source": tls_asset.service_id, "target": tls_asset.tls_id, "relation": "service_tls"}
            )

    for technology in run_data.technologies:
        nodes[technology.tech_id] = {
            "id": technology.tech_id,
            "type": "technology",
            "label": technology.name,
            "version": technology.version,
        }
        edges.append(
            {"source": technology.asset_id, "target": technology.tech_id, "relation": "asset_technology"}
        )
        if technology.webapp_id:
            edges.append(
                {
                    "source": technology.webapp_id,
                    "target": technology.tech_id,
                    "relation": "web_app_technology",
                }
            )

    for canonical_id, aliases in run_data.alias_map.items():
        for alias in aliases:
            edges.append(
                {
                    "source": canonical_id,
                    "target": alias,
                    "relation": "alias",
                }
            )

    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        source = str(edge.get("source"))
        target = str(edge.get("target"))
        if source and target:
            adjacency[source].add(target)
            adjacency[target].add(source)

    visited: set[str] = set()
    components: list[list[str]] = []
    for node_id in nodes:
        if node_id in visited:
            continue
        queue = deque([node_id])
        component: list[str] = []
        visited.add(node_id)
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in adjacency.get(current, set()):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                queue.append(neighbor)
        components.append(sorted(component))
    components.sort(key=len, reverse=True)

    summary = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "component_count": len(components),
        "largest_component_size": len(components[0]) if components else 0,
    }
    return {
        "summary": summary,
        "nodes": list(nodes.values()),
        "edges": edges,
        "components": components,
    }

