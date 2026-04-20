from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import replace
from typing import Any

from attackcastle.gui.asset_graph_models import GraphBuildOptions, GraphEdge, GraphNode, GraphSnapshot
from attackcastle.gui.asset_inventory import scan_target_for_row
from attackcastle.gui.models import RunSnapshot


class AssetGraphBuilder:
    def __init__(self) -> None:
        self._base_cache: dict[tuple[Any, ...], tuple[dict[str, GraphNode], list[GraphEdge]]] = {}
        self._snapshot_cache: dict[tuple[Any, ...], GraphSnapshot] = {}

    def focus_node_for_row(self, entity_kind: str, row: dict[str, Any]) -> str:
        if entity_kind == "asset":
            return self._entity_node_id("asset", str(row.get("asset_id") or ""))
        if entity_kind == "service":
            return self._entity_node_id("service", str(row.get("service_id") or ""))
        if entity_kind == "web_app":
            return self._entity_node_id("web_app", str(row.get("webapp_id") or ""))
        if entity_kind == "endpoint":
            return self._entity_node_id("endpoint", str(row.get("endpoint_id") or ""))
        if entity_kind == "technology":
            return self._entity_node_id("technology", str(row.get("tech_id") or row.get("technology_id") or ""))
        return ""

    def reveal_inventory_row(
        self,
        snapshot: RunSnapshot | None,
        *,
        entity_type: str,
        entity_id: str,
    ) -> tuple[str, dict[str, Any] | None]:
        if snapshot is None or not entity_id:
            return "", None
        collections: list[tuple[str, list[dict[str, Any]], str]] = [
            ("asset", snapshot.assets, "asset_id"),
            ("service", snapshot.services, "service_id"),
            ("web_app", snapshot.web_apps, "webapp_id"),
            ("endpoint", snapshot.endpoints, "endpoint_id"),
            ("technology", snapshot.technologies, "tech_id"),
        ]
        for kind, rows, key in collections:
            if kind != entity_type:
                continue
            for row in rows:
                if str(row.get(key) or "") == entity_id:
                    return kind, row
        return "", None

    def find_node_id(self, snapshot: RunSnapshot | None, term: str, options: GraphBuildOptions) -> str:
        if snapshot is None:
            return ""
        normalized = str(term or "").strip().lower()
        if not normalized:
            return ""
        nodes, _edges = self._base_graph(snapshot, options)
        ranked = sorted(
            nodes.values(),
            key=lambda node: (
                0 if normalized in node.label.lower() else 1,
                len(node.label),
                node.label.lower(),
            ),
        )
        for node in ranked:
            haystacks = [
                node.label.lower(),
                node.subtitle.lower(),
                str(node.metadata.get("scan_target", "")).lower(),
                str(node.metadata.get("value", "")).lower(),
            ]
            if any(normalized in haystack for haystack in haystacks if haystack):
                return node.id
        return ""

    def build(self, snapshot: RunSnapshot | None, options: GraphBuildOptions | None = None) -> GraphSnapshot:
        if snapshot is None:
            return GraphSnapshot(summary={"node_count": 0, "edge_count": 0})
        resolved = options or GraphBuildOptions()
        cache_key = resolved.cache_key(snapshot.workspace_id or snapshot.run_id, self._snapshot_revision(snapshot))
        cached = self._snapshot_cache.get(cache_key)
        if cached is not None:
            return cached

        base_nodes, base_edges = self._base_graph(snapshot, resolved)
        filtered_nodes, filtered_edges = self._apply_filters(base_nodes, base_edges, resolved)
        focus_node_id = resolved.root_node_id if resolved.root_node_id in filtered_nodes else ""
        if focus_node_id:
            subgraph_nodes, subgraph_edges = self._focused_subgraph(filtered_nodes, filtered_edges, focus_node_id, resolved)
        else:
            subgraph_nodes, subgraph_edges = self._rooted_workspace_subgraph(filtered_nodes, filtered_edges, snapshot)

        graph_snapshot = GraphSnapshot(
            nodes=sorted(subgraph_nodes.values(), key=lambda node: (node.node_type, node.label.lower(), node.id)),
            edges=sorted(subgraph_edges, key=lambda edge: (edge.edge_type, edge.source_id, edge.target_id, edge.id)),
            summary={
                "node_count": len(subgraph_nodes),
                "edge_count": len(subgraph_edges),
                "focus_node_id": focus_node_id,
                "workspace_id": snapshot.workspace_id,
                "workspace_name": snapshot.workspace_name,
                "layout": resolved.layout_name,
            },
            focus_node_id=focus_node_id,
            truncated=False,
        )
        self._snapshot_cache[cache_key] = graph_snapshot
        return graph_snapshot

    def _base_graph(
        self,
        snapshot: RunSnapshot,
        options: GraphBuildOptions,
    ) -> tuple[dict[str, GraphNode], list[GraphEdge]]:
        key = (
            snapshot.workspace_id or snapshot.run_id,
            self._snapshot_revision(snapshot),
            bool(options.include_provenance),
            bool(options.include_findings),
            bool(options.include_evidence),
        )
        cached = self._base_cache.get(key)
        if cached is not None:
            return cached

        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        workspace_id = self._workspace_node_id(snapshot)
        self._upsert_node(
            nodes,
            GraphNode(
                id=workspace_id,
                node_type="workspace",
                entity_type="workspace",
                entity_id=snapshot.workspace_id or snapshot.run_id,
                label=snapshot.workspace_name or "Ad-Hoc Session",
                subtitle="Project",
                metadata={
                    "workspace_id": snapshot.workspace_id,
                    "workspace_name": snapshot.workspace_name,
                    "scan_target": "",
                    "run_id": snapshot.run_id,
                },
                expandable=bool(snapshot.assets or snapshot.scope),
            ),
        )

        assets_by_id = {str(item.get("asset_id") or ""): item for item in snapshot.assets}

        for scope_row in snapshot.scope:
            value = str(scope_row.get("raw") or scope_row.get("value") or "").strip()
            if not value:
                continue
            node_id = self._scope_node_id(value)
            self._upsert_node(
                nodes,
                GraphNode(
                    id=node_id,
                    node_type="scope_root",
                    entity_type="scope_root",
                    entity_id=value,
                    label=value,
                    subtitle=str(scope_row.get("target_type") or "scope").replace("_", " "),
                    metadata={"value": value, "scan_target": value},
                    expandable=True,
                ),
            )
            self._upsert_edge(edges, self._edge("scopes", workspace_id, node_id, metadata={"source": "workspace"}))

        for asset in snapshot.assets:
            self._add_asset_nodes(snapshot, nodes, edges, asset)

        for service in snapshot.services:
            self._add_service_nodes(snapshot, assets_by_id, nodes, edges, service, include_provenance=options.include_provenance)

        for web_app in snapshot.web_apps:
            self._add_web_app_nodes(snapshot, nodes, edges, web_app, include_provenance=options.include_provenance)

        for endpoint in snapshot.endpoints:
            self._add_endpoint_nodes(snapshot, nodes, edges, endpoint, include_provenance=options.include_provenance)

        for technology in snapshot.technologies:
            self._add_technology_nodes(snapshot, nodes, edges, technology, include_provenance=options.include_provenance)

        for relationship in snapshot.relationships:
            self._add_relationship_nodes(nodes, edges, relationship, include_provenance=options.include_provenance)

        if options.include_findings:
            for finding in snapshot.findings:
                self._add_finding_nodes(nodes, edges, finding)

        if options.include_evidence:
            for bundle in snapshot.evidence_bundles:
                self._add_evidence_nodes(nodes, edges, bundle)

        base_graph = (nodes, list(edges.values()))
        self._base_cache[key] = base_graph
        return base_graph

    def _add_asset_nodes(
        self,
        snapshot: RunSnapshot,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        asset: dict[str, Any],
    ) -> None:
        asset_id = str(asset.get("asset_id") or "")
        if not asset_id:
            return
        asset_node_id = self._entity_node_id("asset", asset_id)
        asset_node_type = self._asset_node_type(asset)
        label = str(asset.get("name") or asset.get("ip") or asset_id)
        self._upsert_node(
            nodes,
            GraphNode(
                id=asset_node_id,
                node_type=asset_node_type,
                entity_type="asset",
                entity_id=asset_id,
                label=label,
                subtitle=self._asset_subtitle(asset, asset_node_type),
                metadata={
                    **dict(asset),
                    "scan_target": scan_target_for_row("asset", asset, snapshot),
                },
                expandable=True,
            ),
        )
        parent_asset_id = str(asset.get("parent_asset_id") or "")
        if parent_asset_id:
            self._upsert_edge(
                edges,
                self._edge(
                    "derived_from",
                    self._entity_node_id("asset", parent_asset_id),
                    asset_node_id,
                    metadata={"source_tool": asset.get("source_tool", "")},
                    style_class="provenance-edge",
                ),
            )
        else:
            self._upsert_edge(edges, self._edge("contains", self._workspace_node_id(snapshot), asset_node_id))

        ip_values = [str(asset.get("ip") or "").strip(), *[str(item).strip() for item in asset.get("resolved_ips") or []]]
        for ip_value in sorted({item for item in ip_values if item and item != label}):
            ip_node_id = self._entity_node_id("ip", ip_value)
            self._upsert_node(
                nodes,
                GraphNode(
                    id=ip_node_id,
                    node_type="ip",
                    entity_type="ip",
                    entity_id=ip_value,
                    label=ip_value,
                    subtitle="Resolved IP",
                    metadata={"value": ip_value, "scan_target": ip_value},
                    expandable=True,
                ),
            )
            self._upsert_edge(edges, self._edge("resolves_to", asset_node_id, ip_node_id))

    def _add_service_nodes(
        self,
        snapshot: RunSnapshot,
        assets_by_id: dict[str, dict[str, Any]],
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        service: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        service_id = str(service.get("service_id") or "")
        asset_id = str(service.get("asset_id") or "")
        if not service_id or not asset_id:
            return
        asset_row = assets_by_id.get(asset_id, {})
        host_value = str(asset_row.get("ip") or asset_row.get("name") or asset_id)
        host_node_id = self._preferred_host_node_id(asset_row)
        port_id = self._port_node_id(host_value, service)
        protocol = str(service.get("protocol") or "tcp").lower()
        port = int(service.get("port") or 0)
        self._upsert_node(
            nodes,
            GraphNode(
                id=port_id,
                node_type="port",
                entity_type="port",
                entity_id=f"{host_value}:{port}/{protocol}",
                label=f"{port}/{protocol}",
                subtitle=host_value,
                metadata={"port": port, "protocol": protocol, "scan_target": f"{host_value}:{port}"},
                expandable=True,
            ),
        )
        self._upsert_edge(edges, self._edge("hosts_port", host_node_id, port_id))

        service_node_id = self._entity_node_id("service", service_id)
        self._upsert_node(
            nodes,
            GraphNode(
                id=service_node_id,
                node_type="service",
                entity_type="service",
                entity_id=service_id,
                label=str(service.get("name") or f"{port}/{protocol}"),
                subtitle=f"{port}/{protocol}",
                metadata={**dict(service), "scan_target": scan_target_for_row("service", service, snapshot)},
                expandable=True,
            ),
        )
        self._upsert_edge(edges, self._edge("identifies_service", port_id, service_node_id))
        self._attach_source_tool(nodes, edges, service_node_id, service, include_provenance=include_provenance)

    def _add_web_app_nodes(
        self,
        snapshot: RunSnapshot,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        web_app: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        webapp_id = str(web_app.get("webapp_id") or "")
        asset_id = str(web_app.get("asset_id") or "")
        if not webapp_id or not asset_id:
            return
        node_id = self._entity_node_id("web_app", webapp_id)
        self._upsert_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="web_app",
                entity_type="web_app",
                entity_id=webapp_id,
                label=str(web_app.get("title") or web_app.get("url") or webapp_id),
                subtitle=str(web_app.get("url") or ""),
                metadata={**dict(web_app), "scan_target": scan_target_for_row("web_app", web_app, snapshot)},
                expandable=True,
            ),
        )
        service_id = str(web_app.get("service_id") or "")
        source_id = self._entity_node_id("service", service_id) if service_id else self._entity_node_id("asset", asset_id)
        self._upsert_edge(edges, self._edge("serves", source_id, node_id))
        self._attach_source_tool(nodes, edges, node_id, web_app, include_provenance=include_provenance)

    def _add_endpoint_nodes(
        self,
        snapshot: RunSnapshot,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        endpoint: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        webapp_id = str(endpoint.get("webapp_id") or "")
        if not endpoint_id or not webapp_id:
            return
        node_id = self._entity_node_id("endpoint", endpoint_id)
        method = str(endpoint.get("method") or "").upper()
        self._upsert_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="endpoint",
                entity_type="endpoint",
                entity_id=endpoint_id,
                label=str(endpoint.get("url") or endpoint_id),
                subtitle=method or str(endpoint.get("kind") or "endpoint"),
                metadata={**dict(endpoint), "scan_target": scan_target_for_row("endpoint", endpoint, snapshot)},
                expandable=False,
            ),
        )
        self._upsert_edge(edges, self._edge("has_endpoint", self._entity_node_id("web_app", webapp_id), node_id))
        self._attach_source_tool(nodes, edges, node_id, endpoint, include_provenance=include_provenance)

    def _add_technology_nodes(
        self,
        snapshot: RunSnapshot,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        technology: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        tech_id = str(technology.get("tech_id") or technology.get("technology_id") or "")
        if not tech_id:
            return
        node_id = self._entity_node_id("technology", tech_id)
        self._upsert_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="technology",
                entity_type="technology",
                entity_id=tech_id,
                label=str(technology.get("name") or tech_id),
                subtitle=str(technology.get("version") or technology.get("category") or ""),
                metadata={**dict(technology), "scan_target": scan_target_for_row("technology", technology, snapshot)},
                expandable=False,
            ),
        )
        webapp_id = str(technology.get("webapp_id") or "")
        asset_id = str(technology.get("asset_id") or "")
        source_id = self._entity_node_id("web_app", webapp_id) if webapp_id else self._entity_node_id("asset", asset_id)
        self._upsert_edge(edges, self._edge("uses_technology", source_id, node_id))
        self._attach_source_tool(nodes, edges, node_id, technology, include_provenance=include_provenance)

    def _add_relationship_nodes(
        self,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        relationship: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        relation_type = str(relationship.get("relationship_type") or "").strip()
        if not relation_type:
            return
        source_node_id = self._node_id_for_relationship_endpoint(relationship, "source")
        target_node_id = self._node_id_for_relationship_endpoint(relationship, "target")
        if not source_node_id or not target_node_id:
            return
        if source_node_id not in nodes:
            self._upsert_node(nodes, self._synthetic_relationship_node(source_node_id, relationship, "source"))
        if target_node_id not in nodes:
            self._upsert_node(nodes, self._synthetic_relationship_node(target_node_id, relationship, "target"))
        self._upsert_edge(
            edges,
            self._edge(
                relation_type,
                source_node_id,
                target_node_id,
                metadata=dict(relationship),
                style_class="provenance-edge" if relation_type in {"discovered_by", "derived_from"} else "",
            ),
        )
        if include_provenance and relationship.get("source_tool"):
            tool_name = str(relationship.get("source_tool") or "internal")
            tool_id = self._tool_node_id(tool_name)
            self._upsert_tool_node(nodes, tool_id, tool_name)
            self._upsert_edge(
                edges,
                self._edge(
                    "discovered_by",
                    tool_id,
                    target_node_id,
                    metadata=dict(relationship),
                    style_class="provenance-edge",
                ),
            )

    def _add_finding_nodes(
        self,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        finding: dict[str, Any],
    ) -> None:
        finding_id = str(finding.get("finding_id") or "")
        if not finding_id:
            return
        node_id = self._entity_node_id("finding", finding_id)
        severity = str(finding.get("severity") or "info")
        self._upsert_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="finding",
                entity_type="finding",
                entity_id=finding_id,
                label=str(finding.get("title") or finding_id),
                subtitle=severity.title(),
                metadata={**dict(finding), "severity": severity},
                expandable=False,
            ),
        )
        for entity_ref in finding.get("affected_entities") or []:
            if not isinstance(entity_ref, dict):
                continue
            source_node_id = self._entity_node_id(
                str(entity_ref.get("entity_type") or ""),
                str(entity_ref.get("entity_id") or ""),
            )
            if source_node_id in nodes:
                self._upsert_edge(
                    edges,
                    self._edge(
                        "produces_finding",
                        source_node_id,
                        node_id,
                        metadata={"severity": severity},
                        style_class="finding-edge",
                    ),
                )

    def _add_evidence_nodes(
        self,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        bundle: dict[str, Any],
    ) -> None:
        bundle_id = str(bundle.get("bundle_id") or "")
        if not bundle_id:
            return
        node_id = self._entity_node_id("evidence_bundle", bundle_id)
        self._upsert_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="evidence_bundle",
                entity_type="evidence_bundle",
                entity_id=bundle_id,
                label=str(bundle.get("label") or "Evidence Bundle"),
                subtitle=str(bundle.get("summary") or ""),
                metadata=dict(bundle),
                expandable=bool(bundle.get("screenshot_paths") or bundle.get("artifact_paths")),
            ),
        )
        parent_id = ""
        entity_type = str(bundle.get("entity_type") or "")
        entity_id = str(bundle.get("entity_id") or "")
        if entity_type and entity_id:
            parent_id = self._entity_node_id(entity_type, entity_id)
        elif bundle.get("asset_id"):
            parent_id = self._entity_node_id("asset", str(bundle.get("asset_id") or ""))
        if parent_id in nodes:
            self._upsert_edge(edges, self._edge("has_evidence", parent_id, node_id, style_class="evidence-edge"))
        for path in bundle.get("screenshot_paths") or []:
            path_text = str(path or "").strip()
            if not path_text:
                continue
            screenshot_id = self._entity_node_id("screenshot", path_text)
            self._upsert_node(
                nodes,
                GraphNode(
                    id=screenshot_id,
                    node_type="screenshot",
                    entity_type="screenshot",
                    entity_id=path_text,
                    label=self._basename(path_text),
                    subtitle="Screenshot",
                    metadata={"path": path_text},
                    expandable=False,
                ),
            )
            self._upsert_edge(edges, self._edge("has_screenshot", node_id, screenshot_id, style_class="evidence-edge"))

    def _focused_subgraph(
        self,
        nodes: dict[str, GraphNode],
        edges: list[GraphEdge],
        focus_node_id: str,
        options: GraphBuildOptions,
    ) -> tuple[dict[str, GraphNode], list[GraphEdge]]:
        if focus_node_id not in nodes:
            return {}, []
        incoming, outgoing, undirected = self._adjacency(edges)
        selected_nodes: set[str] = {focus_node_id}
        max_depth = max(int(options.depth), 1)
        frontier = deque([(focus_node_id, 0)])
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            next_nodes: set[str] = set()
            if options.lineage_mode == "upstream":
                next_nodes.update(edge.source_id for edge in incoming.get(current, []))
            elif options.lineage_mode == "downstream":
                next_nodes.update(edge.target_id for edge in outgoing.get(current, []))
            else:
                next_nodes.update(undirected.get(current, set()))
            for node_id in next_nodes:
                if node_id in selected_nodes:
                    continue
                selected_nodes.add(node_id)
                if not options.direct_neighbors_only:
                    frontier.append((node_id, depth + 1))
        selected_nodes, overflow_edges, _truncated = self._apply_neighbor_caps(
            nodes,
            edges,
            focus_node_id,
            selected_nodes,
            options.max_neighbors_per_type,
        )
        subgraph_nodes = {node_id: nodes[node_id] for node_id in selected_nodes if node_id in nodes}
        subgraph_edges = [
            edge
            for edge in edges
            if edge.source_id in subgraph_nodes and edge.target_id in subgraph_nodes
        ]
        subgraph_edges.extend(overflow_edges)
        return subgraph_nodes, subgraph_edges

    def _rooted_workspace_subgraph(
        self,
        nodes: dict[str, GraphNode],
        edges: list[GraphEdge],
        snapshot: RunSnapshot,
    ) -> tuple[dict[str, GraphNode], list[GraphEdge]]:
        workspace_id = self._workspace_node_id(snapshot)
        selected_ids = {workspace_id}
        for edge in edges:
            if edge.source_id == workspace_id:
                selected_ids.add(edge.target_id)
        if not snapshot.scope:
            for asset in snapshot.assets:
                if str(asset.get("parent_asset_id") or ""):
                    continue
                selected_ids.add(self._entity_node_id("asset", str(asset.get("asset_id") or "")))
        selected_nodes = {node_id: nodes[node_id] for node_id in selected_ids if node_id in nodes}
        selected_edges = [
            edge for edge in edges if edge.source_id in selected_nodes and edge.target_id in selected_nodes
        ]
        return selected_nodes, selected_edges

    def _apply_filters(
        self,
        nodes: dict[str, GraphNode],
        edges: list[GraphEdge],
        options: GraphBuildOptions,
    ) -> tuple[dict[str, GraphNode], list[GraphEdge]]:
        filtered_nodes = dict(nodes)
        if options.node_filters:
            filtered_nodes = {
                node_id: node
                for node_id, node in filtered_nodes.items()
                if node.node_type in options.node_filters
            }
        filtered_edges = [
            edge
            for edge in edges
            if edge.source_id in filtered_nodes
            and edge.target_id in filtered_nodes
            and (not options.edge_filters or edge.edge_type in options.edge_filters)
        ]
        return filtered_nodes, filtered_edges

    def _apply_neighbor_caps(
        self,
        nodes: dict[str, GraphNode],
        edges: list[GraphEdge],
        focus_node_id: str,
        selected_nodes: set[str],
        max_neighbors_per_type: int,
    ) -> tuple[set[str], list[GraphEdge], bool]:
        cap = max(int(max_neighbors_per_type), 1)
        neighbors_by_type: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            if edge.source_id == focus_node_id and edge.target_id in selected_nodes:
                neighbor_id = edge.target_id
            elif edge.target_id == focus_node_id and edge.source_id in selected_nodes:
                neighbor_id = edge.source_id
            else:
                continue
            node = nodes.get(neighbor_id)
            if node is None:
                continue
            neighbors_by_type[node.node_type].append(neighbor_id)

        overflow_edges: list[GraphEdge] = []
        truncated = False
        for node_type, node_ids in neighbors_by_type.items():
            ordered = sorted(set(node_ids), key=lambda item: (nodes[item].label.lower(), item))
            if len(ordered) <= cap:
                continue
            truncated = True
            for node_id in ordered[cap:]:
                selected_nodes.discard(node_id)
            overflow_node_id = f"overflow::{focus_node_id}::{node_type}"
            nodes[overflow_node_id] = GraphNode(
                id=overflow_node_id,
                node_type="overflow",
                entity_type="overflow",
                entity_id=overflow_node_id,
                label=f"+ {len(ordered) - cap} more",
                subtitle=node_type.replace("_", " "),
                metadata={"hidden_type": node_type, "count": len(ordered) - cap},
                expandable=False,
            )
            selected_nodes.add(overflow_node_id)
            overflow_edges.append(
                self._edge(
                    "related_to",
                    focus_node_id,
                    overflow_node_id,
                    metadata={"count": len(ordered) - cap, "hidden_type": node_type},
                    style_class="overflow-edge",
                )
            )
        return selected_nodes, overflow_edges, truncated

    def _adjacency(
        self,
        edges: list[GraphEdge],
    ) -> tuple[dict[str, list[GraphEdge]], dict[str, list[GraphEdge]], dict[str, set[str]]]:
        incoming: dict[str, list[GraphEdge]] = defaultdict(list)
        outgoing: dict[str, list[GraphEdge]] = defaultdict(list)
        undirected: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            outgoing[edge.source_id].append(edge)
            incoming[edge.target_id].append(edge)
            undirected[edge.source_id].add(edge.target_id)
            undirected[edge.target_id].add(edge.source_id)
        return incoming, outgoing, undirected

    def _upsert_node(self, nodes: dict[str, GraphNode], node: GraphNode) -> None:
        existing = nodes.get(node.id)
        if existing is None:
            nodes[node.id] = node
            return
        metadata = dict(existing.metadata)
        metadata.update({key: value for key, value in node.metadata.items() if value not in (None, "", [], {})})
        nodes[node.id] = replace(
            existing,
            label=existing.label if existing.label and existing.label != existing.id else node.label,
            subtitle=existing.subtitle or node.subtitle,
            metadata=metadata,
            expandable=existing.expandable or node.expandable,
        )

    def _upsert_edge(self, edges: dict[str, GraphEdge], edge: GraphEdge) -> None:
        edges.setdefault(edge.id, edge)

    def _edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        *,
        metadata: dict[str, Any] | None = None,
        style_class: str = "",
    ) -> GraphEdge:
        edge_id = self._stable_hash("edge", edge_type, source_id, target_id, json.dumps(metadata or {}, sort_keys=True, default=str))
        return GraphEdge(
            id=edge_id,
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            metadata=metadata or {},
            style_class=style_class,
        )

    def _workspace_node_id(self, snapshot: RunSnapshot) -> str:
        return f"workspace::{snapshot.workspace_id or snapshot.run_id}"

    def _scope_node_id(self, value: str) -> str:
        return f"scope::{self._stable_hash('scope', value)}"

    def _entity_node_id(self, entity_type: str, entity_id: str) -> str:
        normalized_type = str(entity_type or "").strip().lower()
        normalized_id = str(entity_id or "").strip()
        if not normalized_type or not normalized_id:
            return ""
        if normalized_type in {"ip", "screenshot", "scope_root", "tool_source"}:
            return f"{normalized_type}::{self._stable_hash(normalized_type, normalized_id)}"
        return f"{normalized_type}::{normalized_id}"

    def _tool_node_id(self, tool_name: str) -> str:
        return self._entity_node_id("tool_source", tool_name.lower())

    def _port_node_id(self, host_value: str, service: dict[str, Any]) -> str:
        return self._entity_node_id(
            "port",
            f"{host_value}:{int(service.get('port') or 0)}/{str(service.get('protocol') or 'tcp').lower()}",
        )

    def _preferred_host_node_id(self, asset_row: dict[str, Any]) -> str:
        asset_id = str(asset_row.get("asset_id") or "")
        ip_value = str(asset_row.get("ip") or "").strip()
        if ip_value and self._asset_node_type(asset_row) != "ip":
            return self._entity_node_id("ip", ip_value)
        return self._entity_node_id("asset", asset_id)

    def _attach_source_tool(
        self,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        target_node_id: str,
        row: dict[str, Any],
        *,
        include_provenance: bool,
    ) -> None:
        if not include_provenance:
            return
        source_tool = str(row.get("source_tool") or "").strip()
        if not source_tool:
            return
        tool_id = self._tool_node_id(source_tool)
        self._upsert_tool_node(nodes, tool_id, source_tool)
        self._upsert_edge(
            edges,
            self._edge(
                "discovered_by",
                tool_id,
                target_node_id,
                metadata={
                    "source_tool": source_tool,
                    "source_execution_id": str(row.get("source_execution_id") or ""),
                },
                style_class="provenance-edge",
            ),
        )

    def _upsert_tool_node(self, nodes: dict[str, GraphNode], tool_id: str, tool_name: str) -> None:
        self._upsert_node(
            nodes,
            GraphNode(
                id=tool_id,
                node_type="tool_source",
                entity_type="tool_source",
                entity_id=tool_name,
                label=tool_name,
                subtitle="Tool / Source",
                metadata={"tool_name": tool_name},
                expandable=True,
            ),
        )

    def _synthetic_relationship_node(
        self,
        node_id: str,
        relationship: dict[str, Any],
        side: str,
    ) -> GraphNode:
        entity_type = str(relationship.get(f"{side}_entity_type") or "")
        entity_id = str(relationship.get(f"{side}_entity_id") or "")
        return GraphNode(
            id=node_id,
            node_type=entity_type or "related",
            entity_type=entity_type,
            entity_id=entity_id,
            label=entity_id,
            subtitle=entity_type.replace("_", " ").title(),
            metadata={"value": entity_id},
            expandable=True,
        )

    def _node_id_for_relationship_endpoint(self, relationship: dict[str, Any], side: str) -> str:
        entity_type = str(relationship.get(f"{side}_entity_type") or "")
        entity_id = str(relationship.get(f"{side}_entity_id") or "")
        if entity_type == "tool_source":
            return self._tool_node_id(entity_id)
        return self._entity_node_id(entity_type, entity_id)

    def _asset_node_type(self, asset: dict[str, Any]) -> str:
        kind = str(asset.get("kind") or "").strip().lower()
        name = str(asset.get("name") or "").strip().lower()
        ip_value = str(asset.get("ip") or "").strip()
        if kind == "ip" or (ip_value and name == ip_value):
            return "ip"
        if "." in name:
            return "domain" if name.count(".") == 1 else "subdomain"
        if ip_value:
            return "hostname"
        return kind or "asset"

    def _asset_subtitle(self, asset: dict[str, Any], node_type: str) -> str:
        aliases = [str(item).strip() for item in asset.get("aliases") or [] if str(item).strip()]
        if node_type == "ip":
            return "IP Address"
        if aliases:
            return ", ".join(aliases[:2])
        return str(asset.get("kind") or node_type).replace("_", " ").title()

    def _basename(self, path_text: str) -> str:
        return path_text.replace("\\", "/").rsplit("/", 1)[-1]

    def _stable_hash(self, *parts: str) -> str:
        digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()  # noqa: S324
        return digest[:12]

    def _snapshot_revision(self, snapshot: RunSnapshot) -> str:
        fields = {
            "scope": len(snapshot.scope),
            "assets": len(snapshot.assets),
            "services": len(snapshot.services),
            "web_apps": len(snapshot.web_apps),
            "endpoints": len(snapshot.endpoints),
            "technologies": len(snapshot.technologies),
            "findings": len(snapshot.findings),
            "bundles": len(snapshot.evidence_bundles),
            "relationships": len(snapshot.relationships),
            "tool_executions": len(snapshot.tool_executions),
        }
        return json.dumps(fields, sort_keys=True)
