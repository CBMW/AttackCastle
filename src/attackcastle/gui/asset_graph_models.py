from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class GraphNode:
    id: str
    node_type: str
    entity_type: str
    entity_id: str
    label: str
    subtitle: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    expandable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GraphEdge:
    id: str
    edge_type: str
    source_id: str
    target_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    style_class: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GraphBuildOptions:
    root_node_id: str = ""
    depth: int = 1
    node_filters: set[str] = field(default_factory=set)
    edge_filters: set[str] = field(default_factory=set)
    include_provenance: bool = False
    include_findings: bool = False
    include_evidence: bool = False
    max_neighbors_per_type: int = 8
    direct_neighbors_only: bool = True
    lineage_mode: str = "off"
    layout_name: str = "dagre"

    def cache_key(self, workspace_id: str, snapshot_revision: str) -> tuple[Any, ...]:
        return (
            workspace_id,
            snapshot_revision,
            self.root_node_id,
            max(int(self.depth), 0),
            tuple(sorted(self.node_filters)),
            tuple(sorted(self.edge_filters)),
            bool(self.include_provenance),
            bool(self.include_findings),
            bool(self.include_evidence),
            max(int(self.max_neighbors_per_type), 1),
            bool(self.direct_neighbors_only),
            self.lineage_mode,
            self.layout_name,
        )


@dataclass(slots=True)
class GraphSnapshot:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    focus_node_id: str = ""
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": dict(self.summary),
            "focus_node_id": self.focus_node_id,
            "truncated": self.truncated,
        }
