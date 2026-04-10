from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.asset_graph_bridge import AssetGraphBridge
from attackcastle.gui.asset_graph_builder import AssetGraphBuilder
from attackcastle.gui.asset_graph_models import GraphBuildOptions, GraphSnapshot
from attackcastle.gui.common import (
    SURFACE_FLAT,
    build_surface_frame,
    configure_scroll_surface,
    set_tooltip,
    style_button,
)
from attackcastle.gui.models import RunSnapshot

try:
    from PySide6.QtWebChannel import QWebChannel
    from PySide6.QtWebEngineWidgets import QWebEngineView
except ImportError:  # pragma: no cover - handled by fallback UI.
    QWebChannel = None
    QWebEngineView = None


class AssetGraphView(QWidget):
    nodeSelected = Signal(dict)
    statusChanged = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._builder = AssetGraphBuilder()
        self._snapshot: RunSnapshot | None = None
        self._focus_node_id = ""
        self._selected_node: dict[str, Any] = {}
        self._lineage_mode = "off"
        self._page_ready = False
        self._pending_payload: dict[str, Any] | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        controls_frame, controls_layout = build_surface_frame(surface=SURFACE_FLAT, padding=0, spacing=10)
        controls_layout.addLayout(self._build_primary_controls())
        controls_layout.addLayout(self._build_secondary_controls())
        layout.addWidget(controls_frame)

        graph_frame, graph_layout = build_surface_frame(surface=SURFACE_FLAT, padding=0, spacing=0)
        self.graph_status = QLabel("Graph view is ready.")
        self.graph_status.setObjectName("helperText")
        graph_layout.addWidget(self.graph_status)
        self._graph_surface = self._build_graph_surface()
        graph_layout.addWidget(self._graph_surface, 1)
        layout.addWidget(graph_frame, 1)

        self._refresh_graph()

    def _build_primary_controls(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        row.addWidget(QLabel("Search"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Find an asset, host, service, web app, finding, or tool")
        self.search_edit.returnPressed.connect(self.search_graph)
        set_tooltip(self.search_edit, "Search the workspace graph and focus the first matching node.")
        row.addWidget(self.search_edit, 1)

        self.search_button = QPushButton("Search")
        style_button(self.search_button, role="secondary", min_height=36)
        self.search_button.clicked.connect(self.search_graph)
        row.addWidget(self.search_button)

        row.addWidget(QLabel("Depth"))
        self.depth_combo = QComboBox()
        for value in ("1", "2", "3"):
            self.depth_combo.addItem(value, int(value))
        self.depth_combo.currentIndexChanged.connect(self._refresh_graph)
        row.addWidget(self.depth_combo)

        row.addWidget(QLabel("Layout"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItem("Hierarchical", "dagre")
        self.layout_combo.addItem("Concentric", "concentric")
        self.layout_combo.addItem("Force", "cose")
        self.layout_combo.currentIndexChanged.connect(self._refresh_graph)
        row.addWidget(self.layout_combo)
        return row

    def _build_secondary_controls(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self.node_group_combo = QComboBox()
        self.node_group_combo.addItem("All Nodes", "all")
        self.node_group_combo.addItem("Infra Only", "infra")
        self.node_group_combo.addItem("Web Only", "web")
        self.node_group_combo.addItem("Evidence Only", "evidence")
        self.node_group_combo.currentIndexChanged.connect(self._refresh_graph)
        row.addWidget(self.node_group_combo)

        self.edge_group_combo = QComboBox()
        self.edge_group_combo.addItem("All Relationships", "all")
        self.edge_group_combo.addItem("Topology", "topology")
        self.edge_group_combo.addItem("Provenance", "provenance")
        self.edge_group_combo.addItem("Findings", "findings")
        self.edge_group_combo.currentIndexChanged.connect(self._refresh_graph)
        row.addWidget(self.edge_group_combo)

        self.neighbors_only_checkbox = QCheckBox("Neighbors Only")
        self.neighbors_only_checkbox.setChecked(True)
        self.neighbors_only_checkbox.toggled.connect(self._refresh_graph)
        row.addWidget(self.neighbors_only_checkbox)

        self.include_provenance_checkbox = QCheckBox("Include Provenance")
        self.include_provenance_checkbox.toggled.connect(self._refresh_graph)
        row.addWidget(self.include_provenance_checkbox)

        self.include_findings_checkbox = QCheckBox("Include Findings")
        self.include_findings_checkbox.toggled.connect(self._refresh_graph)
        row.addWidget(self.include_findings_checkbox)

        self.include_evidence_checkbox = QCheckBox("Include Evidence")
        self.include_evidence_checkbox.toggled.connect(self._refresh_graph)
        row.addWidget(self.include_evidence_checkbox)

        self.lineage_button = QPushButton("Show Lineage")
        style_button(self.lineage_button, role="secondary", min_height=36)
        self.lineage_button.clicked.connect(self.show_lineage)
        row.addWidget(self.lineage_button)

        self.center_button = QPushButton("Center")
        style_button(self.center_button, role="secondary", min_height=36)
        self.center_button.clicked.connect(self.center_on_selected)
        row.addWidget(self.center_button)

        self.reset_button = QPushButton("Reset")
        style_button(self.reset_button, role="secondary", min_height=36)
        self.reset_button.clicked.connect(self.reset_graph_view)
        row.addWidget(self.reset_button)
        row.addStretch(1)
        return row

    def _build_graph_surface(self) -> QWidget:
        if not self._web_engine_supported():
            self.fallback_label = QLabel(
                "Interactive graph rendering is unavailable in this environment. "
                "The graph model and controls still update, but the embedded browser view could not be started."
            )
            self.fallback_label.setObjectName("helperText")
            self.fallback_label.setWordWrap(True)
            fallback_frame = QFrame()
            fallback_layout = QVBoxLayout(fallback_frame)
            fallback_layout.setContentsMargins(0, 0, 0, 0)
            fallback_layout.addWidget(self.fallback_label)
            return fallback_frame

        self.bridge = AssetGraphBridge()
        self.bridge.nodeSelected.connect(self._handle_node_selected)
        self.bridge.graphReady.connect(self._flush_pending_payload)
        self.web_view = configure_scroll_surface(QWebEngineView())
        self.web_view.setContextMenuPolicy(Qt.NoContextMenu)
        self.web_view.loadFinished.connect(self._handle_load_finished)

        channel = QWebChannel(self.web_view.page())
        channel.registerObject("attackcastleBridge", self.bridge)
        self.web_view.page().setWebChannel(channel)
        html_path = Path(__file__).resolve().parent / "web" / "asset_graph.html"
        self.web_view.setUrl(QUrl.fromLocalFile(str(html_path)))
        return self.web_view

    def _web_engine_supported(self) -> bool:
        if QWebEngineView is None or QWebChannel is None:
            return False
        platform_name = QApplication.instance().platformName() if QApplication.instance() is not None else ""
        return platform_name not in {"offscreen", "minimal"}

    def set_snapshot(self, snapshot: RunSnapshot | None) -> None:
        self._snapshot = snapshot
        if snapshot is None:
            self._focus_node_id = ""
            self._selected_node = {}
        elif self._focus_node_id and self._focus_node_id not in {
            node.id for node in self._builder.build(snapshot, self._current_options()).nodes
        }:
            self._focus_node_id = ""
            self._selected_node = {}
        self._refresh_graph()

    def focus_entity(self, entity_kind: str, row: dict[str, Any]) -> bool:
        node_id = self._builder.focus_node_for_row(entity_kind, row)
        if not node_id:
            return False
        self._focus_node_id = node_id
        self._lineage_mode = "off"
        self._refresh_graph()
        return True

    def can_focus_entity(self, entity_kind: str, row: dict[str, Any]) -> bool:
        return bool(self._builder.focus_node_for_row(entity_kind, row))

    def reveal_inventory_row(
        self,
        *,
        entity_type: str,
        entity_id: str,
    ) -> tuple[str, dict[str, Any] | None]:
        return self._builder.reveal_inventory_row(
            self._snapshot,
            entity_type=entity_type,
            entity_id=entity_id,
        )

    def expand_selected(self) -> None:
        node_id = str(self._selected_node.get("id") or "")
        if not node_id:
            return
        self._focus_node_id = node_id
        self._lineage_mode = "off"
        self._refresh_graph()

    def show_lineage(self) -> None:
        node_id = str(self._selected_node.get("id") or self._focus_node_id or "")
        if not node_id:
            return
        self._focus_node_id = node_id
        self._lineage_mode = "upstream"
        self._refresh_graph()

    def search_graph(self) -> None:
        options = self._current_options()
        node_id = self._builder.find_node_id(self._snapshot, self.search_edit.text(), options)
        if not node_id:
            self._set_status("No matching graph node was found.")
            return
        self._focus_node_id = node_id
        self._lineage_mode = "off"
        self._refresh_graph()

    def reset_graph_view(self) -> None:
        self._lineage_mode = "off"
        self._focus_node_id = ""
        self._selected_node = {}
        self._refresh_graph()
        if hasattr(self, "web_view"):
            self.web_view.page().runJavaScript("window.assetGraph && window.assetGraph.resetLayout();")

    def center_on_selected(self) -> None:
        if hasattr(self, "web_view"):
            self.web_view.page().runJavaScript("window.assetGraph && window.assetGraph.centerOnSelection();")

    def current_selected_node(self) -> dict[str, Any]:
        return dict(self._selected_node)

    def _current_options(self) -> GraphBuildOptions:
        return GraphBuildOptions(
            root_node_id=self._focus_node_id,
            depth=int(self.depth_combo.currentData() or 1),
            node_filters=self._resolve_node_filters(),
            edge_filters=self._resolve_edge_filters(),
            include_provenance=self.include_provenance_checkbox.isChecked(),
            include_findings=self.include_findings_checkbox.isChecked(),
            include_evidence=self.include_evidence_checkbox.isChecked(),
            max_neighbors_per_type=8,
            direct_neighbors_only=self.neighbors_only_checkbox.isChecked(),
            lineage_mode=self._lineage_mode,
            layout_name=str(self.layout_combo.currentData() or "dagre"),
        )

    def _resolve_node_filters(self) -> set[str]:
        mode = str(self.node_group_combo.currentData() or "all")
        if mode == "infra":
            return {"workspace", "scope_root", "domain", "subdomain", "hostname", "ip", "port", "service", "tool_source"}
        if mode == "web":
            return {"web_app", "endpoint", "technology", "domain", "subdomain", "service"}
        if mode == "evidence":
            return {"finding", "evidence_bundle", "screenshot", "tool_source"}
        return set()

    def _resolve_edge_filters(self) -> set[str]:
        mode = str(self.edge_group_combo.currentData() or "all")
        if mode == "topology":
            return {"scopes", "contains", "resolves_to", "hosts_port", "identifies_service", "serves", "has_endpoint", "uses_technology"}
        if mode == "provenance":
            return {"derived_from", "discovered_by", "related_to"}
        if mode == "findings":
            return {"produces_finding", "has_evidence", "has_screenshot"}
        return set()

    def _refresh_graph(self) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            self._push_graph(GraphSnapshot(summary={"node_count": 0, "edge_count": 0}))
            self._set_status("Select a workspace run to populate the asset graph.")
            return
        graph_snapshot = self._builder.build(snapshot, self._current_options())
        self._push_graph(graph_snapshot)
        focus_text = f" Focused on {graph_snapshot.focus_node_id}." if graph_snapshot.focus_node_id else ""
        self._set_status(
            f"Showing {len(graph_snapshot.nodes)} node(s) and {len(graph_snapshot.edges)} edge(s) for {snapshot.workspace_name or 'the workspace'}."
            f"{focus_text}"
        )

    def _push_graph(self, graph_snapshot: GraphSnapshot) -> None:
        payload = graph_snapshot.to_dict()
        self._pending_payload = payload
        if hasattr(self, "fallback_label"):
            summary = graph_snapshot.summary
            self.fallback_label.setText(
                f"Graph preview unavailable here. Model contains {summary.get('node_count', 0)} node(s) "
                f"and {summary.get('edge_count', 0)} edge(s)."
            )
            return
        if self._page_ready:
            self._flush_pending_payload()

    def _flush_pending_payload(self) -> None:
        if not hasattr(self, "web_view") or not self._page_ready or self._pending_payload is None:
            return
        payload = json.dumps(self._pending_payload, sort_keys=True)
        self.web_view.page().runJavaScript(f"window.assetGraph && window.assetGraph.setGraph({payload});")

    def _handle_load_finished(self, success: bool) -> None:
        self._page_ready = bool(success)
        if success:
            self._flush_pending_payload()
        else:
            self._set_status("Graph view could not finish loading its local web assets.")

    def _handle_node_selected(self, payload: dict[str, Any]) -> None:
        self._selected_node = dict(payload)
        self._focus_node_id = str(payload.get("id") or self._focus_node_id)
        self.nodeSelected.emit(dict(payload))
        self._set_status(f"Selected {payload.get('label') or payload.get('id') or 'graph node'}.")

    def _set_status(self, text: str) -> None:
        self.graph_status.setText(text)
        self.statusChanged.emit(text)
