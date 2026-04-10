(function () {
  let bridge = null;
  let cy = null;
  let currentLayout = "dagre";

  const nodeColors = {
    workspace: "#62748e",
    scope_root: "#7d8ea8",
    domain: "#4da2ff",
    subdomain: "#6dc8ff",
    hostname: "#7bc9d4",
    ip: "#3ad1c4",
    port: "#4cc070",
    service: "#5ed37a",
    web_app: "#35b5a5",
    endpoint: "#33c2d1",
    technology: "#f2b95d",
    tool_source: "#9b8cc5",
    finding: "#ff8b5e",
    evidence_bundle: "#d6b55f",
    screenshot: "#ddc884",
    overflow: "#4b5563",
  };

  function styleForNode(nodeType) {
    return nodeColors[nodeType] || "#7f8ea3";
  }

  function buildStyles() {
    return [
      {
        selector: "node",
        style: {
          "background-color": (ele) => styleForNode(ele.data("node_type")),
          color: "#ecf3fb",
          label: "data(label)",
          "font-size": 11,
          "text-wrap": "wrap",
          "text-max-width": 110,
          "text-valign": "bottom",
          "text-margin-y": 8,
          "border-width": 1.5,
          "border-color": "#0f1724",
          width: (ele) => (ele.data("node_type") === "workspace" ? 42 : 30),
          height: (ele) => (ele.data("node_type") === "workspace" ? 42 : 30),
          shape: (ele) => {
            const type = ele.data("node_type");
            if (type === "workspace") return "round-rectangle";
            if (type === "finding") return "diamond";
            if (type === "technology") return "hexagon";
            if (type === "port") return "rectangle";
            if (type === "tool_source") return "tag";
            if (type === "overflow") return "round-rectangle";
            return "ellipse";
          },
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.7,
          "line-color": "#66819d",
          "target-arrow-color": "#66819d",
          "curve-style": "bezier",
          opacity: 0.72,
          "target-arrow-shape": "triangle",
        },
      },
      {
        selector: 'edge[style_class = "provenance-edge"]',
        style: {
          "line-style": "dashed",
          "line-color": "#9e8ee0",
          "target-arrow-color": "#9e8ee0",
          opacity: 0.65,
        },
      },
      {
        selector: 'edge[style_class = "finding-edge"]',
        style: {
          "line-color": "#ff8b5e",
          "target-arrow-color": "#ff8b5e",
          width: 2,
        },
      },
      {
        selector: 'edge[style_class = "evidence-edge"]',
        style: {
          "line-color": "#d7b45a",
          "target-arrow-color": "#d7b45a",
        },
      },
      {
        selector: "node.faded, edge.faded",
        style: {
          opacity: 0.12,
        },
      },
      {
        selector: "node.selected",
        style: {
          "border-color": "#ffffff",
          "border-width": 3,
          opacity: 1,
        },
      },
      {
        selector: "node.neighbor, edge.neighbor",
        style: {
          opacity: 1,
        },
      },
    ];
  }

  function buildLayout(name) {
    currentLayout = name || currentLayout || "dagre";
    if (currentLayout === "cose") {
      return { name: "cose", animate: false, fit: true, padding: 48 };
    }
    if (currentLayout === "concentric") {
      return { name: "concentric", animate: false, fit: true, padding: 48 };
    }
    if (cytoscape("layout", "dagre")) {
      return {
        name: "dagre",
        animate: false,
        fit: true,
        rankDir: "LR",
        nodeSep: 34,
        rankSep: 64,
        padding: 48,
      };
    }
    return { name: "breadthfirst", animate: false, fit: true, directed: true, padding: 48 };
  }

  function ensureGraph() {
    if (cy) return;
    cy = cytoscape({
      container: document.getElementById("graph"),
      elements: [],
      style: buildStyles(),
      wheelSensitivity: 0.18,
      minZoom: 0.18,
      maxZoom: 2.8,
    });
    cy.on("tap", "node", (event) => {
      selectNeighborhood(event.target);
      if (bridge && typeof bridge.onNodeSelected === "function") {
        bridge.onNodeSelected(JSON.stringify(event.target.data()));
      }
    });
  }

  function selectNeighborhood(node) {
    if (!cy) return;
    cy.elements().addClass("faded").removeClass("selected").removeClass("neighbor");
    const neighborhood = node.closedNeighborhood();
    neighborhood.removeClass("faded").addClass("neighbor");
    node.removeClass("neighbor").addClass("selected");
  }

  function setGraph(payload) {
    ensureGraph();
    if (!payload) return;
    currentLayout = payload.summary && payload.summary.layout ? payload.summary.layout : currentLayout;
    const elements = [];
    (payload.nodes || []).forEach((node) => elements.push({ data: node }));
    (payload.edges || []).forEach((edge) => elements.push({ data: edge }));
    cy.elements().remove();
    cy.add(elements);
    cy.layout(buildLayout(currentLayout)).run();
    if (payload.focus_node_id) {
      const focus = cy.getElementById(payload.focus_node_id);
      if (focus && focus.length) {
        selectNeighborhood(focus);
        cy.animate({ center: { eles: focus }, zoom: Math.min(cy.maxZoom(), 1.1) }, { duration: 180 });
      }
    } else {
      cy.elements().removeClass("faded").removeClass("selected").removeClass("neighbor");
      cy.fit(cy.elements(), 42);
    }
  }

  function centerOnSelection() {
    if (!cy) return;
    const selected = cy.nodes(".selected");
    if (selected.length) {
      cy.animate({ center: { eles: selected } }, { duration: 180 });
    } else {
      cy.fit(cy.elements(), 42);
    }
  }

  function resetLayout() {
    if (!cy) return;
    cy.elements().removeClass("faded").removeClass("selected").removeClass("neighbor");
    cy.layout(buildLayout(currentLayout)).run();
  }

  window.assetGraph = {
    setGraph,
    centerOnSelection,
    resetLayout,
  };

  new QWebChannel(qt.webChannelTransport, function (channel) {
    bridge = channel.objects.attackcastleBridge || null;
    ensureGraph();
    if (bridge && typeof bridge.onGraphReady === "function") {
      bridge.onGraphReady();
    }
  });
})();
