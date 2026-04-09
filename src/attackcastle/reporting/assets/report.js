function severityColor(key) {
  const colors = {
    critical: "#b42318",
    high: "#d9480f",
    medium: "#f08c00",
    low: "#2b8a3e",
    info: "#495057"
  };
  return colors[key] || "#0b7285";
}

function drawBarChart(containerId, items) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }
  if (!items || items.length === 0) {
    container.innerHTML = "<p class=\"muted\">No chart data available.</p>";
    return;
  }
  const maxValue = Math.max(...items.map((item) => item.value), 1);
  container.innerHTML = "";
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "bar-row";

    const label = document.createElement("div");
    label.className = "label";
    label.textContent = `${item.label}: ${item.value}`;

    const track = document.createElement("div");
    track.className = "track";

    const fill = document.createElement("div");
    fill.className = "fill";
    fill.style.width = `${(item.value / maxValue) * 100}%`;
    fill.style.backgroundColor = item.color || "#0b7285";

    track.appendChild(fill);
    row.appendChild(label);
    row.appendChild(track);
    container.appendChild(row);
  });
}

function makeTableSortable(table) {
  const headers = table.querySelectorAll("th");
  headers.forEach((header, index) => {
    header.addEventListener("click", () => {
      const tbody = table.querySelector("tbody");
      if (!tbody) {
        return;
      }
      const rows = Array.from(tbody.querySelectorAll("tr"));
      const asc = header.dataset.sortDir !== "asc";
      headers.forEach((h) => {
        delete h.dataset.sortDir;
      });
      header.dataset.sortDir = asc ? "asc" : "desc";
      rows.sort((a, b) => {
        const aText = (a.children[index]?.innerText || "").trim();
        const bText = (b.children[index]?.innerText || "").trim();
        const aNum = Number(aText.replace(/[^0-9.-]/g, ""));
        const bNum = Number(bText.replace(/[^0-9.-]/g, ""));
        if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && aText !== "" && bText !== "") {
          return asc ? aNum - bNum : bNum - aNum;
        }
        return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
      });
      rows.forEach((row) => tbody.appendChild(row));
    });
  });
}

function applyFindingFilters() {
  const severityFilter = document.getElementById("finding-severity-filter");
  const statusFilter = document.getElementById("finding-status-filter");
  if (!severityFilter || !statusFilter) {
    return;
  }
  const severity = severityFilter.value;
  const status = statusFilter.value;
  const rows = document.querySelectorAll("[data-finding-severity][data-finding-status]");
  rows.forEach((row) => {
    const rowSeverity = row.getAttribute("data-finding-severity");
    const rowStatus = row.getAttribute("data-finding-status");
    const severityOk = severity === "all" || rowSeverity === severity;
    const statusOk = status === "all" || rowStatus === status;
    row.style.display = severityOk && statusOk ? "" : "none";
  });
}

function initFindingsFilters() {
  const severityFilter = document.getElementById("finding-severity-filter");
  const statusFilter = document.getElementById("finding-status-filter");
  const reset = document.getElementById("finding-filter-reset");
  if (!severityFilter || !statusFilter || !reset) {
    return;
  }
  severityFilter.addEventListener("change", applyFindingFilters);
  statusFilter.addEventListener("change", applyFindingFilters);
  reset.addEventListener("click", () => {
    severityFilter.value = "all";
    statusFilter.value = "all";
    applyFindingFilters();
  });
  applyFindingFilters();
}

function runCharts() {
  const node = document.getElementById("chart-data");
  if (!node) {
    return;
  }
  const payload = JSON.parse(node.textContent);
  const severityCounts = payload.severityCounts || {};
  const serviceDistribution = payload.serviceDistribution || [];
  const riskDomains = payload.riskDomains || [];
  const serviceExposure = payload.serviceExposureBreakdown || [];
  const trendHistory = payload.trendHistory || [];

  drawBarChart(
    "severity-chart",
    Object.keys(severityCounts).map((key) => ({
      label: key.toUpperCase(),
      value: severityCounts[key],
      color: severityColor(key)
    }))
  );
  drawBarChart(
    "service-chart",
    serviceDistribution.slice(0, 12).map((item) => ({
      label: item.name,
      value: item.count,
      color: "#0b7285"
    }))
  );
  drawBarChart(
    "domain-chart",
    riskDomains.map((item) => ({
      label: item.domain.toUpperCase(),
      value: item.score,
      color: "#1f8a70"
    }))
  );
  drawBarChart(
    "service-exposure-chart",
    serviceExposure.map((item) => ({
      label: item.category.toUpperCase(),
      value: item.count,
      color: "#155e75"
    }))
  );
  drawBarChart(
    "trend-chart",
    trendHistory.map((item) => ({
      label: item.run_id,
      value: item.risk_score,
      color: "#5c7cfa"
    }))
  );
}

function initSortableTables() {
  document.querySelectorAll("table.sortable").forEach((table) => makeTableSortable(table));
}

function sectionGroup(sectionId) {
  const node = document.querySelector(`[data-section-id="${sectionId}"]`);
  return node ? (node.getAttribute("data-section-group") || "other") : "other";
}

function applySectionFilters() {
  const active = document.querySelector(".tab-btn.active");
  const tab = active ? active.getAttribute("data-tab") : "all";
  const pivotInput = document.getElementById("pivot-filter");
  const term = pivotInput ? pivotInput.value.trim().toLowerCase() : "";
  document.querySelectorAll(".report-section").forEach((section) => {
    const group = section.getAttribute("data-section-group") || "other";
    const inTab = tab === "all" || group === tab;
    const inPivot = !term || (section.innerText || "").toLowerCase().includes(term);
    section.style.display = inTab && inPivot ? "" : "none";
  });
}

function initSectionTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  if (!buttons.length) {
    return;
  }
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      buttons.forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      applySectionFilters();
    });
  });
}

function initPivotFilter() {
  const input = document.getElementById("pivot-filter");
  const reset = document.getElementById("pivot-filter-reset");
  if (!input || !reset) {
    return;
  }
  input.addEventListener("input", applySectionFilters);
  reset.addEventListener("click", () => {
    input.value = "";
    applySectionFilters();
  });
}

function initCopyCommand() {
  document.querySelectorAll(".copy-command").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.getAttribute("data-command") || "";
      if (!value) {
        return;
      }
      try {
        await navigator.clipboard.writeText(value);
        button.innerText = "Copied";
        setTimeout(() => {
          button.innerText = "Copy command";
        }, 1000);
      } catch {
        button.innerText = "Copy failed";
        setTimeout(() => {
          button.innerText = "Copy command";
        }, 1000);
      }
    });
  });
}

function initHostNotes() {
  document.querySelectorAll(".host-note").forEach((node) => {
    const key = node.getAttribute("data-notes-key");
    if (!key) {
      return;
    }
    const storageKey = `attackcastle-note:${key}`;
    const saved = window.localStorage.getItem(storageKey);
    if (saved) {
      node.value = saved;
    }
    node.addEventListener("input", () => {
      window.localStorage.setItem(storageKey, node.value);
    });
  });
}

function initSectionToggles() {
  const expandButton = document.getElementById("expand-sections");
  const collapseButton = document.getElementById("collapse-sections");
  if (!expandButton || !collapseButton) {
    return;
  }
  expandButton.addEventListener("click", () => {
    document.querySelectorAll(".section-shell").forEach((node) => {
      node.open = true;
    });
  });
  collapseButton.addEventListener("click", () => {
    document.querySelectorAll(".section-shell").forEach((node) => {
      const section = node.closest(".report-section");
      if (!section) {
        node.open = false;
        return;
      }
      const group = section.getAttribute("data-section-group") || "other";
      node.open = group === "overview" || group === "findings";
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  runCharts();
  initSortableTables();
  initFindingsFilters();
  initSectionTabs();
  initPivotFilter();
  initSectionToggles();
  initCopyCommand();
  initHostNotes();
  applySectionFilters();
});
