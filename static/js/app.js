/**
 * app.js - UniPort Monitor Client-Side Dashboard Controller
 * =========================================================
 * Manages periodic 1s data polling, Chart.js visualizations, connection filtering,
 * interactive controls, security alerts, and theme switching.
 */

// State Management
const state = {
  mode: "demo",              // "demo" | "live"
  isPaused: false,
  pollInterval: null,
  activeInterface: "default",
  theme: localStorage.getItem("uniport_theme") || "dark",
  charts: {
    categories: null,
    topApps: null,
    throughput: null
  }
};

// Category Color Palette for Charts & Chips
const CATEGORY_COLORS = {
  "Web": "#6366f1",
  "Campus-Specific": "#ec4899",
  "Network Services": "#06b6d4",
  "Remote Access": "#f59e0b",
  "Database": "#a855f7",
  "Email": "#3b82f6",
  "File Transfer": "#14b8a6",
  "Streaming/VoIP": "#ef4444",
  "Unknown": "#eab308"
};

// Initialize Application on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initCharts();
  bindEventHandlers();
  loadInterfaces();
  startPolling();
});

/* ==========================================================================
   Theme Management
   ========================================================================== */
function initTheme() {
  document.documentElement.setAttribute("data-theme", state.theme);
  updateThemeIcon();
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", state.theme);
  localStorage.setItem("uniport_theme", state.theme);
  updateThemeIcon();
  updateChartsTheme();
}

function updateThemeIcon() {
  const icon = document.getElementById("theme-icon");
  if (icon) {
    icon.textContent = state.theme === "dark" ? "🌙" : "☀️";
  }
}

function getChartColors() {
  const isDark = state.theme === "dark";
  return {
    text: isDark ? "#94a3b8" : "#475569",
    grid: isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)",
    cardBg: isDark ? "#111827" : "#ffffff"
  };
}

/* ==========================================================================
   Chart.js Initialization
   ========================================================================== */
function initCharts() {
  const colors = getChartColors();

  // 1. Category Distribution (Doughnut)
  const ctxCat = document.getElementById("chart-categories")?.getContext("2d");
  if (ctxCat) {
    state.charts.categories = new Chart(ctxCat, {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [],
          borderWidth: 2,
          borderColor: colors.cardBg,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: {
            position: "right",
            labels: {
              color: colors.text,
              font: { family: "'Outfit', sans-serif", size: 11 },
              boxWidth: 12,
              padding: 8
            }
          }
        }
      }
    });
  }

  // 2. Top 10 Applications (Horizontal/Vertical Bar)
  const ctxApps = document.getElementById("chart-top-apps")?.getContext("2d");
  if (ctxApps) {
    state.charts.topApps = new Chart(ctxApps, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Packets",
          data: [],
          backgroundColor: "#6366f1",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            ticks: { color: colors.text, font: { size: 10 } },
            grid: { display: false }
          },
          y: {
            beginAtZero: true,
            ticks: { color: colors.text, font: { size: 10 } },
            grid: { color: colors.grid }
          }
        }
      }
    });
  }

  // 3. Real-Time Throughput PPS (Line Chart)
  const ctxPps = document.getElementById("chart-throughput")?.getContext("2d");
  if (ctxPps) {
    state.charts.throughput = new Chart(ctxPps, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Packets/Sec",
          data: [],
          borderColor: "#06b6d4",
          backgroundColor: "rgba(6, 182, 212, 0.12)",
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            ticks: {
              color: colors.text,
              font: { size: 9 },
              maxTicksLimit: 6
            },
            grid: { display: false }
          },
          y: {
            beginAtZero: true,
            ticks: { color: colors.text, font: { size: 10 } },
            grid: { color: colors.grid }
          }
        },
        animation: { duration: 400 }
      }
    });
  }
}

function updateChartsTheme() {
  const colors = getChartColors();
  Object.values(state.charts).forEach(chart => {
    if (!chart) return;
    if (chart.options.plugins?.legend?.labels) {
      chart.options.plugins.legend.labels.color = colors.text;
    }
    if (chart.options.scales) {
      if (chart.options.scales.x) {
        chart.options.scales.x.ticks.color = colors.text;
        if (chart.options.scales.x.grid) chart.options.scales.x.grid.color = colors.grid;
      }
      if (chart.options.scales.y) {
        chart.options.scales.y.ticks.color = colors.text;
        if (chart.options.scales.y.grid) chart.options.scales.y.grid.color = colors.grid;
      }
    }
    chart.update();
  });
}

/* ==========================================================================
   Data Fetching & Live Polling (1s Interval)
   ========================================================================== */
function startPolling() {
  if (state.pollInterval) clearInterval(state.pollInterval);
  // Immediate initial load
  fetchDashboardData();
  // Poll every 1000ms
  state.pollInterval = setInterval(fetchDashboardData, 1000);
}

async function fetchDashboardData() {
  if (state.isPaused) return;

  try {
    await Promise.all([
      fetchConnections(),
      fetchStats(),
      fetchAlerts()
    ]);
  } catch (err) {
    console.error("[UniPort] Polling error:", err);
  }
}

// 1. Fetch Connections Table Data with Active Filters
async function fetchConnections() {
  const params = new URLSearchParams();
  const search = document.getElementById("filter-search")?.value.trim();
  const proto = document.getElementById("filter-protocol")?.value;
  const cat = document.getElementById("filter-category")?.value;
  const port = document.getElementById("filter-port")?.value.trim();

  if (search) params.append("q", search);
  if (proto) params.append("protocol", proto);
  if (cat) params.append("category", cat);
  if (port) params.append("port", port);
  params.append("limit", "200");

  const res = await fetch(`/api/connections?${params.toString()}`);
  if (!res.ok) return;
  const json = await res.json();
  renderConnectionsTable(json.connections || []);
}

// 2. Fetch Aggregated Statistics and Chart Datasets
async function fetchStats() {
  const res = await fetch("/api/stats");
  if (!res.ok) return;
  const json = await res.json();
  const s = json.stats;
  if (!s) return;

  // Update Summary Metric Cards
  setText("stat-total-packets", s.total_packets.toLocaleString());
  setText("stat-active-conns", s.active_connections.toLocaleString());
  setText("stat-unique-apps", s.unique_applications);
  setText("stat-tcp-count", s.tcp_count.toLocaleString());
  setText("stat-udp-count", s.udp_count.toLocaleString());
  setText("stat-unknown-count", s.unknown_count.toLocaleString());
  setText("header-pps", `${s.throughput?.current_pps || 0} pkt/s`);

  // Update Doughnut Chart (Categories)
  if (state.charts.categories && s.categories) {
    const labels = s.categories.map(c => c.category);
    const data = s.categories.map(c => c.count);
    const bgColors = labels.map(l => CATEGORY_COLORS[l] || "#94a3b8");

    state.charts.categories.data.labels = labels;
    state.charts.categories.data.datasets[0].data = data;
    state.charts.categories.data.datasets[0].backgroundColor = bgColors;
    state.charts.categories.update("none");
  }

  // Update Bar Chart (Top 10 Apps)
  if (state.charts.topApps && s.top_apps) {
    const labels = s.top_apps.map(a => a.app_name);
    const data = s.top_apps.map(a => a.count);
    const bgColors = s.top_apps.map(a => CATEGORY_COLORS[a.category] || "#6366f1");

    state.charts.topApps.data.labels = labels;
    state.charts.topApps.data.datasets[0].data = data;
    state.charts.topApps.data.datasets[0].backgroundColor = bgColors;
    state.charts.topApps.update("none");
  }

  // Update Line Chart (Throughput PPS)
  if (state.charts.throughput && s.throughput) {
    state.charts.throughput.data.labels = s.throughput.labels;
    state.charts.throughput.data.datasets[0].data = s.throughput.data;
    state.charts.throughput.update("none");
  }
}

// 3. Fetch Alerts Feed
async function fetchAlerts() {
  const res = await fetch("/api/alerts?limit=30");
  if (!res.ok) return;
  const json = await res.json();
  renderAlertsFeed(json.alerts || []);
}

/* ==========================================================================
   Table & Alert Rendering
   ========================================================================== */
function renderConnectionsTable(rows) {
  const tbody = document.getElementById("connections-tbody");
  const countLabel = document.getElementById("table-row-count");
  if (!tbody) return;

  if (countLabel) {
    countLabel.textContent = `Showing ${rows.length} connection${rows.length === 1 ? '' : 's'}`;
  }

  if (rows.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-state-row">
        <td colspan="9">
          <div class="empty-table-state">
            <span>No connections match your filters.</span>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  const html = rows.map(r => {
    const isUnknown = r.is_unknown || r.category === "Unknown";
    const rowClass = isUnknown ? 'class="row-unknown"' : '';
    const protoBadge = r.protocol === 'TCP'
      ? '<span class="proto-badge proto-tcp">TCP</span>'
      : '<span class="proto-badge proto-udp">UDP</span>';

    const catClass = getCategoryClass(r.category);

    return `
      <tr ${rowClass}>
        <td class="time-mono">${escapeHtml(r.timestamp)}</td>
        <td class="ip-mono">${escapeHtml(r.src_ip)}</td>
        <td class="port-mono">${r.src_port}</td>
        <td class="ip-mono">${escapeHtml(r.dst_ip)}</td>
        <td class="port-mono">${r.dst_port}</td>
        <td>${protoBadge}</td>
        <td><strong class="app-highlight">${escapeHtml(r.app_name)}</strong></td>
        <td><span class="cat-chip ${catClass}">${escapeHtml(r.category)}</span></td>
        <td class="time-mono">${r.packet_size} B</td>
      </tr>
    `;
  }).join("");

  tbody.innerHTML = html;
}

function renderAlertsFeed(alerts) {
  const feed = document.getElementById("alerts-feed");
  const badge = document.getElementById("alerts-count-badge");
  if (!feed) return;

  if (badge) {
    badge.textContent = `${alerts.length} Alert${alerts.length === 1 ? '' : 's'}`;
  }

  if (alerts.length === 0) {
    feed.innerHTML = '<div class="empty-alerts">No alerts triggered yet. System nominal.</div>';
    return;
  }

  feed.innerHTML = alerts.map(a => {
    let sevClass = "severity-info";
    let badgeClass = "alert-badge-info";

    if (a.severity === "Warning" || a.alert_type === "Insecure Protocol") {
      sevClass = "severity-warning";
      badgeClass = "alert-badge-warning";
    } else if (a.alert_type === "Port Scan Detected") {
      sevClass = "severity-danger";
      badgeClass = "alert-badge-danger";
    }

    return `
      <div class="alert-item ${sevClass}">
        <span class="alert-badge ${badgeClass}">${escapeHtml(a.severity)}</span>
        <div class="alert-content">
          <div class="alert-msg">${escapeHtml(a.message)}</div>
          <div class="alert-time">${escapeHtml(a.timestamp)} • ${escapeHtml(a.alert_type)}</div>
        </div>
      </div>
    `;
  }).join("");
}

function getCategoryClass(category) {
  switch (category) {
    case "Web": return "cat-web";
    case "Campus-Specific": return "cat-campus";
    case "Network Services": return "cat-network";
    case "Remote Access": return "cat-remote";
    case "Database": return "cat-db";
    case "Email": return "cat-email";
    case "File Transfer": return "cat-file";
    case "Streaming/VoIP": return "cat-media";
    default: return "cat-unknown";
  }
}

/* ==========================================================================
   Interactive Controls & Event Listeners
   ========================================================================== */
function bindEventHandlers() {
  // Theme Toggle
  document.getElementById("btn-theme-toggle")?.addEventListener("click", toggleTheme);

  // Play / Pause Toggle
  document.getElementById("btn-toggle-capture")?.addEventListener("click", toggleCapture);

  // Clear Data
  document.getElementById("btn-clear-data")?.addEventListener("click", clearData);

  // Mode Switching
  document.getElementById("btn-mode-demo")?.addEventListener("click", () => switchMode("demo"));
  document.getElementById("btn-mode-live")?.addEventListener("click", () => switchMode("live"));

  // Interface Selection
  document.getElementById("select-interface")?.addEventListener("change", (e) => {
    state.activeInterface = e.target.value;
    if (state.mode === "live") {
      switchMode("live", state.activeInterface);
    }
  });

  // Filter Event Listeners (Debounced Search)
  const debounce = (fn, delay = 300) => {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  };

  const triggerFilter = debounce(fetchConnections, 200);
  document.getElementById("filter-search")?.addEventListener("input", triggerFilter);
  document.getElementById("filter-port")?.addEventListener("input", triggerFilter);
  document.getElementById("filter-protocol")?.addEventListener("change", fetchConnections);
  document.getElementById("filter-category")?.addEventListener("change", fetchConnections);

  // Reset Filters Button
  document.getElementById("btn-reset-filters")?.addEventListener("click", () => {
    setVal("filter-search", "");
    setVal("filter-port", "");
    setVal("filter-protocol", "");
    setVal("filter-category", "");
    fetchConnections();
  });

  // Download CSV
  document.getElementById("btn-export-csv")?.addEventListener("click", exportCsv);

  // Port Lookup Tool
  document.getElementById("btn-do-lookup")?.addEventListener("click", doPortLookup);
  document.getElementById("lookup-port-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") doPortLookup();
  });
}

async function loadInterfaces() {
  try {
    const res = await fetch("/api/interfaces");
    if (!res.ok) return;
    const json = await res.json();
    const select = document.getElementById("select-interface");
    if (!select || !json.interfaces) return;

    select.innerHTML = json.interfaces.map(iface => `
      <option value="${escapeHtml(iface.id)}">${escapeHtml(iface.name)}</option>
    `).join("");
  } catch (e) {
    console.error("Failed to load interfaces:", e);
  }
}

async function switchMode(mode, iface = null) {
  state.mode = mode;
  const btnDemo = document.getElementById("btn-mode-demo");
  const btnLive = document.getElementById("btn-mode-live");
  const ifaceWrap = document.getElementById("interface-select-wrap");
  const modeText = document.getElementById("status-mode-text");

  if (mode === "live") {
    btnLive?.classList.add("active");
    btnDemo?.classList.remove("active");
    ifaceWrap?.classList.remove("hidden");
    if (modeText) modeText.textContent = "LIVE MODE (Scapy Packet Capture)";
  } else {
    btnDemo?.classList.add("active");
    btnLive?.classList.remove("active");
    ifaceWrap?.classList.add("hidden");
    if (modeText) modeText.textContent = "DEMO MODE (Simulated Campus Traffic)";
  }

  try {
    const res = await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: mode,
        interface: iface || state.activeInterface
      })
    });
    const json = await res.json();
    if (json.status === "error") {
      alert(json.message);
      // Fall back to demo UI
      switchMode("demo");
    }
  } catch (err) {
    console.error("Mode switch failed:", err);
  }
}

async function toggleCapture() {
  state.isPaused = !state.isPaused;
  const btn = document.getElementById("btn-toggle-capture");
  const icon = document.getElementById("capture-icon");
  const label = document.getElementById("capture-label");
  const statusLabel = document.getElementById("engine-status");

  if (state.isPaused) {
    if (icon) icon.textContent = "▶️";
    if (label) label.textContent = "Resume";
    if (btn) btn.className = "btn btn-secondary";
    if (statusLabel) statusLabel.textContent = "Paused";

    await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "pause" })
    });
  } else {
    if (icon) icon.textContent = "⏸";
    if (label) label.textContent = "Pause";
    if (btn) btn.className = "btn btn-primary";
    if (statusLabel) statusLabel.textContent = "Running";

    await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "resume" })
    });
  }
}

async function clearData() {
  if (!confirm("Clear all captured packets and alerts?")) return;
  try {
    await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "clear" })
    });
    fetchDashboardData();
  } catch (err) {
    console.error("Clear error:", err);
  }
}

function exportCsv() {
  const params = new URLSearchParams();
  const search = document.getElementById("filter-search")?.value.trim();
  const proto = document.getElementById("filter-protocol")?.value;
  const cat = document.getElementById("filter-category")?.value;
  const port = document.getElementById("filter-port")?.value.trim();

  if (search) params.append("q", search);
  if (proto) params.append("protocol", proto);
  if (cat) params.append("category", cat);
  if (port) params.append("port", port);

  window.location.href = `/api/export.csv?${params.toString()}`;
}

async function doPortLookup() {
  const portInput = document.getElementById("lookup-port-input");
  const protoSelect = document.getElementById("lookup-proto-select");
  const resultBox = document.getElementById("lookup-result-box");
  if (!portInput || !resultBox) return;

  const portVal = parseInt(portInput.value, 10);
  if (!portVal || isNaN(portVal) || portVal < 1 || portVal > 65535) {
    resultBox.innerHTML = '<div class="lookup-placeholder" style="color:var(--accent-rose)">Please enter a valid port number (1 - 65535).</div>';
    return;
  }

  const protoVal = protoSelect?.value || "";
  resultBox.innerHTML = '<span class="loader-spinner"></span>';

  try {
    const url = `/api/port/${portVal}${protoVal ? '?protocol=' + protoVal : ''}`;
    const res = await fetch(url);
    const json = await res.json();
    const data = json.data;

    if (!data) {
      resultBox.innerHTML = '<div class="lookup-placeholder">No data found.</div>';
      return;
    }

    const catClass = getCategoryClass(data.category);
    resultBox.innerHTML = `
      <div class="lookup-result-card">
        <div class="lookup-res-header">
          <span class="lookup-res-name">${escapeHtml(data.name)}</span>
          <span class="cat-chip ${catClass}">${escapeHtml(data.category)}</span>
        </div>
        <div style="font-size:0.8rem; color:var(--text-secondary);">
          <strong>Port:</strong> ${data.port} / ${escapeHtml(data.protocol)}
        </div>
        <div class="lookup-res-desc">${escapeHtml(data.description || 'Standard university port registration.')}</div>
      </div>
    `;
  } catch (e) {
    resultBox.innerHTML = `<div class="lookup-placeholder" style="color:var(--accent-rose)">Lookup failed: ${e}</div>`;
  }
}

/* ==========================================================================
   Utilities
   ========================================================================== */
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
