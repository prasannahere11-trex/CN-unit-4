/**
 * app.js - UniPort Monitor Client-Side & Hybrid Dashboard Controller
 * =================================================================
 * Supports both:
 * 1. Live Python/Flask backend with Scapy live packet sniffing & SQLite
 * 2. Standalone static execution on GitHub Pages with built-in client simulation
 */

// Application State
const state = {
  mode: "demo",              // "demo" | "live"
  isPaused: false,
  pollInterval: null,
  activeInterface: "default",
  theme: localStorage.getItem("uniport_theme") || "dark",
  isStaticMode: false,       // true when deployed to GitHub Pages / no backend
  simPackets: [],
  simAlerts: [],
  simCounter: 0,
  charts: {
    categories: null,
    topApps: null,
    throughput: null
  }
};

// Embedded Port Database for Zero-Latency Client & Static GitHub Pages Support
const PORT_DATABASE = [
  { port: 80, protocol: "TCP", name: "HTTP", category: "Web", description: "Hypertext Transfer Protocol (Unencrypted Web)" },
  { port: 443, protocol: "TCP", name: "HTTPS", category: "Web", description: "Hypertext Transfer Protocol Secure (TLS/SSL Encrypted Web)" },
  { port: 443, protocol: "UDP", name: "HTTP/3 (QUIC)", category: "Web", description: "HTTP/3 Quick UDP Internet Connections (Modern Web & YouTube)" },
  { port: 8080, protocol: "TCP", name: "HTTP-Alt", category: "Web", description: "Alternative HTTP port commonly used for web caches and dev servers" },
  { port: 8443, protocol: "TCP", name: "HTTPS-Alt", category: "Web", description: "Alternative HTTPS / Tomcat / Admin Web Portal" },
  { port: 3128, protocol: "TCP", name: "Squid Proxy", category: "Web", description: "Squid Web Caching Proxy server widely used in campus networks" },
  { port: 8000, protocol: "TCP", name: "HTTP-Dev", category: "Web", description: "Common development web server port (Django, Python http.server)" },
  { port: 5000, protocol: "TCP", name: "Flask / Node App", category: "Web", description: "Common development server port for Flask and internal services" },
  { port: 25, protocol: "TCP", name: "SMTP", category: "Email", description: "Simple Mail Transfer Protocol (MTA server-to-server relay)" },
  { port: 465, protocol: "TCP", name: "SMTPS", category: "Email", description: "Secure SMTP over SSL wrapper for email submission" },
  { port: 587, protocol: "TCP", name: "SMTP Submission", category: "Email", description: "Standard authenticated email submission with STARTTLS" },
  { port: 110, protocol: "TCP", name: "POP3", category: "Email", description: "Post Office Protocol v3 for unencrypted email retrieval" },
  { port: 995, protocol: "TCP", name: "POP3S", category: "Email", description: "Post Office Protocol v3 over TLS/SSL encryption" },
  { port: 143, protocol: "TCP", name: "IMAP", category: "Email", description: "Internet Message Access Protocol for email sync" },
  { port: 993, protocol: "TCP", name: "IMAPS", category: "Email", description: "Internet Message Access Protocol over TLS/SSL encryption" },
  { port: 20, protocol: "TCP", name: "FTP-Data", category: "File Transfer", description: "File Transfer Protocol (Active Data Channel)" },
  { port: 21, protocol: "TCP", name: "FTP-Control", category: "File Transfer", description: "File Transfer Protocol (Command/Control Channel - Insecure)" },
  { port: 22, protocol: "TCP", name: "SSH / SFTP", category: "Remote Access", description: "Secure Shell remote terminal and SFTP encrypted file transfer" },
  { port: 23, protocol: "TCP", name: "Telnet", category: "Remote Access", description: "Legacy unencrypted remote terminal protocol (Security Risk)" },
  { port: 69, protocol: "UDP", name: "TFTP", category: "File Transfer", description: "Trivial File Transfer Protocol used for PXE network booting & routers" },
  { port: 137, protocol: "UDP", name: "NetBIOS-NS", category: "File Transfer", description: "NetBIOS Name Service for Windows network discovery" },
  { port: 138, protocol: "UDP", name: "NetBIOS-DGM", category: "File Transfer", description: "NetBIOS Datagram Service for Windows file sharing" },
  { port: 139, protocol: "TCP", name: "NetBIOS-SSN", category: "File Transfer", description: "NetBIOS Session Service for legacy Windows file sharing" },
  { port: 445, protocol: "TCP", name: "SMB / CIFS", category: "File Transfer", description: "Server Message Block for Windows network file & printer sharing" },
  { port: 3389, protocol: "TCP", name: "RDP", category: "Remote Access", description: "Microsoft Remote Desktop Protocol for graphical desktop access" },
  { port: 5900, protocol: "TCP", name: "VNC", category: "Remote Access", description: "Virtual Network Computing remote frame buffer display" },
  { port: 53, protocol: "UDP", name: "DNS", category: "Network Services", description: "Domain Name System standard queries (UDP)" },
  { port: 53, protocol: "TCP", name: "DNS Zone Transfer", category: "Network Services", description: "Domain Name System large responses or zone transfers (TCP)" },
  { port: 67, protocol: "UDP", name: "DHCP Server", category: "Network Services", description: "Bootstrap Protocol / DHCP Server listening port" },
  { port: 68, protocol: "UDP", name: "DHCP Client", category: "Network Services", description: "Bootstrap Protocol / DHCP Client listening port" },
  { port: 123, protocol: "UDP", name: "NTP", category: "Network Services", description: "Network Time Protocol for clock synchronization" },
  { port: 161, protocol: "UDP", name: "SNMP", category: "Network Services", description: "Simple Network Management Protocol for router/switch monitoring" },
  { port: 389, protocol: "TCP", name: "LDAP", category: "Network Services", description: "Lightweight Directory Access Protocol for directory lookups" },
  { port: 636, protocol: "TCP", name: "LDAPS", category: "Network Services", description: "Lightweight Directory Access Protocol over TLS/SSL" },
  { port: 1812, protocol: "UDP", name: "RADIUS Auth", category: "Campus-Specific", description: "RADIUS Authentication server for Eduroam / 802.1X Wi-Fi login" },
  { port: 1813, protocol: "UDP", name: "RADIUS Acct", category: "Campus-Specific", description: "RADIUS Accounting server for session tracking on campus networks" },
  { port: 88, protocol: "TCP", name: "Kerberos", category: "Campus-Specific", description: "Kerberos Network Authentication Protocol (Single Sign-On / Active Directory)" },
  { port: 88, protocol: "UDP", name: "Kerberos", category: "Campus-Specific", description: "Kerberos Ticket Granting Service over UDP" },
  { port: 3306, protocol: "TCP", name: "MySQL", category: "Database", description: "MySQL / MariaDB database server connection" },
  { port: 5432, protocol: "TCP", name: "PostgreSQL", category: "Database", description: "PostgreSQL database server connection" },
  { port: 1521, protocol: "TCP", name: "Oracle DB", category: "Database", description: "Oracle Database listener service" },
  { port: 1433, protocol: "TCP", name: "MS-SQL", category: "Database", description: "Microsoft SQL Server database listener" },
  { port: 27017, protocol: "TCP", name: "MongoDB", category: "Database", description: "MongoDB NoSQL document database listener" },
  { port: 6379, protocol: "TCP", name: "Redis", category: "Database", description: "Redis in-memory key-value cache and message broker" },
  { port: 5060, protocol: "UDP", name: "SIP", category: "Streaming/VoIP", description: "Session Initiation Protocol for campus IP phones & VoIP" },
  { port: 5061, protocol: "TCP", name: "SIP-TLS", category: "Streaming/VoIP", description: "Encrypted Session Initiation Protocol for secure voice calls" },
  { port: 1935, protocol: "TCP", name: "RTMP", category: "Streaming/VoIP", description: "Real-Time Messaging Protocol for live lecture video streaming" },
  { port: 3478, protocol: "UDP", name: "STUN", category: "Streaming/VoIP", description: "Session Traversal Utilities for NAT (WebRTC / Zoom / Teams)" },
  { port: 5004, protocol: "UDP", name: "RTP", category: "Streaming/VoIP", description: "Real-time Transport Protocol media stream for voice and video" }
];

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

// Client-Side Port Resolver
function resolvePortClient(srcPort, dstPort, protocol) {
  const proto = (protocol || "TCP").toUpperCase();
  
  const dstMatch = PORT_DATABASE.find(p => p.port === dstPort && (p.protocol === proto || !p.protocol)) ||
                   PORT_DATABASE.find(p => p.port === dstPort);
  const srcMatch = PORT_DATABASE.find(p => p.port === srcPort && (p.protocol === proto || !p.protocol)) ||
                   PORT_DATABASE.find(p => p.port === srcPort);

  if (dstMatch && srcMatch) {
    const chosen = dstPort <= srcPort ? dstMatch : srcMatch;
    return { application: chosen.name, category: chosen.category, description: chosen.description, is_known: true };
  }
  if (dstMatch) return { application: dstMatch.name, category: dstMatch.category, description: dstMatch.description, is_known: true };
  if (srcMatch) return { application: srcMatch.name, category: srcMatch.category, description: srcMatch.description, is_known: true };

  const primaryPort = Math.min(srcPort, dstPort);
  return { application: `Unknown (Port ${primaryPort})`, category: "Unknown", description: `Unregistered port (${proto}/${primaryPort})`, is_known: false };
}

// Client-Side Traffic Generator (for GitHub Pages static demo)
function generateClientPacket() {
  const campusSubnets = ["10.20.", "10.10.", "10.30.", "10.40."];
  const srcIp = `${campusSubnets[Math.floor(Math.random() * campusSubnets.length)]}${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 2}`;
  const srcPort = Math.floor(Math.random() * (65535 - 49152)) + 49152;
  
  const sampleApps = [
    { name: "HTTPS", dstPort: 443, proto: "TCP", cat: "Web" },
    { name: "HTTP/3 (QUIC)", dstPort: 443, proto: "UDP", cat: "Web" },
    { name: "DNS", dstPort: 53, proto: "UDP", cat: "Network Services" },
    { name: "RADIUS Auth", dstPort: 1812, proto: "UDP", cat: "Campus-Specific" },
    { name: "SSH / SFTP", dstPort: 22, proto: "TCP", cat: "Remote Access" },
    { name: "MySQL", dstPort: 3306, proto: "TCP", cat: "Database" },
    { name: "IMAPS", dstPort: 993, proto: "TCP", cat: "Email" },
    { name: "STUN", dstPort: 3478, proto: "UDP", cat: "Streaming/VoIP" },
    { name: "Telnet", dstPort: 23, proto: "TCP", cat: "Remote Access" },
    { name: "FTP-Control", dstPort: 21, proto: "TCP", cat: "File Transfer" },
    { name: "Unknown", dstPort: 7777, proto: "TCP", cat: "Unknown" }
  ];

  const weights = [35, 15, 18, 10, 8, 5, 4, 6, 2, 2, 3];
  let totalWeight = weights.reduce((a, b) => a + b, 0);
  let randomVal = Math.random() * totalWeight;
  let chosen = sampleApps[0];
  
  for (let i = 0; i < sampleApps.length; i++) {
    if (randomVal < weights[i]) { chosen = sampleApps[i]; break; }
    randomVal -= weights[i];
  }

  let dstIp = "142.250.190.46";
  if (chosen.name === "RADIUS Auth") dstIp = "172.16.1.20";
  else if (chosen.name === "DNS") dstIp = "172.16.1.10";
  else if (chosen.name === "MySQL") dstIp = "172.16.1.100";
  else if (chosen.name === "Telnet" || chosen.name === "FTP-Control") dstIp = "10.30.0.15";

  const resolved = resolvePortClient(srcPort, chosen.dstPort, chosen.proto);
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];

  const pkt = {
    id: Date.now() + Math.random(),
    timestamp: timeStr,
    epoch_time: Date.now() / 1000,
    src_ip: srcIp,
    src_port: srcPort,
    dst_ip: dstIp,
    dst_port: chosen.dstPort,
    protocol: chosen.proto,
    app_name: resolved.application,
    category: resolved.category,
    packet_size: Math.floor(Math.random() * 1200) + 64,
    is_unknown: !resolved.is_known
  };

  // Add packet
  state.simPackets.unshift(pkt);
  if (state.simPackets.length > 500) state.simPackets.pop();

  // Alerts logic
  if (chosen.name === "Telnet" || chosen.name === "FTP-Control") {
    state.simAlerts.unshift({
      id: Date.now(),
      timestamp: timeStr,
      severity: "Warning",
      alert_type: "Insecure Protocol",
      message: `Insecure plaintext ${chosen.name} detected: ${srcIp}:${srcPort} -> ${dstIp}:${chosen.dstPort}`
    });
  } else if (!resolved.is_known) {
    state.simAlerts.unshift({
      id: Date.now(),
      timestamp: timeStr,
      severity: "Info",
      alert_type: "Unknown Port",
      message: `Traffic on unrecognized port ${chosen.dstPort} (${chosen.proto}): ${srcIp}:${srcPort} -> ${dstIp}:${chosen.dstPort}`
    });
  }

  state.simCounter++;
  if (state.simCounter % 25 === 0) {
    // Simulate port scan alert
    const scanIp = "10.30.5.99";
    state.simAlerts.unshift({
      id: Date.now(),
      timestamp: timeStr,
      severity: "Warning",
      alert_type: "Port Scan Detected",
      message: `Potential port scan: ${scanIp} probed 25 distinct ports in the last 10s!`
    });
  }

  if (state.simAlerts.length > 50) state.simAlerts.pop();
}

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initCharts();
  bindEventHandlers();
  detectEnvironmentAndStart();
});

async function detectEnvironmentAndStart() {
  try {
    const res = await fetch("/api/stats", { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      state.isStaticMode = false;
      loadInterfaces();
    } else {
      state.isStaticMode = true;
    }
  } catch (e) {
    // Static mode (GitHub Pages or local file)
    state.isStaticMode = true;
  }

  if (state.isStaticMode) {
    console.log("[UniPort] Running in Standalone Client Mode (GitHub Pages compatible)");
    // Pre-populate with initial packets
    for (let i = 0; i < 30; i++) {
      generateClientPacket();
    }
  }

  startPolling();
}

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
  if (icon) icon.textContent = state.theme === "dark" ? "🌙" : "☀️";
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

  // 1. Category Distribution
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
            labels: { color: colors.text, font: { family: "'Outfit', sans-serif", size: 11 }, boxWidth: 12, padding: 8 }
          }
        }
      }
    });
  }

  // 2. Top 10 Apps
  const ctxApps = document.getElementById("chart-top-apps")?.getContext("2d");
  if (ctxApps) {
    state.charts.topApps = new Chart(ctxApps, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{ label: "Packets", data: [], backgroundColor: "#6366f1", borderRadius: 6 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: colors.text, font: { size: 10 } }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: colors.text, font: { size: 10 } }, grid: { color: colors.grid } }
        }
      }
    });
  }

  // 3. Throughput PPS
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
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: colors.text, font: { size: 9 }, maxTicksLimit: 6 }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: colors.text, font: { size: 10 } }, grid: { color: colors.grid } }
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
    if (chart.options.plugins?.legend?.labels) chart.options.plugins.legend.labels.color = colors.text;
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
   Polling & Data Updates
   ========================================================================== */
function startPolling() {
  if (state.pollInterval) clearInterval(state.pollInterval);
  fetchDashboardData();
  state.pollInterval = setInterval(fetchDashboardData, 1000);
}

async function fetchDashboardData() {
  if (state.isPaused) return;

  if (state.isStaticMode) {
    // Generate 3-8 packets per second in client simulation
    const count = Math.floor(Math.random() * 5) + 3;
    for (let i = 0; i < count; i++) {
      generateClientPacket();
    }
    renderStaticDashboardData(count);
    return;
  }

  try {
    await Promise.all([fetchConnections(), fetchStats(), fetchAlerts()]);
  } catch (err) {
    console.warn("Backend poll failed, switching to static client mode:", err);
    state.isStaticMode = true;
  }
}

function renderStaticDashboardData(currentPps = 6) {
  // 1. Filter connections
  const search = document.getElementById("filter-search")?.value.trim().toLowerCase();
  const proto = document.getElementById("filter-protocol")?.value;
  const cat = document.getElementById("filter-category")?.value;
  const port = document.getElementById("filter-port")?.value.trim();

  let filtered = state.simPackets.filter(p => {
    if (proto && p.protocol !== proto) return false;
    if (cat && p.category !== cat) return false;
    if (port && p.src_port != port && p.dst_port != port) return false;
    if (search) {
      const match = p.src_ip.includes(search) || p.dst_ip.includes(search) ||
                    p.app_name.toLowerCase().includes(search) || p.category.toLowerCase().includes(search) ||
                    String(p.src_port).includes(search) || String(p.dst_port).includes(search);
      if (!match) return false;
    }
    return true;
  });

  renderConnectionsTable(filtered.slice(0, 200));
  renderAlertsFeed(state.simAlerts.slice(0, 30));

  // 2. Stats
  const totalPkts = state.simPackets.length;
  const tcpCount = state.simPackets.filter(p => p.protocol === "TCP").length;
  const udpCount = state.simPackets.filter(p => p.protocol === "UDP").length;
  const uniqueApps = new Set(state.simPackets.map(p => p.app_name)).size;
  const unknownCount = state.simPackets.filter(p => p.is_unknown || p.category === "Unknown").length;

  setText("stat-total-packets", totalPkts.toLocaleString());
  setText("stat-active-conns", Math.min(totalPkts, 24).toLocaleString());
  setText("stat-unique-apps", uniqueApps);
  setText("stat-tcp-count", tcpCount.toLocaleString());
  setText("stat-udp-count", udpCount.toLocaleString());
  setText("stat-unknown-count", unknownCount.toLocaleString());
  setText("header-pps", `${currentPps} pkt/s`);

  // Category counts
  const catMap = {};
  state.simPackets.forEach(p => { catMap[p.category] = (catMap[p.category] || 0) + 1; });
  const catLabels = Object.keys(catMap);
  const catData = Object.values(catMap);

  if (state.charts.categories) {
    state.charts.categories.data.labels = catLabels;
    state.charts.categories.data.datasets[0].data = catData;
    state.charts.categories.data.datasets[0].backgroundColor = catLabels.map(l => CATEGORY_COLORS[l] || "#94a3b8");
    state.charts.categories.update("none");
  }

  // Top 10 Apps
  const appMap = {};
  state.simPackets.forEach(p => { appMap[p.app_name] = (appMap[p.app_name] || 0) + 1; });
  const topAppEntries = Object.entries(appMap).sort((a, b) => b[1] - a[1]).slice(0, 10);

  if (state.charts.topApps) {
    state.charts.topApps.data.labels = topAppEntries.map(e => e[0]);
    state.charts.topApps.data.datasets[0].data = topAppEntries.map(e => e[1]);
    state.charts.topApps.update("none");
  }

  // Throughput Line
  if (state.charts.throughput) {
    const timeLabels = state.charts.throughput.data.labels;
    const timeData = state.charts.throughput.data.datasets[0].data;

    const nowStr = new Date().toTimeString().split(' ')[0];
    timeLabels.push(nowStr);
    timeData.push(currentPps);

    if (timeLabels.length > 30) {
      timeLabels.shift();
      timeData.shift();
    }
    state.charts.throughput.update("none");
  }
}

// Backend Fetch Handlers
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

async function fetchStats() {
  const res = await fetch("/api/stats");
  if (!res.ok) return;
  const json = await res.json();
  const s = json.stats;
  if (!s) return;

  setText("stat-total-packets", s.total_packets.toLocaleString());
  setText("stat-active-conns", s.active_connections.toLocaleString());
  setText("stat-unique-apps", s.unique_applications);
  setText("stat-tcp-count", s.tcp_count.toLocaleString());
  setText("stat-udp-count", s.udp_count.toLocaleString());
  setText("stat-unknown-count", s.unknown_count.toLocaleString());
  setText("header-pps", `${s.throughput?.current_pps || 0} pkt/s`);

  if (state.charts.categories && s.categories) {
    const labels = s.categories.map(c => c.category);
    const data = s.categories.map(c => c.count);
    state.charts.categories.data.labels = labels;
    state.charts.categories.data.datasets[0].data = data;
    state.charts.categories.data.datasets[0].backgroundColor = labels.map(l => CATEGORY_COLORS[l] || "#94a3b8");
    state.charts.categories.update("none");
  }

  if (state.charts.topApps && s.top_apps) {
    state.charts.topApps.data.labels = s.top_apps.map(a => a.app_name);
    state.charts.topApps.data.datasets[0].data = s.top_apps.map(a => a.count);
    state.charts.topApps.update("none");
  }

  if (state.charts.throughput && s.throughput) {
    state.charts.throughput.data.labels = s.throughput.labels;
    state.charts.throughput.data.datasets[0].data = s.throughput.data;
    state.charts.throughput.update("none");
  }
}

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

  if (countLabel) countLabel.textContent = `Showing ${rows.length} connection${rows.length === 1 ? '' : 's'}`;

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

  tbody.innerHTML = rows.map(r => {
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
}

function renderAlertsFeed(alerts) {
  const feed = document.getElementById("alerts-feed");
  const badge = document.getElementById("alerts-count-badge");
  if (!feed) return;

  if (badge) badge.textContent = `${alerts.length} Alert${alerts.length === 1 ? '' : 's'}`;

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
  document.getElementById("btn-theme-toggle")?.addEventListener("click", toggleTheme);
  document.getElementById("btn-toggle-capture")?.addEventListener("click", toggleCapture);
  document.getElementById("btn-clear-data")?.addEventListener("click", clearData);

  document.getElementById("btn-mode-demo")?.addEventListener("click", () => switchMode("demo"));
  document.getElementById("btn-mode-live")?.addEventListener("click", () => switchMode("live"));

  const debounce = (fn, delay = 200) => {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  };

  const triggerFilter = debounce(() => {
    if (state.isStaticMode) renderStaticDashboardData(0);
    else fetchConnections();
  }, 200);

  document.getElementById("filter-search")?.addEventListener("input", triggerFilter);
  document.getElementById("filter-port")?.addEventListener("input", triggerFilter);
  document.getElementById("filter-protocol")?.addEventListener("change", triggerFilter);
  document.getElementById("filter-category")?.addEventListener("change", triggerFilter);

  document.getElementById("btn-reset-filters")?.addEventListener("click", () => {
    setVal("filter-search", "");
    setVal("filter-port", "");
    setVal("filter-protocol", "");
    setVal("filter-category", "");
    triggerFilter();
  });

  document.getElementById("btn-export-csv")?.addEventListener("click", exportCsv);
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
    // Static mode
  }
}

async function switchMode(mode) {
  state.mode = mode;
  const btnDemo = document.getElementById("btn-mode-demo");
  const btnLive = document.getElementById("btn-mode-live");
  const ifaceWrap = document.getElementById("interface-select-wrap");
  const modeText = document.getElementById("status-mode-text");

  if (mode === "live") {
    if (state.isStaticMode) {
      alert("Live packet sniffing with Scapy requires running the Python backend locally (python app.py --mode live). Running in Simulated Demo mode on GitHub Pages.");
      return;
    }
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

  if (!state.isStaticMode) {
    try {
      const res = await fetch("/api/control", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mode })
      });
      const json = await res.json();
      if (json.status === "error") {
        alert(json.message);
        switchMode("demo");
      }
    } catch (e) {}
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
  } else {
    if (icon) icon.textContent = "⏸";
    if (label) label.textContent = "Pause";
    if (btn) btn.className = "btn btn-primary";
    if (statusLabel) statusLabel.textContent = "Running";
  }

  if (!state.isStaticMode) {
    try {
      await fetch("/api/control", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: state.isPaused ? "pause" : "resume" })
      });
    } catch (e) {}
  }
}

async function clearData() {
  if (!confirm("Clear all captured packets and alerts?")) return;
  state.simPackets = [];
  state.simAlerts = [];
  if (state.charts.throughput) {
    state.charts.throughput.data.labels = [];
    state.charts.throughput.data.datasets[0].data = [];
    state.charts.throughput.update();
  }

  if (!state.isStaticMode) {
    try {
      await fetch("/api/control", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "clear" })
      });
    } catch (e) {}
  }
  fetchDashboardData();
}

function exportCsv() {
  if (!state.isStaticMode) {
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
    return;
  }

  // Client-side CSV generation for GitHub Pages
  let csvContent = "data:text/csv;charset=utf-8,Timestamp,Source IP,Source Port,Destination IP,Destination Port,Protocol,Application,Category,Packet Size (Bytes),Is Unknown\n";
  state.simPackets.forEach(p => {
    csvContent += `"${p.timestamp}","${p.src_ip}",${p.src_port},"${p.dst_ip}",${p.dst_port},"${p.protocol}","${p.app_name}","${p.category}",${p.packet_size},"${p.is_unknown ? 'Yes' : 'No'}"\n`;
  });

  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "uniport_connections.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function doPortLookup() {
  const portInput = document.getElementById("lookup-port-input");
  const protoSelect = document.getElementById("lookup-proto-select");
  const resultBox = document.getElementById("lookup-result-box");
  if (!portInput || !resultBox) return;

  const portVal = parseInt(portInput.value, 10);
  if (!portVal || isNaN(portVal) || portVal < 1 || portVal > 65535) {
    resultBox.innerHTML = '<div class="lookup-placeholder" style="color:var(--accent-rose)">Please enter a valid port number (1 - 65535).</div>';
    return;
  }

  const protoVal = protoSelect?.value ? protoSelect.value.toUpperCase() : null;
  const match = PORT_DATABASE.find(p => p.port === portVal && (!protoVal || p.protocol === protoVal)) ||
                PORT_DATABASE.find(p => p.port === portVal);

  if (match) {
    const catClass = getCategoryClass(match.category);
    resultBox.innerHTML = `
      <div class="lookup-result-card">
        <div class="lookup-res-header">
          <span class="lookup-res-name">${escapeHtml(match.name)}</span>
          <span class="cat-chip ${catClass}">${escapeHtml(match.category)}</span>
        </div>
        <div style="font-size:0.8rem; color:var(--text-secondary);">
          <strong>Port:</strong> ${match.port} / ${escapeHtml(match.protocol || 'TCP')}
        </div>
        <div class="lookup-res-desc">${escapeHtml(match.description || 'Standard university port service.')}</div>
      </div>
    `;
  } else {
    resultBox.innerHTML = `
      <div class="lookup-result-card">
        <div class="lookup-res-header">
          <span class="lookup-res-name">Unknown Port ${portVal}</span>
          <span class="cat-chip cat-unknown">Unknown</span>
        </div>
        <div class="lookup-res-desc">Port ${portVal} is not in the recognized university service database.</div>
      </div>
    `;
  }
}

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
