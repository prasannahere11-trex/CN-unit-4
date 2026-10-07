# 🌐 UniPort Monitor
**A Port-Based Communication Monitor & Traffic Analyzer for University Networks**

---

## 📌 Project Overview
**UniPort Monitor** is a real-time network traffic analysis tool tailored for campus environments. It captures or simulates transport-layer packets (TCP & UDP), identifies communicating applications by mapping port numbers to well-known university network services, detects security anomalies, and visualizes network activity on a modern, responsive single-page web dashboard.

---

## 🏗️ Architecture & How It Works

```
  [ Network Interface ]              [ Demo Traffic Generator ]
           │ (Scapy Sniffer)                     │ (Simulated Campus Traffic)
           ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Packet Ingestion Engine                  │
│       Extracts: IP Layer (Src/Dst IP) + Transport Layer     │
│                 (Src Port, Dst Port, Protocol, Wire Size)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Port-to-Application Mapper                  │
│                     (ports.json Rules)                      │
│   - Lower/Server Port preference rule                       │
│   - Protocol-specific differentiation (e.g. QUIC vs HTTPS)  │
│   - Category Tagging (Web, Email, Database, etc.)           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      SQLite Database                        │
│          (Time-Series Packets & Security Alerts Log)        │
│   - Insecure Protocol Check (Telnet / FTP)                  │
│   - Unknown High Port Flagging                              │
│   - Port Scan Detection (>20 distinct ports / 10s)          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Flask REST API & Web Dashboard              │
│       - 1s Polling / Live Updates                           │
│       - Chart.js (Categories, Top 10 Apps, Throughput PPS)  │
│       - Filterable & Exportable Connections Table           │
│       - Interactive Port Lookup Tool                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

1. **Two Execution Modes**:
   - **Demo Mode (Default)**: Generates realistic simulated university traffic (Eduroam Wi-Fi, LMS web traffic, campus databases, DNS/NTP, and occasional alerts). Runs out-of-the-box on any computer without needing administrator/root privileges or packet capture drivers.
   - **Live Mode**: Uses **Scapy** to sniff real packets on any selected network interface in promiscuous mode.
2. **Port-to-Application Mapper (`ports.json`)**:
   - Easily editable JSON configuration mapping ports to application names, categories, and descriptions.
   - Intelligent resolution: evaluates both source and destination ports, prioritizing server/well-known ports over ephemeral client ports.
   - Distinguishes protocols (e.g., `UDP 443` = HTTP/3 QUIC, `TCP 443` = HTTPS, `UDP 53` = DNS).
3. **Live Connections Table**:
   - Displays: Timestamp, Source IP, Source Port, Destination IP, Destination Port, Protocol badge, Application, Category chip, and Packet Size.
   - Real-time updates every 1 second, capped at the newest 200 packets.
   - Unknown ports automatically highlighted in amber.
4. **Interactive Dashboard & Charts (Chart.js)**:
   - **Doughnut Chart**: Traffic volume by category.
   - **Bar Chart**: Top 10 applications by packet count.
   - **Line Chart**: Real-time throughput (packets/second) over a rolling 60-second window.
5. **Security & Anomaly Alerts**:
   - **Insecure Plaintext Detection**: Flags unencrypted Telnet (`TCP 23`) and FTP (`TCP 21`).
   - **Unknown Port Activity**: Identifies and logs traffic on unmapped/unregistered ports.
   - **Port Scan Detection**: Detects horizontal/vertical scanning if a single source IP probes $>20$ distinct destination ports within 10 seconds.
6. **Port Lookup Tool**: Instant lookup utility allowing users to search any port (1–65535) and inspect its standard assignment and description.
7. **CSV Export & Filtering**: Download filtered connection logs with one click.
8. **Dark / Light Theme**: Built-in theme switcher with `localStorage` persistence.

---

## 💻 Tech Stack

- **Backend**: Python 3.10+, Flask, Threading
- **Packet Capture**: Scapy
- **Database**: SQLite3 (`WAL` mode for non-blocking concurrent reads/writes)
- **Frontend**: Plain HTML5, Modern Vanilla CSS (CSS variables, glassmorphism, responsive grid), Vanilla JavaScript (Fetch API, zero npm/build steps)
- **Charts**: Chart.js 4.4 via CDN

---

## 📂 Project Structure

```
uniport-monitor/
├── app.py                 # Flask server, REST API routes, CLI arguments
├── sniffer.py             # Live Scapy packet capture engine
├── simulator.py           # Realistic campus network traffic generator
├── port_mapper.py         # Port resolution logic & ports.json loader
├── database.py            # SQLite schema, queries, time-series & alerts
├── ports.json             # Editable database of port-to-application mappings
├── templates/
│   └── index.html         # Single-page dashboard UI
├── static/
│   ├── css/
│   │   └── style.css      # Dark/Light theme, NOC styling, responsive layouts
│   └── js/
│       └── app.js         # Chart.js controller, polling & interactions
├── tests/
│   └── test_port_mapper.py# Unit tests for port resolution
├── requirements.txt       # Python dependencies
└── README.md              # Documentation & Viva Q&A Guide
```

---

## ⚙️ Installation & Setup

### 1. Clone or Navigate to the Repository
```bash
git clone <repo-url>
cd "Cn proj 4th"
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

### 3. Platform-Specific Setup for LIVE Mode

#### 🪟 Windows Setup
- **Demo Mode**: Requires no special permissions.
- **Live Mode**: Requires [Npcap](https://npcap.com/#download) (or WinPcap) installed.
  1. Download and run the Npcap installer from [https://npcap.com/#download](https://npcap.com/#download).
  2. During installation, ensure the option **"Install Npcap in WinPcap API-compatible Mode"** is checked.
  3. Open your terminal as Administrator and start in live mode:
     ```cmd
     python app.py --mode live
     ```

#### 🐧 Linux Setup
- **Demo Mode**: Run directly: `python3 app.py --mode demo`
- **Live Mode**: Raw packet sockets require superuser permissions (`CAP_NET_RAW`):
  ```bash
  sudo python3 app.py --mode live
  ```

#### 🍎 macOS Setup
- **Demo Mode**: Run directly: `python3 app.py --mode demo`
- **Live Mode**: Run with root privileges:
  ```bash
  sudo python3 app.py --mode live
  ```

---

## 🏃 Running the Application

### Start in Demo Mode (Recommended for testing & viva presentation)
```bash
python app.py --mode demo
```

### Start in Live Mode
```bash
python app.py --mode live
```

### Optional CLI Arguments
- `--port <PORT>`: Specify web server port (default: `5000`)
- `--host <HOST>`: Specify bind address (default: `0.0.0.0`)
- `--interface <NAME>`: Specify network interface for live capture

Open your web browser and navigate to:
```
http://localhost:5000
```

---

## 🧪 Running Unit Tests

Run the test suite using `pytest`:
```bash
pytest
```
All 9 unit test cases verify known port lookup, unknown port handling, dual-port preference, protocol differentiation (TCP vs UDP), and interactive port searches.

---

## 🌐 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /` | `GET` | Main single-page web dashboard |
| `GET /api/connections` | `GET` | List recent filtered packets (`protocol`, `category`, `app`, `port`, `q`, `limit`) |
| `GET /api/stats` | `GET` | Summary metrics, category counts, top 10 apps, 60s throughput time-series |
| `GET /api/alerts` | `GET` | List recent security and operational alerts |
| `GET /api/port/<int:port>`| `GET` | Query metadata for a specific port number |
| `POST /api/control` | `POST` | Control monitoring (`start`, `pause`, `resume`, `clear`, `mode`) |
| `GET /api/interfaces` | `GET` | List available network capture interfaces |
| `GET /api/export.csv` | `GET` | Export filtered connections table as downloadable CSV file |

---

## 🎓 Viva & Exam Quick Reference Guide

### Q1: What is the role of a Port Number in Computer Networks?
> **Answer**: Port numbers reside in the Transport Layer (Layer 4 of OSI / TCP-IP model). While IP addresses uniquely identify a host device on a network, 16-bit port numbers (0 to 65,535) uniquely identify the specific process or service running on that host.

### Q2: What are the three categories of Port Numbers defined by IANA?
> **Answer**:
> 1. **Well-Known Ports (0 – 1,023)**: Reserved for core system services (HTTP 80, HTTPS 443, SSH 22, DNS 53).
> 2. **Registered Ports (1,024 – 49,151)**: Assigned by IANA for specific vendor applications and databases (MySQL 3306, PostgreSQL 5432, RADIUS 1812).
> 3. **Dynamic / Ephemeral Ports (49,152 – 65,535)**: Assigned temporarily by client operating systems for outbound client sockets.

### Q3: Why does UniPort Monitor check both Source and Destination ports?
> **Answer**: When a client accesses a web server, the packet sent from the client has an ephemeral Source Port (e.g., 54321) and Destination Port 443 (HTTPS). When the server replies, the Source Port is 443 and Destination Port is 54321. Checking both ports and prioritizing the well-known/lower port ensures the application is correctly identified in both directions of the flow.

### Q4: How does the Port Scan detection algorithm work?
> **Answer**: A sliding window of 10 seconds is maintained in SQLite. If a single source IP attempts connections to more than 20 distinct destination ports within that 10-second window, the system triggers a "Port Scan Detected" warning alert.

---

## 🔒 Privacy & Compliance Statement
UniPort Monitor is designed strictly for network diagnostic and educational purposes:
- **Headers Only**: The sniffer extracts only IP headers and transport layer ports. It **never captures, logs, or inspects payload contents**.
- **Authorization**: Only monitor networks that you own or have explicit authorization to inspect.
