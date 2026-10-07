"""
database.py - SQLite Storage and Analytics Module
================================================
Handles data persistence, connection filtering, traffic statistics,
and security alert detection for UniPort Monitor.

Key Concepts for Viva:
- SQLite is an embedded, serverless, zero-configuration SQL engine.
- WAL (Write-Ahead Logging) mode allows concurrent readers and writers without blocking.
- Time-series aggregation (packets per second over 60s) computes real-time throughput.
- Port scan heuristic: detects horizontal/vertical scanning if a single source IP
  probes > 20 distinct destination ports within a 10-second sliding window.
"""

import sqlite3
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uniport.db")

# Cache to avoid duplicate port scan alert spamming within 30 seconds for the same IP
_last_scan_alert: Dict[str, float] = {}

def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row_factory enabled and WAL mode."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db() -> None:
    """Initializes the database tables and indexes."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                epoch_time REAL NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                app_name TEXT NOT NULL,
                category TEXT NOT NULL,
                packet_size INTEGER NOT NULL,
                is_unknown INTEGER NOT NULL DEFAULT 0
            );
        """)

        # Indexes for fast filtering and statistics aggregation
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_epoch ON packets(epoch_time);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_category ON packets(category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_app ON packets(app_name);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_scan ON packets(src_ip, epoch_time);")

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                epoch_time REAL NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_epoch ON alerts(epoch_time);")
        conn.commit()

def record_alert(severity: str, alert_type: str, message: str, epoch_now: Optional[float] = None) -> None:
    """Inserts a security or operational alert into the database."""
    now_epoch = epoch_now or time.time()
    now_str = datetime.fromtimestamp(now_epoch).strftime("%H:%M:%S")
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, epoch_time, severity, alert_type, message) VALUES (?, ?, ?, ?, ?)",
            (now_str, now_epoch, severity, alert_type, message)
        )
        conn.commit()

def insert_packet(pkt: Dict[str, Any]) -> None:
    """
    Inserts a captured or simulated packet and triggers alert evaluation rules.
    """
    epoch_now = pkt.get("epoch_time", time.time())
    ts = pkt.get("timestamp") or datetime.fromtimestamp(epoch_now).strftime("%H:%M:%S")
    src_ip = pkt["src_ip"]
    src_port = int(pkt["src_port"])
    dst_ip = pkt["dst_ip"]
    dst_port = int(pkt["dst_port"])
    protocol = pkt["protocol"].upper()
    app_name = pkt["app_name"]
    category = pkt["category"]
    packet_size = int(pkt.get("packet_size", 64))
    is_unknown = 1 if pkt.get("is_unknown") else 0

    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO packets (
                timestamp, epoch_time, src_ip, src_port, dst_ip, dst_port,
                protocol, app_name, category, packet_size, is_unknown
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, epoch_now, src_ip, src_port, dst_ip, dst_port, protocol, app_name, category, packet_size, is_unknown))
        conn.commit()

    # Alert Rules Check:
    # Rule (a): Insecure Plaintext Protocols (Telnet, FTP)
    if app_name in ("Telnet", "FTP-Control") or dst_port in (23, 21) or src_port in (23, 21):
        # Trigger Warning
        proto_name = "Telnet" if (dst_port == 23 or src_port == 23 or app_name == "Telnet") else "FTP"
        msg = f"Insecure plaintext {proto_name} detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        record_alert("Warning", "Insecure Protocol", msg, epoch_now)

    # Rule (b): Unknown Port
    if is_unknown or category == "Unknown":
        target_port = dst_port if dst_port < 49152 else src_port
        msg = f"Traffic on unrecognized port {target_port} ({protocol}): {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        record_alert("Info", "Unknown Port", msg, epoch_now)

    # Rule (c): Port Scan Detection (>20 distinct destination ports in 10s from same src_ip)
    check_port_scan(src_ip, epoch_now)

def check_port_scan(src_ip: str, epoch_now: float) -> None:
    """
    Checks if src_ip has contacted > 20 distinct destination ports in the past 10 seconds.
    """
    # Rate limit alerts to at most once per 20 seconds per IP
    last_time = _last_scan_alert.get(src_ip, 0)
    if epoch_now - last_time < 20.0:
        return

    window_start = epoch_now - 10.0
    with get_db_connection() as conn:
        row = conn.execute("""
            SELECT COUNT(DISTINCT dst_port) as distinct_ports
            FROM packets
            WHERE src_ip = ? AND epoch_time >= ?
        """, (src_ip, window_start)).fetchone()

        if row and row["distinct_ports"] >= 20:
            _last_scan_alert[src_ip] = epoch_now
            msg = f"Potential port scan: {src_ip} probed {row['distinct_ports']} distinct ports in the last 10s!"
            record_alert("Warning", "Port Scan Detected", msg, epoch_now)

def get_recent_connections(
    limit: int = 200,
    protocol: str = "",
    category: str = "",
    app: str = "",
    port: str = "",
    q: str = ""
) -> List[Dict[str, Any]]:
    """
    Retrieves recent packet records matching all provided filters, sorted newest first.
    """
    query = ["SELECT * FROM packets WHERE 1=1"]
    params: List[Any] = []

    if protocol and protocol.strip():
        query.append("AND protocol = ?")
        params.append(protocol.strip().upper())

    if category and category.strip():
        query.append("AND category = ?")
        params.append(category.strip())

    if app and app.strip():
        query.append("AND app_name LIKE ?")
        params.append(f"%{app.strip()}%")

    if port and port.strip():
        try:
            port_num = int(port.strip())
            query.append("AND (src_port = ? OR dst_port = ?)")
            params.extend([port_num, port_num])
        except ValueError:
            pass

    if q and q.strip():
        search_term = f"%{q.strip()}%"
        query.append("""
            AND (src_ip LIKE ? OR dst_ip LIKE ? OR app_name LIKE ? OR category LIKE ? 
                 OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)
        """)
        params.extend([search_term, search_term, search_term, search_term, search_term, search_term])

    query.append("ORDER BY id DESC LIMIT ?")
    params.append(limit)

    with get_db_connection() as conn:
        rows = conn.execute(" ".join(query), params).fetchall()
        return [dict(r) for r in rows]

def get_stats() -> Dict[str, Any]:
    """
    Calculates summary statistics and data series for Chart.js dashboards.
    """
    now = time.time()
    one_min_ago = now - 60.0

    with get_db_connection() as conn:
        # Total packets count
        total_packets = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

        # TCP vs UDP count
        proto_counts = dict(conn.execute("""
            SELECT protocol, COUNT(*) as cnt 
            FROM packets 
            GROUP BY protocol
        """).fetchall())
        tcp_count = proto_counts.get("TCP", 0)
        udp_count = proto_counts.get("UDP", 0)

        # Unique applications
        unique_apps = conn.execute("SELECT COUNT(DISTINCT app_name) FROM packets").fetchone()[0]

        # Unknown port count
        unknown_count = conn.execute("SELECT COUNT(*) FROM packets WHERE is_unknown = 1 OR category = 'Unknown'").fetchone()[0]

        # Active connections in the last 60 seconds (unique conversation 4-tuples)
        active_conns = conn.execute("""
            SELECT COUNT(DISTINCT src_ip || ':' || src_port || '-' || dst_ip || ':' || dst_port)
            FROM packets
            WHERE epoch_time >= ?
        """, (one_min_ago,)).fetchone()[0]

        # Category distribution
        category_rows = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM packets
            GROUP BY category
            ORDER BY count DESC
        """).fetchall()
        category_dist = [{"category": r["category"], "count": r["count"]} for r in category_rows]

        # Top 10 applications/ports
        top_apps_rows = conn.execute("""
            SELECT app_name, category, COUNT(*) as count
            FROM packets
            GROUP BY app_name
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        top_apps = [{"app_name": r["app_name"], "category": r["category"], "count": r["count"]} for r in top_apps_rows]

        # Packets per second over the last 60 seconds (grouped by second bucket)
        # Create 60 second buckets
        pps_rows = conn.execute("""
            SELECT CAST(epoch_time AS INTEGER) as sec, COUNT(*) as pps
            FROM packets
            WHERE epoch_time >= ?
            GROUP BY sec
            ORDER BY sec ASC
        """, (one_min_ago,)).fetchall()

        pps_map = {r["sec"]: r["pps"] for r in pps_rows}
        current_sec = int(now)
        time_series_labels = []
        time_series_data = []

        for offset in range(59, -1, -1):
            sec_point = current_sec - offset
            time_series_labels.append(datetime.fromtimestamp(sec_point).strftime("%H:%M:%S"))
            time_series_data.append(pps_map.get(sec_point, 0))

        return {
            "total_packets": total_packets,
            "active_connections": active_conns,
            "unique_applications": unique_apps,
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "unknown_count": unknown_count,
            "categories": category_dist,
            "top_apps": top_apps,
            "throughput": {
                "labels": time_series_labels,
                "data": time_series_data,
                "current_pps": time_series_data[-1] if time_series_data else 0
            }
        }

def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent security/network alerts."""
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, severity, alert_type, message
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

def clear_all_data() -> None:
    """Wipes all packet and alert records for a clean slate."""
    _last_scan_alert.clear()
    with get_db_connection() as conn:
        conn.execute("DELETE FROM packets;")
        conn.execute("DELETE FROM alerts;")
        conn.execute("VACUUM;")
        conn.commit()
