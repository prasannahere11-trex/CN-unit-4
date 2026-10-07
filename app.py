"""
app.py - UniPort Monitor Flask Web Application
=============================================
Central server combining the Web UI, REST APIs, database, and background capture engines.

Run Instructions:
  python app.py --mode demo           # Demo mode (default, no root/admin required)
  python app.py --mode live           # Live mode with Scapy capture (requires Npcap/sudo)
  python app.py --port 5000           # Custom port
"""

import argparse
import csv
import io
import os
import sys
from flask import Flask, render_template, request, jsonify, Response

import database
from port_mapper import default_mapper
from simulator import default_simulator
from sniffer import default_sniffer

app = Flask(__name__)

# State variables
current_mode = "demo" # "live" or "demo"
is_monitoring_active = True

def initialize_engine(mode: str = "demo", interface: str = None) -> None:
    """Initializes the database and starts either live sniffing or simulator."""
    global current_mode, is_monitoring_active
    database.init_db()
    current_mode = mode.lower()

    if current_mode == "live":
        default_simulator.stop()
        success, msg = default_sniffer.start(interface)
        if not success:
            print(f"[Warning] Live capture failed: {msg}. Falling back to Demo mode.")
            current_mode = "demo"
            default_simulator.start()
        else:
            print(f"[Info] UniPort Monitor running in LIVE mode on interface '{interface or 'default'}'.")
    else:
        default_sniffer.stop()
        default_simulator.start()
        print("[Info] UniPort Monitor running in DEMO mode (Simulated University Traffic).")

    is_monitoring_active = True

@app.route("/")
def index():
    """Renders the single-page dashboard."""
    return render_template("index.html")

@app.route("/api/connections", methods=["GET"])
def api_connections():
    """
    Returns recent connections matching optional query filters.
    Query parameters: protocol, category, app, port, q, limit.
    """
    protocol = request.args.get("protocol", "")
    category = request.args.get("category", "")
    app_name = request.args.get("app", "")
    port = request.args.get("port", "")
    q = request.args.get("q", "")
    limit = int(request.args.get("limit", 200))

    connections = database.get_recent_connections(
        limit=limit,
        protocol=protocol,
        category=category,
        app=app_name,
        port=port,
        q=q
    )
    return jsonify({
        "status": "success",
        "count": len(connections),
        "connections": connections
    })

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """
    Returns aggregated summary cards and chart datasets.
    """
    stats = database.get_stats()
    return jsonify({
        "status": "success",
        "stats": stats
    })

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    Returns recent security and operational alerts.
    """
    limit = int(request.args.get("limit", 50))
    alerts = database.get_alerts(limit=limit)
    return jsonify({
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    })

@app.route("/api/port/<int:port_num>", methods=["GET"])
def api_port_lookup(port_num: int):
    """
    Port Lookup tool endpoint: returns application and category for a port number.
    """
    protocol = request.args.get("protocol", None)
    lookup_res = default_mapper.lookup_port(port_num, protocol)
    return jsonify({
        "status": "success",
        "data": lookup_res
    })

@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """
    Returns list of available network interfaces for Live mode.
    """
    ifaces = default_sniffer.get_interfaces()
    return jsonify({
        "status": "success",
        "interfaces": ifaces
    })

@app.route("/api/status", methods=["GET"])
def api_status():
    """
    Returns the current operational status of the monitoring engine.
    """
    global current_mode, is_monitoring_active
    sniffer_info = default_sniffer.get_status()
    simulator_running = default_simulator.is_running()

    return jsonify({
        "status": "success",
        "mode": current_mode,
        "is_active": is_monitoring_active,
        "sniffer": sniffer_info,
        "simulator_running": simulator_running
    })

@app.route("/api/control", methods=["POST"])
def api_control():
    """
    Handles dashboard controls: start, pause, resume, clear, and mode switching.
    """
    global current_mode, is_monitoring_active
    data = request.get_json() or {}
    action = data.get("action", "").lower()
    new_mode = data.get("mode", "").lower()
    interface = data.get("interface", None)

    message = "Action processed"

    if new_mode in ("live", "demo") and new_mode != current_mode:
        current_mode = new_mode
        if current_mode == "live":
            default_simulator.stop()
            success, msg = default_sniffer.start(interface)
            if not success:
                current_mode = "demo"
                default_simulator.start()
                return jsonify({
                    "status": "error",
                    "mode": "demo",
                    "message": f"Could not switch to Live mode: {msg}. Switched to Demo mode."
                })
            message = f"Switched to Live mode on interface '{interface or 'default'}'."
        else:
            default_sniffer.stop()
            default_simulator.start()
            message = "Switched to Demo mode (simulated traffic)."

    if action == "pause":
        is_monitoring_active = False
        if current_mode == "live":
            default_sniffer.pause()
        else:
            default_simulator.pause()
        message = "Monitoring paused."

    elif action in ("start", "resume"):
        is_monitoring_active = True
        if current_mode == "live":
            if not default_sniffer.is_running():
                default_sniffer.start(interface)
            else:
                default_sniffer.resume()
        else:
            if not default_simulator.is_running():
                default_simulator.start()
            else:
                default_simulator.resume()
        message = "Monitoring active."

    elif action == "clear":
        database.clear_all_data()
        message = "All captured packet and alert records cleared."

    return jsonify({
        "status": "success",
        "mode": current_mode,
        "is_active": is_monitoring_active,
        "message": message
    })

@app.route("/api/export.csv", methods=["GET"])
def api_export_csv():
    """
    Generates and downloads a CSV of the currently filtered connections table.
    """
    protocol = request.args.get("protocol", "")
    category = request.args.get("category", "")
    app_name = request.args.get("app", "")
    port = request.args.get("port", "")
    q = request.args.get("q", "")
    limit = int(request.args.get("limit", 1000))

    connections = database.get_recent_connections(
        limit=limit,
        protocol=protocol,
        category=category,
        app=app_name,
        port=port,
        q=q
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Source IP", "Source Port", "Destination IP",
        "Destination Port", "Protocol", "Application", "Category", "Packet Size (Bytes)", "Is Unknown"
    ])

    for c in connections:
        writer.writerow([
            c["timestamp"],
            c["src_ip"],
            c["src_port"],
            c["dst_ip"],
            c["dst_port"],
            c["protocol"],
            c["app_name"],
            c["category"],
            c["packet_size"],
            "Yes" if c.get("is_unknown") else "No"
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=uniport_connections.csv"}
    )

def parse_cli_args():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(description="UniPort Monitor - University Network Port Analyzer")
    parser.add_argument("--mode", choices=["live", "demo"], default="demo", help="Initial monitoring mode (default: demo)")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0", help="Web server host (default: 0.0.0.0)")
    parser.add_argument("--interface", default=None, help="Network interface for live packet capture")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_cli_args()
    initialize_engine(mode=args.mode, interface=args.interface)
    print(f"[Info] UniPort Monitor running at http://localhost:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
