"""
simulator.py - University Network Traffic Simulator
==================================================
Generates realistic, synthetic network traffic modeled after a university campus
network (Eduroam Wi-Fi, Computer Science Labs, Admin Offices, LMS Server,
Campus Databases, DNS/NTP, and external Internet traffic).

Viva Explanation Points:
- Simulates realistic campus IP addressing (Class A/B private subnets + public servers).
- Emulates transport layer interactions (ephemeral client ports -> service ports).
- Injects periodic anomalous traffic (Insecure Telnet/FTP, Unknown high ports, Port Scans)
  to demonstrate the live alert detection engine without needing real attack tools.
"""

import threading
import time
import random
from typing import Dict, Any, List, Optional
import database
from port_mapper import default_mapper

CAMPUS_SUBNETS = [
    ("10.20.", "Eduroam Wi-Fi (Students)"),
    ("10.10.", "Faculty & Admin"),
    ("10.30.", "CS Computer Lab"),
    ("10.40.", "Hostel / Dormitories")
]

CAMPUS_SERVERS = {
    "DNS": "172.16.1.10",
    "RADIUS": "172.16.1.20",
    "LMS_WEB": "172.16.1.50",
    "DB_MYSQL": "172.16.1.100",
    "MAIL": "172.16.1.200",
    "SQUID_PROXY": "172.16.1.254"
}

EXTERNAL_SERVERS = [
    ("142.250.190.46", "Google / YouTube"),
    ("151.101.1.140", "Cloudflare / CDN"),
    ("13.107.4.52", "Microsoft 365 / Teams"),
    ("140.82.112.4", "GitHub"),
    ("8.8.8.8", "Google Public DNS"),
    ("1.1.1.1", "Cloudflare DNS")
]

# Traffic profiles with relative weights (probability of occurrence)
TRAFFIC_PROFILES = [
    # Web Browsing & Streaming
    {"app_name": "HTTPS", "dst_port": 443, "protocol": "TCP", "category": "Web", "weight": 35, "size_range": (300, 1500)},
    {"app_name": "HTTP/3 (QUIC)", "dst_port": 443, "protocol": "UDP", "category": "Web", "weight": 15, "size_range": (500, 1420)},
    {"app_name": "HTTP", "dst_port": 80, "protocol": "TCP", "category": "Web", "weight": 8, "size_range": (150, 1200)},
    {"app_name": "Squid Proxy", "dst_port": 3128, "protocol": "TCP", "category": "Web", "weight": 5, "size_range": (200, 1500)},
    
    # Campus Wi-Fi & Authentication
    {"app_name": "RADIUS Auth", "dst_port": 1812, "protocol": "UDP", "category": "Campus-Specific", "weight": 10, "size_range": (128, 256)},
    {"app_name": "RADIUS Acct", "dst_port": 1813, "protocol": "UDP", "category": "Campus-Specific", "weight": 5, "size_range": (100, 200)},
    {"app_name": "Kerberos", "dst_port": 88, "protocol": "TCP", "category": "Campus-Specific", "weight": 4, "size_range": (256, 1024)},
    
    # Network Infrastructure
    {"app_name": "DNS", "dst_port": 53, "protocol": "UDP", "category": "Network Services", "weight": 18, "size_range": (64, 256)},
    {"app_name": "DHCP Client", "dst_port": 67, "protocol": "UDP", "category": "Network Services", "weight": 3, "size_range": (300, 576)},
    {"app_name": "NTP", "dst_port": 123, "protocol": "UDP", "category": "Network Services", "weight": 4, "size_range": (48, 90)},
    {"app_name": "LDAPS", "dst_port": 636, "protocol": "TCP", "category": "Network Services", "weight": 3, "size_range": (200, 600)},

    # Remote Coding / Admin
    {"app_name": "SSH / SFTP", "dst_port": 22, "protocol": "TCP", "category": "Remote Access", "weight": 8, "size_range": (80, 1400)},
    {"app_name": "RDP", "dst_port": 3389, "protocol": "TCP", "category": "Remote Access", "weight": 4, "size_range": (400, 1400)},

    # Databases
    {"app_name": "MySQL", "dst_port": 3306, "protocol": "TCP", "category": "Database", "weight": 5, "size_range": (120, 800)},
    {"app_name": "PostgreSQL", "dst_port": 5432, "protocol": "TCP", "category": "Database", "weight": 4, "size_range": (120, 800)},

    # Email
    {"app_name": "IMAPS", "dst_port": 993, "protocol": "TCP", "category": "Email", "weight": 4, "size_range": (200, 1400)},
    {"app_name": "SMTP Submission", "dst_port": 587, "protocol": "TCP", "category": "Email", "weight": 3, "size_range": (300, 1500)},

    # Media & VoIP
    {"app_name": "STUN", "dst_port": 3478, "protocol": "UDP", "category": "Streaming/VoIP", "weight": 6, "size_range": (80, 400)},
    {"app_name": "SIP", "dst_port": 5060, "protocol": "UDP", "category": "Streaming/VoIP", "weight": 3, "size_range": (200, 800)},
    {"app_name": "RTMP", "dst_port": 1935, "protocol": "TCP", "category": "Streaming/VoIP", "weight": 2, "size_range": (800, 1500)},

    # Anomalies / Special Cases for Alert Testing
    {"app_name": "Telnet", "dst_port": 23, "protocol": "TCP", "category": "Remote Access", "weight": 2, "size_range": (40, 120)},
    {"app_name": "FTP-Control", "dst_port": 21, "protocol": "TCP", "category": "File Transfer", "weight": 2, "size_range": (60, 200)},
    {"app_name": "Unknown", "dst_port": 0, "protocol": "TCP", "category": "Unknown", "weight": 3, "size_range": (50, 500)}
]

class TrafficSimulator:
    """
    Simulates real-time university network traffic in a background daemon thread.
    """

    def __init__(self, packets_per_second: float = 8.0):
        self.packets_per_second = packets_per_second
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Flatten weighted profile for fast random choices
        self._profile_pool = []
        for p in TRAFFIC_PROFILES:
            self._profile_pool.extend([p] * p["weight"])

        self._scan_counter = 0

    def start(self) -> None:
        """Starts the simulator background worker thread."""
        with self._lock:
            if self._running and self._thread and self._thread.is_alive():
                self._paused = False
                return
            self._running = True
            self._paused = False
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="TrafficSimulatorThread")
            self._thread.start()

    def pause(self) -> None:
        """Pauses traffic generation."""
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        """Resumes traffic generation."""
        with self._lock:
            self._paused = False

    def stop(self) -> None:
        """Stops the simulator background worker thread completely."""
        with self._lock:
            self._running = False
            self._paused = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def is_running(self) -> bool:
        with self._lock:
            return self._running and not self._paused

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused

    def _generate_client_ip(self) -> str:
        """Generates a realistic campus IP (e.g., 10.20.45.112)."""
        prefix, _ = random.choice(CAMPUS_SUBNETS)
        return f"{prefix}{random.randint(1, 254)}.{random.randint(2, 254)}"

    def _generate_packet(self) -> Dict[str, Any]:
        """Creates a single simulated network packet."""
        profile = random.choice(self._profile_pool)
        src_ip = self._generate_client_ip()
        src_port = random.randint(49152, 65535)  # Ephemeral client port
        protocol = profile["protocol"]
        size = random.randint(*profile["size_range"])

        # Determine destination IP based on application
        app_name = profile["app_name"]
        dst_port = profile["dst_port"]

        if app_name == "Unknown":
            # Pick a random unassigned high port
            dst_port = random.choice([7777, 8888, 9999, 13337, 23456, 31337, 45678, 55555])
            dst_ip = random.choice(EXTERNAL_SERVERS)[0]
        elif app_name in ("RADIUS Auth", "RADIUS Acct"):
            dst_ip = CAMPUS_SERVERS["RADIUS"]
        elif app_name in ("DNS",):
            dst_ip = random.choice([CAMPUS_SERVERS["DNS"], "8.8.8.8", "1.1.1.1"])
        elif app_name in ("MySQL", "PostgreSQL"):
            dst_ip = CAMPUS_SERVERS["DB_MYSQL"]
        elif app_name in ("Squid Proxy",):
            dst_ip = CAMPUS_SERVERS["SQUID_PROXY"]
        elif app_name in ("Kerberos", "LDAPS"):
            dst_ip = CAMPUS_SERVERS["DNS"] # Campus controller
        elif app_name in ("Telnet", "FTP-Control"):
            # Internal legacy switch or lab server
            dst_ip = f"10.30.0.{random.randint(10, 50)}"
        else:
            # External or Web server
            if random.random() < 0.3:
                dst_ip = CAMPUS_SERVERS["LMS_WEB"]
            else:
                dst_ip = random.choice(EXTERNAL_SERVERS)[0]

        # Use port_mapper to accurately resolve
        resolution = default_mapper.resolve_connection(src_port, dst_port, protocol)

        return {
            "epoch_time": time.time(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "app_name": resolution["application"],
            "category": resolution["category"],
            "packet_size": size,
            "is_unknown": not resolution["is_known"]
        }

    def _simulate_port_scan_burst(self) -> None:
        """
        Simulates an occasional rapid port scan from a rogue lab machine
        probing 25 common service ports to trigger the port scan alert.
        """
        scanner_ip = "10.30.5.99" # Lab workstation #99
        target_server = "172.16.1.50"
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080, 8443, 9000]

        for p in scan_ports:
            src_p = random.randint(50000, 60000)
            res = default_mapper.resolve_connection(src_p, p, "TCP")
            pkt = {
                "epoch_time": time.time(),
                "src_ip": scanner_ip,
                "src_port": src_p,
                "dst_ip": target_server,
                "dst_port": p,
                "protocol": "TCP",
                "app_name": res["application"],
                "category": res["category"],
                "packet_size": 44, # Small TCP SYN probe
                "is_unknown": not res["is_known"]
            }
            database.insert_packet(pkt)
            time.sleep(0.01)

    def _run_loop(self) -> None:
        """Main generator loop running on background thread."""
        while self._running:
            if self._paused:
                time.sleep(0.3)
                continue

            try:
                # Normal packet generation
                pkt = self._generate_packet()
                database.insert_packet(pkt)

                self._scan_counter += 1
                # Trigger a port scan burst every ~120 generated packets (~15-20 seconds)
                if self._scan_counter % 120 == 0:
                    self._simulate_port_scan_burst()

            except Exception as e:
                print(f"[Simulator Error] {e}")

            # Sleep to match target rate
            delay = 1.0 / max(self.packets_per_second, 1.0)
            # Add small random jitter (0.7x to 1.3x) to look natural
            time.sleep(delay * random.uniform(0.7, 1.3))

# Global simulator instance
default_simulator = TrafficSimulator()
