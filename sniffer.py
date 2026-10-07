"""
sniffer.py - Live Packet Sniffing Module using Scapy
===================================================
Captures real-time TCP and UDP network packets from a specified network interface,
extracts transport headers, resolves applications via port_mapper, and stores
traffic metadata in SQLite.

Viva Explanation Key Points:
1. Packet Sniffing operates at Layer 2/Layer 3 by putting the network interface
   into promiscuous mode (with OS driver support, e.g., Npcap on Windows or AF_PACKET on Linux).
2. Scapy filters packets in kernel space using BPF (Berkeley Packet Filter) syntax: 'tcp or udp'.
3. Only header metadata (IPs, Ports, Protocol, Length) is stored - payload contents are NEVER logged
   to ensure privacy and network compliance.
"""

import threading
import time
from typing import Dict, Any, List, Optional, Tuple
import database
from port_mapper import default_mapper

# Safe import of Scapy with graceful fallback
SCAPY_AVAILABLE = False
SCAPY_ERROR_MSG = ""
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, get_if_list, conf
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_ERROR_MSG = str(e)

class LiveSniffer:
    """
    Live packet sniffer running Scapy in a background thread.
    """

    def __init__(self):
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._interface: Optional[str] = None
        self._lock = threading.Lock()
        self._error_status: Optional[str] = None
        self._packets_captured = 0

    @staticmethod
    def get_interfaces() -> List[Dict[str, str]]:
        """
        Returns a list of detected network interfaces available for packet capture.
        """
        if not SCAPY_AVAILABLE:
            return [{"id": "default", "name": "Default Interface (Scapy Unavailable)"}]
        
        try:
            if_list = get_if_list()
            results = []
            for iface in if_list:
                results.append({"id": str(iface), "name": str(iface)})
            return results if results else [{"id": "default", "name": "Default Interface"}]
        except Exception as e:
            return [{"id": "default", "name": f"Default Interface ({e})"}]

    def start(self, interface: Optional[str] = None) -> Tuple[bool, str]:
        """
        Starts live packet capture on the given interface.
        Returns (success: bool, message: str).
        """
        if not SCAPY_AVAILABLE:
            self._error_status = f"Scapy or Npcap/libpcap driver not available: {SCAPY_ERROR_MSG}"
            return False, self._error_status

        with self._lock:
            if self._running and self._thread and self._thread.is_alive():
                self._paused = False
                return True, "Live sniffer already running."

            self._running = True
            self._paused = False
            self._interface = interface if (interface and interface != "default") else None
            self._error_status = None
            self._thread = threading.Thread(target=self._sniff_worker, daemon=True, name="ScapySnifferThread")
            self._thread.start()

        return True, "Live sniffer started successfully."

    def pause(self) -> None:
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        with self._lock:
            self._paused = False

    def stop(self) -> None:
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

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._running and not self._paused,
                "paused": self._paused,
                "interface": self._interface or "Default / Any",
                "scapy_available": SCAPY_AVAILABLE,
                "error": self._error_status,
                "packets_captured": self._packets_captured
            }

    def _process_packet(self, packet) -> None:
        """Callback invoked by Scapy for each captured TCP/UDP packet."""
        if not self._running or self._paused:
            return

        try:
            # Extract IP layer
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return  # Skip non-IP traffic

            # Extract Transport layer (TCP or UDP)
            protocol = "TCP"
            src_port = 0
            dst_port = 0

            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                return

            # Packet wire size
            pkt_size = len(packet)

            # Resolve application and category via port_mapper
            res = default_mapper.resolve_connection(src_port, dst_port, protocol)

            pkt_dict = {
                "epoch_time": time.time(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "app_name": res["application"],
                "category": res["category"],
                "packet_size": pkt_size,
                "is_unknown": not res["is_known"]
            }

            database.insert_packet(pkt_dict)
            self._packets_captured += 1

        except Exception as e:
            # Avoid crashing the sniffing loop on corrupted malformed frames
            pass

    def _sniff_worker(self) -> None:
        """Worker thread executing Scapy's sniff loop."""
        try:
            kwargs = {
                "prn": self._process_packet,
                "filter": "tcp or udp",
                "store": False,
                "stop_filter": lambda x: not self._running
            }
            if self._interface:
                kwargs["iface"] = self._interface

            sniff(**kwargs)
        except Exception as e:
            self._error_status = f"Live sniff failed: {e}. (On Windows, verify Npcap is installed. On Linux/macOS, run as root/sudo)."
            print(f"[Sniffer Error] {self._error_status}")
            self._running = False


# Global sniffer instance
default_sniffer = LiveSniffer()
