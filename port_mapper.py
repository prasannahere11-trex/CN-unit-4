"""
port_mapper.py - Port to Application Mapping Module
==================================================
This module is responsible for loading port definitions from 'ports.json'
and identifying the network application, category, and protocol for any
given TCP/UDP connection.

Viva Explanation Key Points:
1. Transport layer headers contain 16-bit Source and Destination port numbers (0 - 65535).
2. Well-known ports (0-1023) and registered ports (1024-49151) identify server services.
3. Ephemeral/dynamic ports (49152-65535, or 1024+ in older stacks) are assigned by the OS to clients.
4. When inspecting a packet, we inspect both ports and prefer the well-known/lower port as the application.
"""

import json
import os
from typing import Dict, Any, Optional, Tuple

class PortMapper:
    """
    PortMapper loads and caches port definitions from ports.json and provides
    fast O(1) lookup methods for packet inspection and user search.
    """

    def __init__(self, json_path: Optional[str] = None):
        if json_path is None:
            # Default to ports.json in the same directory as this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            json_path = os.path.join(base_dir, "ports.json")
        
        self.json_path = json_path
        # Lookup tables: (port, protocol) -> info dict
        self.table_by_proto_port: Dict[Tuple[int, str], Dict[str, Any]] = {}
        # Fallback table: port -> info dict (if protocol is generic or wildcard)
        self.table_by_port: Dict[int, Dict[str, Any]] = {}
        self.load_mappings()

    def load_mappings(self) -> None:
        """
        Loads and parses the JSON mappings file. If the file is not found
        or corrupted, initializes with safe fallback standard defaults.
        """
        self.table_by_proto_port.clear()
        self.table_by_port.clear()

        if not os.path.exists(self.json_path):
            print(f"[PortMapper Warning] {self.json_path} not found. Using minimal fallback.")
            self._load_fallback_defaults()
            return

        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                mappings = data.get("mappings", [])

                for item in mappings:
                    port = int(item["port"])
                    proto = item.get("protocol", "TCP").upper()
                    entry = {
                        "port": port,
                        "protocol": proto,
                        "name": item.get("name", f"Port {port}"),
                        "category": item.get("category", "Unknown"),
                        "description": item.get("description", "")
                    }
                    self.table_by_proto_port[(port, proto)] = entry
                    # In case of dual protocols, keep the first or most specific entry
                    if port not in self.table_by_port:
                        self.table_by_port[port] = entry

        except Exception as e:
            print(f"[PortMapper Error] Failed to load {self.json_path}: {e}")
            self._load_fallback_defaults()

    def _load_fallback_defaults(self) -> None:
        """Minimal essential mappings in case ports.json is missing."""
        defaults = [
            (80, "TCP", "HTTP", "Web", "Hypertext Transfer Protocol"),
            (443, "TCP", "HTTPS", "Web", "HTTP Secure over TLS/SSL"),
            (53, "UDP", "DNS", "Network Services", "Domain Name System"),
            (22, "TCP", "SSH", "Remote Access", "Secure Shell"),
            (21, "TCP", "FTP", "File Transfer", "File Transfer Protocol")
        ]
        for port, proto, name, category, desc in defaults:
            entry = {"port": port, "protocol": proto, "name": name, "category": category, "description": desc}
            self.table_by_proto_port[(port, proto)] = entry
            self.table_by_port[port] = entry

    def resolve_connection(self, src_port: int, dst_port: int, protocol: str) -> Dict[str, Any]:
        """
        Given a source port, destination port, and protocol (TCP/UDP),
        determines the primary application name, category, and whether it is known.

        Logic:
        1. Check (dst_port, protocol), then (dst_port, any).
        2. Check (src_port, protocol), then (src_port, any).
        3. If both match:
           - Prefer the lower port (server service port is almost always lower than client ephemeral port).
        4. If only one matches, use that matched application.
        5. If neither matches, classify as 'Unknown' on the destination/lower port.
        """
        proto = (protocol or "TCP").upper()

        dst_match = self.table_by_proto_port.get((dst_port, proto)) or self.table_by_port.get(dst_port)
        src_match = self.table_by_proto_port.get((src_port, proto)) or self.table_by_port.get(src_port)

        # Case 1: Both ports match known database entries
        if dst_match and src_match:
            # If they are different, pick the lower port (standard server port rule)
            if dst_port <= src_port:
                chosen = dst_match
                primary_port = dst_port
            else:
                chosen = src_match
                primary_port = src_port

            return {
                "application": chosen["name"],
                "category": chosen["category"],
                "description": chosen["description"],
                "primary_port": primary_port,
                "is_known": True
            }

        # Case 2: Destination port is a known service
        if dst_match:
            return {
                "application": dst_match["name"],
                "category": dst_match["category"],
                "description": dst_match["description"],
                "primary_port": dst_port,
                "is_known": True
            }

        # Case 3: Source port is a known service (e.g. server sending reply back to client)
        if src_match:
            return {
                "application": src_match["name"],
                "category": src_match["category"],
                "description": src_match["description"],
                "primary_port": src_port,
                "is_known": True
            }

        # Case 4: Neither is known -> Unknown Application
        # Use destination port or lower port as primary
        primary_port = min(src_port, dst_port) if min(src_port, dst_port) > 0 else dst_port
        return {
            "application": f"Unknown (Port {primary_port})",
            "category": "Unknown",
            "description": f"Unregistered or dynamic transport port ({proto}/{primary_port})",
            "primary_port": primary_port,
            "is_known": False
        }

    def lookup_port(self, port: int, protocol: Optional[str] = None) -> Dict[str, Any]:
        """
        Provides detailed lookup information for a specific port number.
        Used by the Port Lookup tool in the UI.
        """
        if protocol:
            proto = protocol.upper()
            match = self.table_by_proto_port.get((port, proto))
            if match:
                return {**match, "found": True}

        # Check in general table or try TCP then UDP
        match = self.table_by_proto_port.get((port, "TCP")) or \
                self.table_by_proto_port.get((port, "UDP")) or \
                self.table_by_port.get(port)

        if match:
            return {**match, "found": True}

        # If not found
        return {
            "port": port,
            "protocol": protocol.upper() if protocol else "TCP/UDP",
            "name": f"Unknown Port {port}",
            "category": "Unknown",
            "description": f"Port {port} is not in the recognized university service database.",
            "found": False
        }

    def get_all_mappings(self) -> list:
        """Returns all registered port mappings."""
        return list(self.table_by_proto_port.values())


# Singleton instance for application-wide use
default_mapper = PortMapper()
