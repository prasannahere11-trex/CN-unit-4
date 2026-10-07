"""
tests/test_port_mapper.py - Unit Tests for Port to Application Mapper
====================================================================
Tests cover:
1. Well-known port resolutions (HTTP, HTTPS, SSH, DNS, RADIUS).
2. Unknown / unassigned ports.
3. Both-ports-known conflict resolution (lower/server port preference).
4. Protocol differentiation (TCP vs UDP, e.g. QUIC UDP 443 vs HTTPS TCP 443).
5. Interactive port lookup helper.
"""

import os
import sys
import pytest

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from port_mapper import PortMapper

@pytest.fixture
def mapper():
    """Fixture providing a configured PortMapper instance."""
    return PortMapper()

def test_known_destination_port_http(mapper):
    """Client with ephemeral port connecting to Web HTTP port 80."""
    res = mapper.resolve_connection(src_port=52344, dst_port=80, protocol="TCP")
    assert res["is_known"] is True
    assert res["application"] == "HTTP"
    assert res["category"] == "Web"
    assert res["primary_port"] == 80

def test_known_destination_port_https(mapper):
    """Client connecting to HTTPS port 443 over TCP."""
    res = mapper.resolve_connection(src_port=61234, dst_port=443, protocol="TCP")
    assert res["is_known"] is True
    assert res["application"] == "HTTPS"
    assert res["category"] == "Web"
    assert res["primary_port"] == 443

def test_protocol_differentiation_quic_vs_https(mapper):
    """Port 443 over UDP is HTTP/3 (QUIC), while over TCP is HTTPS."""
    res_tcp = mapper.resolve_connection(src_port=55100, dst_port=443, protocol="TCP")
    res_udp = mapper.resolve_connection(src_port=55100, dst_port=443, protocol="UDP")
    
    assert res_tcp["application"] == "HTTPS"
    assert res_udp["application"] == "HTTP/3 (QUIC)"
    assert res_tcp["category"] == "Web"
    assert res_udp["category"] == "Web"

def test_dns_udp_vs_tcp(mapper):
    """DNS queries over UDP port 53."""
    res = mapper.resolve_connection(src_port=54321, dst_port=53, protocol="UDP")
    assert res["is_known"] is True
    assert res["application"] == "DNS"
    assert res["category"] == "Network Services"

def test_campus_specific_radius(mapper):
    """RADIUS Eduroam authentication on UDP 1812."""
    res = mapper.resolve_connection(src_port=49912, dst_port=1812, protocol="UDP")
    assert res["is_known"] is True
    assert "RADIUS" in res["application"]
    assert res["category"] == "Campus-Specific"

def test_server_response_source_port_known(mapper):
    """Server sending packets back from port 443 to client port 52344."""
    res = mapper.resolve_connection(src_port=443, dst_port=52344, protocol="TCP")
    assert res["is_known"] is True
    assert res["application"] == "HTTPS"
    assert res["primary_port"] == 443

def test_both_ports_known_picks_lower_server_port(mapper):
    """When both ports are recognized services, prioritize the lower/server port."""
    # E.g. Port 80 (HTTP) to Port 8080 (HTTP-Alt)
    res = mapper.resolve_connection(src_port=8080, dst_port=80, protocol="TCP")
    assert res["is_known"] is True
    assert res["primary_port"] == 80
    assert res["application"] == "HTTP"

def test_unknown_ports(mapper):
    """Both ports are unassigned/high ports."""
    res = mapper.resolve_connection(src_port=59123, dst_port=61234, protocol="TCP")
    assert res["is_known"] is False
    assert "Unknown" in res["application"]
    assert res["category"] == "Unknown"

def test_port_lookup_tool(mapper):
    """Instant lookup for individual port metadata."""
    ssh_info = mapper.lookup_port(22, "TCP")
    assert ssh_info["found"] is True
    assert "SSH" in ssh_info["name"]
    assert ssh_info["category"] == "Remote Access"

    unknown_info = mapper.lookup_port(49999)
    assert unknown_info["found"] is False
    assert unknown_info["category"] == "Unknown"
