"""
Tests for packet parser
"""
import pytest
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR

from app.capture.parser import PacketParser


def test_parse_tcp_packet():
    """Test parsing TCP packet"""
    parser = PacketParser()
    
    # Create TCP packet
    packet = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
    
    parsed = parser.parse(packet)
    
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.10"
    assert parsed["dst_ip"] == "10.0.0.1"
    assert parsed["src_port"] == 12345
    assert parsed["dst_port"] == 80
    assert parsed["transport_protocol"] == "TCP"
    assert parsed["tcp_flags"]["SYN"] is True
    assert parsed["tcp_flag_str"] == "S"


def test_parse_udp_packet():
    """Test parsing UDP packet"""
    parser = PacketParser()
    
    packet = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53)
    
    parsed = parser.parse(packet)
    
    assert parsed is not None
    assert parsed["transport_protocol"] == "UDP"
    assert parsed["src_port"] == 53
    assert parsed["dst_port"] == 53


def test_parse_arp_packet():
    """Test parsing ARP packet"""
    parser = PacketParser()
    
    packet = Ether() / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1")
    
    parsed = parser.parse(packet)
    
    assert parsed is not None
    assert parsed["protocol"] == "ARP"
    assert parsed["arp_op"] == "request"
    assert parsed["src_ip"] == "192.168.1.10"
    assert parsed["dst_ip"] == "192.168.1.1"


def test_parse_dns_query():
    """Test parsing DNS query"""
    parser = PacketParser()
    
    packet = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP() / DNS(qd=DNSQR(qname="example.com"))
    
    parsed = parser.parse(packet)
    
    assert parsed is not None
    assert parsed["dns_query"] is True
    assert len(parsed["dns_queries"]) > 0
    assert "example.com" in parsed["dns_queries"][0]["name"]
