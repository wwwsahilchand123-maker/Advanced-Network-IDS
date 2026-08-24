"""
Tests for port scan detector
"""
import pytest
from datetime import datetime

from app.detection.detectors.port_scan import PortScanDetector


def test_vertical_scan_detection():
    """Test vertical port scan detection"""
    detector = PortScanDetector()
    
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"
    
    # Simulate scanning 30 ports
    for port in range(1, 31):
        packet = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000 + port,
            "dst_port": port,
            "transport_protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": False},
            "timestamp": datetime.utcnow(),
            "length": 60
        }
        
        result = detector.analyze(packet, None)
        
        # Should detect after threshold
        if port >= 25:
            assert result is not None
            assert result["rule_id"] == "SCAN_001"
            assert "vertical" in result["evidence"]["scan_type"]
            break


def test_horizontal_scan_detection():
    """Test horizontal port scan detection"""
    detector = PortScanDetector()
    
    src_ip = "192.168.1.100"
    port = 80
    
    # Simulate scanning 25 targets
    for i in range(1, 26):
        packet = {
            "src_ip": src_ip,
            "dst_ip": f"10.0.0.{i}",
            "src_port": 50000,
            "dst_port": port,
            "transport_protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": False},
            "timestamp": datetime.utcnow(),
            "length": 60
        }
        
        result = detector.analyze(packet, None)
        
        # Should detect after threshold
        if i >= 20:
            assert result is not None
            assert result["rule_id"] == "SCAN_002"
            assert "horizontal" in result["evidence"]["scan_type"]
            break
