"""Tests for brute-force authentication detection."""
from datetime import datetime, timedelta

from app.detection.detectors.brute_force import BruteForceDetector


def _packet(timestamp, port=22):
    return {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.10",
        "dst_port": port,
        "transport_protocol": "TCP",
        "tcp_flags": {"SYN": True, "ACK": False},
        "timestamp": timestamp,
    }


def test_ssh_brute_force_triggers_after_threshold():
    detector = BruteForceDetector()
    start = datetime.utcnow()

    detection = None
    for attempt in range(detector.attempt_threshold):
        detection = detector.analyze(_packet(start + timedelta(seconds=attempt)), None)

    assert detection is not None
    assert detection["rule_id"] == "BRUTE_001"
    assert detection["evidence"]["service"] == "SSH"
    assert detection["evidence"]["attempt_count"] == detector.attempt_threshold


def test_non_monitored_port_is_ignored():
    detector = BruteForceDetector()
    packet = _packet(datetime.utcnow(), port=8080)

    assert detector.analyze(packet, None) is None
