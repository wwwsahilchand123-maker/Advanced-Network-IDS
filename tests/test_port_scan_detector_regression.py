from datetime import datetime, timedelta

from app.detection.detectors.port_scan import PortScanDetector


def _tcp_packet(dst_ip: str, dst_port: int, timestamp: datetime):
    return {
        "transport_protocol": "TCP",
        "src_ip": "10.0.0.50",
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "timestamp": timestamp,
        "tcp_flags": {"SYN": True, "ACK": False},
    }


def test_vertical_scan_triggers_at_threshold():
    detector = PortScanDetector()
    now = datetime.utcnow()
    result = None
    for port in range(1, detector.vertical_threshold + 1):
        result = detector.analyze(_tcp_packet("10.0.0.10", port, now + timedelta(milliseconds=port)))

    assert result is not None
    assert result["rule_id"] == "SCAN_001"
    assert result["detector"] == "PortScanDetector"
    assert result["confidence"] >= 70


def test_activity_outside_window_does_not_trigger():
    detector = PortScanDetector()
    now = datetime.utcnow()
    for port in range(1, detector.vertical_threshold):
        detector.analyze(_tcp_packet("10.0.0.10", port, now))

    result = detector.analyze(
        _tcp_packet(
            "10.0.0.10",
            detector.vertical_threshold,
            now + timedelta(seconds=detector.time_window + 1),
        )
    )

    assert result is None
