"""
Suspicious Traffic Detector
Detects various suspicious network behaviors
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class SuspiciousTrafficDetector(BaseDetector):
    """
    Detect suspicious traffic patterns
    
    Detection methods:
    - Unusual outbound connections
    - Rare destination IPs
    - Suspicious TCP flag combinations
    - ICMP anomalies
    - Excessive connection failures
    """
    
    def __init__(self):
        """Initialize suspicious traffic detector"""
        super().__init__("SuspiciousTrafficDetector")
        
        # Track connection patterns
        self.connections: Dict[str, Dict] = defaultdict(
            lambda: {
                "destinations": set(),
                "failed_connections": 0,
                "unusual_flags": [],
                "icmp_count": 0
            }
        )
        
        # Suspicious ports (commonly used by malware/backdoors)
        self.suspicious_ports = {
            31337, 12345, 27374, 1243, 6667, 6668, 6669,  # Common backdoor ports
            4444, 5555, 7777, 8888, 9999,  # Common C2 ports
        }
        
        # Suspicious TCP flag combinations
        self.suspicious_flags = [
            {"FIN": True, "URG": True, "PSH": True},  # XMAS scan
            {"FIN": True, "SYN": False, "RST": False, "PSH": False, "ACK": False, "URG": False},  # FIN scan
            {},  # NULL scan (no flags)
        ]
        
        # Thresholds
        self.rare_dest_threshold = 5  # destinations before considering "rare"
        self.failed_conn_threshold = 10
        self.time_window = 300  # 5 minutes
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for suspicious patterns
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        protocol = packet.get("transport_protocol", packet.get("protocol"))
        
        if not (src_ip and dst_ip):
            return None
        
        # Check for suspicious ports
        if dst_port and dst_port in self.suspicious_ports:
            return self._detect_suspicious_port(src_ip, dst_ip, dst_port, protocol)
        
        # Check TCP flags
        if protocol == "TCP":
            tcp_flags = packet.get("tcp_flags", {})
            flag_detection = self._check_suspicious_flags(src_ip, dst_ip, tcp_flags)
            if flag_detection:
                return flag_detection
            
            # Track failed connections (RST packets)
            if tcp_flags.get("RST"):
                self.connections[src_ip]["failed_connections"] += 1
                
                if self.connections[src_ip]["failed_connections"] > self.failed_conn_threshold:
                    return self._detect_excessive_failures(src_ip)
        
        # Check ICMP anomalies
        if protocol == "ICMP":
            self.connections[src_ip]["icmp_count"] += 1
            icmp_type = packet.get("icmp_type")
            
            detection = self._check_icmp_anomaly(src_ip, dst_ip, icmp_type)
            if detection:
                return detection
        
        # Track destinations
        self.connections[src_ip]["destinations"].add(dst_ip)
        
        return None
    
    def _detect_suspicious_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str
    ) -> Dict[str, Any]:
        """
        Detect connection to suspicious port
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Destination port
            protocol: Protocol
            
        Returns:
            Detection result
        """
        return self._create_detection(
            rule_id="SUSP_001",
            title="Connection to Suspicious Port",
            description=(
                f"Connection detected from {src_ip} to {dst_ip}:{dst_port} "
                f"(commonly associated with malware/backdoors)"
            ),
            confidence=85,
            evidence={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "port_category": "suspicious",
                "common_uses": "Commonly used by malware, backdoors, or C2 communication"
            }
        )
    
    def _check_suspicious_flags(
        self,
        src_ip: str,
        dst_ip: str,
        tcp_flags: Dict[str, bool]
    ) -> Optional[Dict[str, Any]]:
        """
        Check for suspicious TCP flag combinations
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            tcp_flags: TCP flags
            
        Returns:
            Detection result or None
        """
        for suspicious_pattern in self.suspicious_flags:
            if self._flags_match_pattern(tcp_flags, suspicious_pattern):
                pattern_name = self._get_flag_pattern_name(suspicious_pattern)
                
                return self._create_detection(
                    rule_id="SUSP_002",
                    title=f"Suspicious TCP Flags Detected ({pattern_name})",
                    description=(
                        f"Unusual TCP flag combination from {src_ip} to {dst_ip}: {pattern_name}"
                    ),
                    confidence=90,
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "tcp_flags": tcp_flags,
                        "pattern": pattern_name,
                        "indicator": "Possible network scanning or fingerprinting"
                    }
                )
        
        return None
    
    def _flags_match_pattern(
        self,
        flags: Dict[str, bool],
        pattern: Dict[str, bool]
    ) -> bool:
        """
        Check if flags match suspicious pattern
        
        Args:
            flags: Actual TCP flags
            pattern: Pattern to match
            
        Returns:
            True if matches
        """
        # NULL scan: no flags set
        if not pattern and not any(flags.values()):
            return True
        
        # Check if all pattern flags match
        for flag, expected in pattern.items():
            if flags.get(flag, False) != expected:
                return False
        
        return True
    
    def _get_flag_pattern_name(self, pattern: Dict[str, bool]) -> str:
        """
        Get name of flag pattern
        
        Args:
            pattern: Flag pattern
            
        Returns:
            Pattern name
        """
        if not pattern:
            return "NULL scan"
        
        if pattern.get("FIN") and pattern.get("URG") and pattern.get("PSH"):
            return "XMAS scan"
        
        if pattern.get("FIN") and not pattern.get("ACK"):
            return "FIN scan"
        
        return "Unknown pattern"
    
    def _detect_excessive_failures(self, src_ip: str) -> Dict[str, Any]:
        """
        Detect excessive connection failures
        
        Args:
            src_ip: Source IP
            
        Returns:
            Detection result
        """
        failed_count = self.connections[src_ip]["failed_connections"]
        
        return self._create_detection(
            rule_id="SUSP_003",
            title="Excessive Connection Failures Detected",
            description=(
                f"Source {src_ip} has {failed_count} failed connection attempts"
            ),
            confidence=75,
            evidence={
                "src_ip": src_ip,
                "failed_connections": failed_count,
                "threshold": self.failed_conn_threshold,
                "indicator": "Possible scanning, connectivity issues, or denied access attempts"
            }
        )
    
    def _check_icmp_anomaly(
        self,
        src_ip: str,
        dst_ip: str,
        icmp_type: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        """
        Check for ICMP anomalies
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            icmp_type: ICMP type
            
        Returns:
            Detection result or None
        """
        icmp_count = self.connections[src_ip]["icmp_count"]
        
        # Excessive ICMP traffic
        if icmp_count > 100:
            return self._create_detection(
                rule_id="SUSP_004",
                title="Excessive ICMP Traffic Detected",
                description=(
                    f"Source {src_ip} generated {icmp_count} ICMP packets"
                ),
                confidence=70,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "icmp_count": icmp_count,
                    "icmp_type": icmp_type,
                    "indicator": "Possible ICMP flood, tunneling, or network scanning"
                }
            )
        
        return None
