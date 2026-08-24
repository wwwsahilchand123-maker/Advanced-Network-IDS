"""
Port Scan Detector
Detects port scanning behavior
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class PortScanDetector(BaseDetector):
    """
    Detect port scanning activity
    
    Detection methods:
    - Vertical scan (many ports, one target)
    - Horizontal scan (one port, many targets)
    - SYN scan patterns
    - Failed connection patterns
    """
    
    def __init__(self):
        """Initialize port scan detector"""
        super().__init__("PortScanDetector")
        
        # Track connections per source IP
        # src_ip -> {dst_ip -> {ports: set, timestamps: list}}
        self.connections: Dict[str, Dict[str, Dict]] = defaultdict(
            lambda: defaultdict(lambda: {"ports": set(), "timestamps": []})
        )
        
        # Thresholds
        self.vertical_threshold = 25  # ports per target
        self.horizontal_threshold = 20  # targets per source
        self.time_window = 30  # seconds
        self.syn_ratio_threshold = 0.8  # SYN packets ratio
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for port scan patterns
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        # Only analyze TCP packets
        if packet.get("transport_protocol") != "TCP":
            return None
        
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp", datetime.utcnow())
        tcp_flags = packet.get("tcp_flags", {})
        
        if not (src_ip and dst_ip and dst_port):
            return None
        
        # Track connection
        self._track_connection(src_ip, dst_ip, dst_port, timestamp, tcp_flags)
        
        # Clean old entries
        self._cleanup_old_entries(src_ip, timestamp)
        
        # Check for vertical scan (many ports on one target)
        vertical_result = self._check_vertical_scan(src_ip, dst_ip)
        if vertical_result:
            return vertical_result
        
        # Check for horizontal scan (one port on many targets)
        horizontal_result = self._check_horizontal_scan(src_ip)
        if horizontal_result:
            return horizontal_result
        
        return None
    
    def _track_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: datetime,
        tcp_flags: Dict[str, bool]
    ) -> None:
        """
        Track a connection attempt
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Destination port
            timestamp: Packet timestamp
            tcp_flags: TCP flags
        """
        target = self.connections[src_ip][dst_ip]
        target["ports"].add(dst_port)
        target["timestamps"].append(timestamp)
        
        # Track SYN flags for scan detection
        if tcp_flags.get("SYN") and not tcp_flags.get("ACK"):
            if "syn_count" not in target:
                target["syn_count"] = 0
            target["syn_count"] += 1
    
    def _cleanup_old_entries(self, src_ip: str, current_time: datetime) -> None:
        """
        Remove entries older than time window
        
        Args:
            src_ip: Source IP to clean
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for dst_ip in list(self.connections[src_ip].keys()):
            target = self.connections[src_ip][dst_ip]
            
            # Filter old timestamps
            target["timestamps"] = [
                ts for ts in target["timestamps"]
                if ts > cutoff_time
            ]
            
            # Remove target if no recent activity
            if not target["timestamps"]:
                del self.connections[src_ip][dst_ip]
        
        # Remove source if no targets
        if not self.connections[src_ip]:
            del self.connections[src_ip]
    
    def _check_vertical_scan(
        self,
        src_ip: str,
        dst_ip: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check for vertical port scan (many ports, one target)
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.connections:
            return None
        
        target = self.connections[src_ip].get(dst_ip)
        if not target:
            return None
        
        ports_contacted = len(target["ports"])
        
        if ports_contacted >= self.vertical_threshold:
            # Calculate confidence
            confidence = min(100, 70 + (ports_contacted - self.vertical_threshold))
            
            # Check SYN ratio
            total_packets = len(target["timestamps"])
            syn_count = target.get("syn_count", 0)
            syn_ratio = syn_count / total_packets if total_packets > 0 else 0
            
            if syn_ratio > self.syn_ratio_threshold:
                confidence = min(100, confidence + 15)
            
            # Check if ports are sequential
            sorted_ports = sorted(target["ports"])
            sequential = self._check_sequential_ports(sorted_ports)
            if sequential:
                confidence = min(100, confidence + 10)
            
            return self._create_detection(
                rule_id="SCAN_001",
                title="Possible Vertical Port Scan Detected",
                description=(
                    f"Source {src_ip} contacted {ports_contacted} ports "
                    f"on target {dst_ip} within {self.time_window} seconds"
                ),
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports_contacted": ports_contacted,
                    "ports": sorted_ports[:50],  # Limit for readability
                    "time_window": self.time_window,
                    "syn_ratio": round(syn_ratio, 2),
                    "sequential_ports": sequential,
                    "scan_type": "vertical"
                }
            )
        
        return None
    
    def _check_horizontal_scan(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Check for horizontal port scan (one port, many targets)
        
        Args:
            src_ip: Source IP
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.connections:
            return None
        
        targets = self.connections[src_ip]
        num_targets = len(targets)
        
        if num_targets >= self.horizontal_threshold:
            # Find most common port
            port_counts = defaultdict(int)
            for target_data in targets.values():
                for port in target_data["ports"]:
                    port_counts[port] += 1
            
            most_common_port = max(port_counts.items(), key=lambda x: x[1]) if port_counts else (None, 0)
            
            confidence = min(100, 70 + (num_targets - self.horizontal_threshold))
            
            target_ips = list(targets.keys())
            
            return self._create_detection(
                rule_id="SCAN_002",
                title="Possible Horizontal Port Scan Detected",
                description=(
                    f"Source {src_ip} contacted {num_targets} different targets "
                    f"within {self.time_window} seconds"
                ),
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "targets_contacted": num_targets,
                    "target_ips": target_ips[:50],  # Limit for readability
                    "most_common_port": most_common_port[0],
                    "time_window": self.time_window,
                    "scan_type": "horizontal"
                }
            )
        
        return None
    
    def _check_sequential_ports(self, ports: list) -> bool:
        """
        Check if ports are mostly sequential
        
        Args:
            ports: Sorted list of ports
            
        Returns:
            True if ports appear sequential
        """
        if len(ports) < 3:
            return False
        
        sequential_count = 0
        for i in range(len(ports) - 1):
            if ports[i + 1] - ports[i] == 1:
                sequential_count += 1
        
        # Consider sequential if >70% of transitions are consecutive
        return (sequential_count / (len(ports) - 1)) > 0.7
