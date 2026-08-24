"""
Brute Force Detector
Detects brute force authentication attempts
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class BruteForceDetector(BaseDetector):
    """
    Detect brute force authentication attempts
    
    Monitors:
    - SSH (port 22)
    - FTP (port 21)
    - HTTP/HTTPS (ports 80, 443)
    - RDP (port 3389)
    - Repeated connection attempts
    """
    
    def __init__(self):
        """Initialize brute force detector"""
        super().__init__("BruteForceDetector")
        
        # Track connection attempts per source
        # src_ip -> {service_port -> {timestamps: list, connection_count: int}}
        self.attempts: Dict[str, Dict[int, Dict]] = defaultdict(
            lambda: defaultdict(lambda: {"timestamps": [], "connection_count": 0})
        )
        
        # Monitored ports
        self.monitored_ports = {
            22: "SSH",
            21: "FTP",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
        }
        
        # Thresholds
        self.attempt_threshold = 10  # attempts
        self.time_window = 60  # seconds
        self.burst_threshold = 5  # attempts in 10 seconds
        self.burst_window = 10  # seconds
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for brute force patterns
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        # Only analyze TCP packets to monitored ports
        if packet.get("transport_protocol") != "TCP":
            return None
        
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp", datetime.utcnow())
        tcp_flags = packet.get("tcp_flags", {})
        
        if not (src_ip and dst_ip and dst_port):
            return None
        
        # Check if port is monitored
        if dst_port not in self.monitored_ports:
            return None
        
        service_name = self.monitored_ports[dst_port]
        
        # Track SYN packets (connection attempts)
        if tcp_flags.get("SYN") and not tcp_flags.get("ACK"):
            self._track_attempt(src_ip, dst_port, timestamp)
            
            # Clean old entries
            self._cleanup_old_entries(src_ip, dst_port, timestamp)
            
            # Check for brute force
            detection = self._check_brute_force(src_ip, dst_ip, dst_port, service_name)
            if detection:
                return detection
        
        return None
    
    def _track_attempt(self, src_ip: str, dst_port: int, timestamp: datetime) -> None:
        """
        Track a connection attempt
        
        Args:
            src_ip: Source IP
            dst_port: Destination port
            timestamp: Attempt timestamp
        """
        service = self.attempts[src_ip][dst_port]
        service["timestamps"].append(timestamp)
        service["connection_count"] += 1
    
    def _cleanup_old_entries(
        self,
        src_ip: str,
        dst_port: int,
        current_time: datetime
    ) -> None:
        """
        Remove old attempt entries
        
        Args:
            src_ip: Source IP
            dst_port: Destination port
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        if src_ip in self.attempts and dst_port in self.attempts[src_ip]:
            service = self.attempts[src_ip][dst_port]
            
            # Filter old timestamps
            service["timestamps"] = [
                ts for ts in service["timestamps"]
                if ts > cutoff_time
            ]
            
            # Remove if no recent activity
            if not service["timestamps"]:
                del self.attempts[src_ip][dst_port]
        
        # Remove source if no services
        if src_ip in self.attempts and not self.attempts[src_ip]:
            del self.attempts[src_ip]
    
    def _check_brute_force(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if attempts constitute brute force
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Service port
            service_name: Service name
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.attempts or dst_port not in self.attempts[src_ip]:
            return None
        
        service = self.attempts[src_ip][dst_port]
        attempt_count = len(service["timestamps"])
        
        if attempt_count < self.attempt_threshold:
            return None
        
        # Calculate confidence based on attempt frequency
        confidence = min(100, 70 + (attempt_count - self.attempt_threshold) * 2)
        
        # Check for burst pattern
        current_time = datetime.utcnow()
        burst_cutoff = current_time - timedelta(seconds=self.burst_window)
        recent_attempts = sum(1 for ts in service["timestamps"] if ts > burst_cutoff)
        
        is_burst = recent_attempts >= self.burst_threshold
        if is_burst:
            confidence = min(100, confidence + 15)
        
        # Calculate attempts per minute
        time_span = (
            service["timestamps"][-1] - service["timestamps"][0]
        ).total_seconds()
        attempts_per_minute = (attempt_count / time_span) * 60 if time_span > 0 else 0
        
        return self._create_detection(
            rule_id="BRUTE_001",
            title=f"Possible Brute Force Attack on {service_name}",
            description=(
                f"Source {src_ip} made {attempt_count} connection attempts "
                f"to {service_name} on {dst_ip}:{dst_port} within {self.time_window} seconds"
            ),
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "service": service_name,
                "attempt_count": attempt_count,
                "time_window": self.time_window,
                "is_burst_pattern": is_burst,
                "recent_burst_attempts": recent_attempts,
                "attempts_per_minute": round(attempts_per_minute, 2),
                "total_attempts": service["connection_count"]
            }
        )
