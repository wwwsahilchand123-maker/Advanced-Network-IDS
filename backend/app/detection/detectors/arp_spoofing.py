"""
ARP Spoofing Detector
Detects ARP spoofing/poisoning attacks
"""
from typing import Dict, Any, Optional
from datetime import datetime

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class ARPSpoofingDetector(BaseDetector):
    """
    Detect ARP spoofing attacks
    
    Detection methods:
    - IP-MAC binding changes
    - Duplicate IP assignments
    - Gratuitous ARP anomalies
    - Gateway MAC changes
    """
    
    def __init__(self):
        """Initialize ARP spoofing detector"""
        super().__init__("ARPSpoofingDetector")
        
        # ARP cache: ip -> {mac, first_seen, last_seen, mac_history}
        self.arp_cache: Dict[str, Dict[str, Any]] = {}
        
        # Gateway tracking
        self.gateways = set()
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for ARP spoofing
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        # Only analyze ARP packets
        if packet.get("protocol") != "ARP":
            return None
        
        src_ip = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        arp_op = packet.get("arp_op")
        timestamp = packet.get("timestamp", datetime.utcnow())
        
        if not (src_ip and src_mac):
            return None
        
        # Track ARP binding
        detection = self._track_arp_binding(src_ip, src_mac, timestamp, arp_op)
        
        return detection
    
    def _track_arp_binding(
        self,
        ip: str,
        mac: str,
        timestamp: datetime,
        arp_op: str
    ) -> Optional[Dict[str, Any]]:
        """
        Track ARP IP-MAC binding
        
        Args:
            ip: IP address
            mac: MAC address
            timestamp: Packet timestamp
            arp_op: ARP operation
            
        Returns:
            Detection result or None
        """
        # Check if IP is already in cache
        if ip in self.arp_cache:
            cached = self.arp_cache[ip]
            cached_mac = cached["mac"]
            
            # MAC address changed
            if mac != cached_mac:
                # Check if this is a known MAC (might be legitimate change)
                mac_history = cached.get("mac_history", [])
                
                # Add old MAC to history
                if cached_mac not in mac_history:
                    mac_history.append({
                        "mac": cached_mac,
                        "last_seen": cached["last_seen"]
                    })
                
                # Update cache
                self.arp_cache[ip] = {
                    "mac": mac,
                    "first_seen": cached["first_seen"],
                    "last_seen": timestamp,
                    "mac_history": mac_history,
                    "change_count": cached.get("change_count", 0) + 1
                }
                
                change_count = self.arp_cache[ip]["change_count"]
                
                # Calculate confidence
                # More changes = higher confidence of attack
                confidence = min(100, 80 + (change_count * 5))
                
                # Check if this is a gateway
                is_gateway = ip in self.gateways or self._is_likely_gateway(ip)
                if is_gateway:
                    confidence = min(100, confidence + 15)
                    self.gateways.add(ip)
                
                return self._create_detection(
                    rule_id="ARP_001",
                    title="Possible ARP Spoofing Detected",
                    description=(
                        f"IP {ip} MAC address changed from {cached_mac} to {mac}"
                    ),
                    confidence=confidence,
                    evidence={
                        "ip_address": ip,
                        "previous_mac": cached_mac,
                        "new_mac": mac,
                        "change_count": change_count,
                        "mac_history": mac_history,
                        "is_gateway": is_gateway,
                        "arp_operation": arp_op,
                        "time_since_last_seen": (
                            timestamp - cached["last_seen"]
                        ).total_seconds()
                    }
                )
        else:
            # New IP-MAC binding
            self.arp_cache[ip] = {
                "mac": mac,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "mac_history": [],
                "change_count": 0
            }
        
        return None
    
    def _is_likely_gateway(self, ip: str) -> bool:
        """
        Check if IP is likely a gateway
        
        Args:
            ip: IP address
            
        Returns:
            True if likely a gateway
        """
        # Common gateway patterns
        parts = ip.split('.')
        if len(parts) == 4:
            last_octet = parts[3]
            # Common gateway addresses end in .1, .254, .255
            if last_octet in ['1', '254', '255']:
                return True
        
        return False
