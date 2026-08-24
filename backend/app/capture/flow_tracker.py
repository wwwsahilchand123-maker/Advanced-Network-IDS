"""
Flow Tracker
Tracks network flows (connections) based on 5-tuple
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict

from app.core.logging import get_logger

logger = get_logger(__name__)


class FlowTracker:
    """
    Track network flows for connection-based analysis
    """
    
    def __init__(
        self,
        flow_timeout: int = 300,  # 5 minutes
        max_flows: int = 100000
    ):
        """
        Initialize flow tracker
        
        Args:
            flow_timeout: Flow timeout in seconds
            max_flows: Maximum number of flows to track
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        
        # Flow storage: flow_id -> flow_data
        self.flows: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.total_flows = 0
        self.expired_flows = 0
        
        logger.info(f"Flow tracker initialized: timeout={flow_timeout}s, max_flows={max_flows}")
    
    def _generate_flow_id(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str
    ) -> str:
        """
        Generate unique flow ID from 5-tuple
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol (TCP, UDP, etc.)
            
        Returns:
            Flow ID hash
        """
        # Normalize flow direction for bidirectional tracking
        # (Sort IPs and ports to treat both directions as same flow)
        if src_ip < dst_ip:
            flow_tuple = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        elif src_ip > dst_ip:
            flow_tuple = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        else:  # Same IP
            if src_port <= dst_port:
                flow_tuple = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                flow_tuple = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        
        # Generate hash
        return hashlib.md5(flow_tuple.encode()).hexdigest()[:16]
    
    def track_packet(self, parsed_packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Track a packet and update flow statistics
        
        Args:
            parsed_packet: Parsed packet data
            
        Returns:
            Flow data dictionary, or None if packet cannot be tracked
        """
        try:
            # Extract 5-tuple
            src_ip = parsed_packet.get("src_ip")
            dst_ip = parsed_packet.get("dst_ip")
            src_port = parsed_packet.get("src_port", 0)
            dst_port = parsed_packet.get("dst_port", 0)
            protocol = parsed_packet.get("transport_protocol", parsed_packet.get("protocol"))
            
            if not (src_ip and dst_ip and protocol):
                return None
            
            # Generate flow ID
            flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Get or create flow
            if flow_id not in self.flows:
                # Check max flows limit
                if len(self.flows) >= self.max_flows:
                    self._cleanup_old_flows()
                
                # Create new flow
                self.flows[flow_id] = self._create_flow(
                    flow_id, src_ip, dst_ip, src_port, dst_port, protocol, parsed_packet
                )
                self.total_flows += 1
            
            # Update existing flow
            flow = self.flows[flow_id]
            self._update_flow(flow, parsed_packet)
            
            return flow
        
        except Exception as e:
            logger.error(f"Error tracking packet: {e}")
            return None
    
    def _create_flow(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        packet: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new flow
        
        Args:
            flow_id: Flow identifier
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol
            packet: Initial packet data
            
        Returns:
            New flow dictionary
        """
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "first_seen": packet["timestamp"],
            "last_seen": packet["timestamp"],
            "packet_count": 1,
            "byte_count": packet.get("length", 0),
            "src_bytes": packet.get("length", 0) if packet.get("src_ip") == src_ip else 0,
            "dst_bytes": packet.get("length", 0) if packet.get("dst_ip") == dst_ip else 0,
            "state": "NEW",
            "tcp_flags": defaultdict(int),
            "src_mac": packet.get("src_mac"),
            "dst_mac": packet.get("dst_mac"),
        }
    
    def _update_flow(self, flow: Dict[str, Any], packet: Dict[str, Any]) -> None:
        """
        Update flow with new packet
        
        Args:
            flow: Flow to update
            packet: New packet data
        """
        flow["last_seen"] = packet["timestamp"]
        flow["packet_count"] += 1
        flow["byte_count"] += packet.get("length", 0)
        
        # Update directional bytes
        if packet.get("src_ip") == flow["src_ip"]:
            flow["src_bytes"] += packet.get("length", 0)
        else:
            flow["dst_bytes"] += packet.get("length", 0)
        
        # Update TCP state if applicable
        if packet.get("transport_protocol") == "TCP":
            tcp_flags = packet.get("tcp_flags", {})
            
            # Update flag counts
            for flag, value in tcp_flags.items():
                if value:
                    flow["tcp_flags"][flag] += 1
            
            # Update state based on flags
            self._update_tcp_state(flow, tcp_flags)
    
    def _update_tcp_state(self, flow: Dict[str, Any], tcp_flags: Dict[str, bool]) -> None:
        """
        Update TCP flow state based on flags
        
        Args:
            flow: Flow to update
            tcp_flags: TCP flags from packet
        """
        current_state = flow["state"]
        
        if tcp_flags.get("RST"):
            flow["state"] = "RESET"
        
        elif tcp_flags.get("FIN"):
            if current_state == "ESTABLISHED":
                flow["state"] = "CLOSING"
            elif current_state == "CLOSING":
                flow["state"] = "CLOSED"
        
        elif tcp_flags.get("SYN") and tcp_flags.get("ACK"):
            if current_state == "NEW":
                flow["state"] = "SYN_ACK"
        
        elif tcp_flags.get("SYN"):
            flow["state"] = "SYN"
        
        elif tcp_flags.get("ACK"):
            if current_state in ["SYN", "SYN_ACK"]:
                flow["state"] = "ESTABLISHED"
    
    def _cleanup_old_flows(self) -> None:
        """
        Remove expired flows based on timeout
        """
        current_time = datetime.utcnow()
        timeout_delta = timedelta(seconds=self.flow_timeout)
        
        expired_flows = [
            flow_id for flow_id, flow in self.flows.items()
            if current_time - flow["last_seen"] > timeout_delta
        ]
        
        for flow_id in expired_flows:
            del self.flows[flow_id]
            self.expired_flows += 1
        
        if expired_flows:
            logger.debug(f"Cleaned up {len(expired_flows)} expired flows")
    
    def get_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get flow by ID
        
        Args:
            flow_id: Flow identifier
            
        Returns:
            Flow data or None
        """
        return self.flows.get(flow_id)
    
    def get_active_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get active flows sorted by last seen
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of active flows
        """
        flows = sorted(
            self.flows.values(),
            key=lambda x: x["last_seen"],
            reverse=True
        )
        
        return flows[:limit]
    
    def get_flows_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Get all flows involving an IP address
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            List of flows
        """
        return [
            flow for flow in self.flows.values()
            if flow["src_ip"] == ip_address or flow["dst_ip"] == ip_address
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get flow tracker statistics
        
        Returns:
            Statistics dictionary
        """
        active_flows = len(self.flows)
        
        # Protocol distribution
        protocol_dist = defaultdict(int)
        state_dist = defaultdict(int)
        
        for flow in self.flows.values():
            protocol_dist[flow["protocol"]] += 1
            state_dist[flow["state"]] += 1
        
        return {
            "total_flows": self.total_flows,
            "active_flows": active_flows,
            "expired_flows": self.expired_flows,
            "protocol_distribution": dict(protocol_dist),
            "state_distribution": dict(state_dist),
        }
    
    def clear_flows(self) -> None:
        """Clear all flows"""
        self.flows.clear()
        logger.info("All flows cleared")
