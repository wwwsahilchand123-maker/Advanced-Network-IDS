# PHASE 3: Packet Capture Engine

Building the complete network packet capture, parsing, and flow tracking system.

---

## 📁 File 43: `backend/app/capture/__init__.py`

```
Python
```

```
"""
Packet capture module initialization
"""
```

---

## 📁 File 44: `backend/app/capture/engine.py`

```
Python
```

```
"""
Packet Capture Engine
Real-time network traffic capture using Scapy
"""
import asyncio
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime
import threading
from collections import defaultdict

from scapy.all import sniff, AsyncSniffer, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS

from app.core.logging import get_logger
from app.capture.parser import PacketParser
from app.capture.flow_tracker import FlowTracker

logger = get_logger(__name__)


class CaptureEngine:
    """
    Main packet capture engine
    
    Handles real-time packet capture from network interfaces
    """
    
    def __init__(
        self,
        interface: str = "eth0",
        callback: Optional[Callable] = None,
        buffer_size: int = 2048,
        promisc: bool = True
    ):
        """
        Initialize capture engine
        
        Args:
            interface: Network interface to capture from
            callback: Callback function for processed packets
            buffer_size: Packet buffer size
            promisc: Enable promiscuous mode
        """
        self.interface = interface
        self.callback = callback
        self.buffer_size = buffer_size
        self.promisc = promisc
        
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker()
        
        self.is_running = False
        self.sniffer: Optional[AsyncSniffer] = None
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "packets_by_protocol": defaultdict(int),
            "packets_by_interface": defaultdict(int),
            "start_time": None,
            "last_packet_time": None,
        }
        
        # Filters
        self.capture_filter: Optional[str] = None
        
        logger.info(f"Capture engine initialized for interface: {interface}")
    
    def set_filter(self, bpf_filter: str) -> None:
        """
        Set BPF capture filter
        
        Args:
            bpf_filter: Berkeley Packet Filter expression
            
        Example:
            engine.set_filter("tcp port 80 or tcp port 443")
        """
        self.capture_filter = bpf_filter
        logger.info(f"Capture filter set: {bpf_filter}")
    
    def _packet_handler(self, packet: Packet) -> None:
        """
        Handle captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Update statistics
            self.stats["total_packets"] += 1
            self.stats["last_packet_time"] = datetime.utcnow()
            
            if hasattr(packet, 'len'):
                self.stats["total_bytes"] += packet.len
            
            # Parse packet
            parsed_packet = self.parser.parse(packet)
            
            if parsed_packet:
                # Update protocol statistics
                protocol = parsed_packet.get("protocol", "Unknown")
                self.stats["packets_by_protocol"][protocol] += 1
                
                # Update interface statistics
                interface = parsed_packet.get("interface", self.interface)
                self.stats["packets_by_interface"][interface] += 1
                
                # Track flow
                flow = self.flow_tracker.track_packet(parsed_packet)
                
                # Add flow information to parsed packet
                if flow:
                    parsed_packet["flow_id"] = flow["flow_id"]
                    parsed_packet["flow_state"] = flow.get("state")
                
                # Call callback if provided
                if self.callback:
                    self.callback(parsed_packet, flow)
        
        except Exception as e:
            logger.error(f"Error handling packet: {e}", exc_info=True)
    
    def start(self) -> bool:
        """
        Start packet capture
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_running:
            logger.warning("Capture engine already running")
            return False
        
        try:
            logger.info(f"Starting packet capture on {self.interface}")
            
            # Initialize sniffer
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,  # Don't store packets in memory
                filter=self.capture_filter,
                promisc=self.promisc
            )
            
            # Start capture
            self.sniffer.start()
            self.is_running = True
            self.stats["start_time"] = datetime.utcnow()
            
            logger.info("Packet capture started successfully")
            return True
            
        except PermissionError:
            logger.error(
                "Permission denied. Packet capture requires root/administrator privileges "
                "or CAP_NET_RAW capability."
            )
            return False
        
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}", exc_info=True)
            return False
    
    def stop(self) -> bool:
        """
        Stop packet capture
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.is_running:
            logger.warning("Capture engine not running")
            return False
        
        try:
            logger.info("Stopping packet capture")
            
            if self.sniffer:
                self.sniffer.stop()
            
            self.is_running = False
            logger.info("Packet capture stopped")
            
            # Log final statistics
            self._log_statistics()
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping packet capture: {e}", exc_info=True)
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get capture statistics
        
        Returns:
            Dictionary containing statistics
        """
        stats = self.stats.copy()
        
        # Calculate packets per second
        if stats["start_time"]:
            duration = (datetime.utcnow() - stats["start_time"]).total_seconds()
            if duration > 0:
                stats["packets_per_second"] = stats["total_packets"] / duration
            else:
                stats["packets_per_second"] = 0
        else:
            stats["packets_per_second"] = 0
        
        # Convert defaultdict to regular dict
        stats["packets_by_protocol"] = dict(stats["packets_by_protocol"])
        stats["packets_by_interface"] = dict(stats["packets_by_interface"])
        
        # Add flow statistics
        stats["flow_stats"] = self.flow_tracker.get_statistics()
        
        return stats
    
    def get_active_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get active network flows
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of active flows
        """
        return self.flow_tracker.get_active_flows(limit)
    
    def clear_statistics(self) -> None:
        """Clear all statistics"""
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "packets_by_protocol": defaultdict(int),
            "packets_by_interface": defaultdict(int),
            "start_time": None,
            "last_packet_time": None,
        }
        
        self.flow_tracker.clear_flows()
        logger.info("Statistics cleared")
    
    def _log_statistics(self) -> None:
        """Log current statistics"""
        stats = self.get_statistics()
        
        logger.info("=== Capture Statistics ===")
        logger.info(f"Total Packets: {stats['total_packets']}")
        logger.info(f"Total Bytes: {stats['total_bytes']}")
        logger.info(f"Packets/sec: {stats['packets_per_second']:.2f}")
        logger.info(f"Protocol Distribution: {stats['packets_by_protocol']}")
        logger.info(f"Active Flows: {stats['flow_stats'].get('active_flows', 0)}")
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


class CaptureSession:
    """
    Manages a packet capture session with lifecycle management
    """
    
    def __init__(
        self,
        interface: str,
        duration: Optional[int] = None,
        packet_count: Optional[int] = None,
        bpf_filter: Optional[str] = None
    ):
        """
        Initialize capture session
        
        Args:
            interface: Network interface
            duration: Maximum capture duration in seconds
            packet_count: Maximum number of packets to capture
            bpf_filter: BPF filter expression
        """
        self.interface = interface
        self.duration = duration
        self.packet_count = packet_count
        self.bpf_filter = bpf_filter
        
        self.engine: Optional[CaptureEngine] = None
        self.packets_captured = 0
        self.start_time: Optional[datetime] = None
        
        logger.info(
            f"Capture session initialized: interface={interface}, "
            f"duration={duration}s, max_packets={packet_count}"
        )
    
    def packet_callback(self, packet: Dict[str, Any], flow: Optional[Dict[str, Any]]) -> None:
        """
        Handle captured packet
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
        """
        self.packets_captured += 1
        
        # Check if packet count limit reached
        if self.packet_count and self.packets_captured >= self.packet_count:
            logger.info(f"Packet count limit reached: {self.packet_count}")
            self.stop()
    
    def start(self) -> bool:
        """
        Start capture session
        
        Returns:
            True if started successfully
        """
        self.engine = CaptureEngine(
            interface=self.interface,
            callback=self.packet_callback
        )
        
        if self.bpf_filter:
            self.engine.set_filter(self.bpf_filter)
        
        self.start_time = datetime.utcnow()
        
        if self.engine.start():
            # Schedule duration-based stop if specified
            if self.duration:
                threading.Timer(self.duration, self.stop).start()
            
            return True
        
        return False
    
    def stop(self) -> Dict[str, Any]:
        """
        Stop capture session
        
        Returns:
            Session statistics
        """
        if self.engine:
            self.engine.stop()
            
            stats = self.engine.get_statistics()
            stats["session_duration"] = (
                datetime.utcnow() - self.start_time
            ).total_seconds() if self.start_time else 0
            
            return stats
        
        return {}
```

---

## 📁 File 45: `backend/app/capture/parser.py`

```
Python
```

```
"""
Packet Parser
Extracts relevant information from network packets
"""
from typing import Optional, Dict, Any
from datetime import datetime

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from app.core.logging import get_logger

logger = get_logger(__name__)


class PacketParser:
    """
    Parse network packets and extract relevant information
    """
    
    def __init__(self):
        """Initialize packet parser"""
        self.packet_count = 0
    
    def parse(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Parse a packet and extract information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing parsed packet data, or None if parsing fails
        """
        try:
            self.packet_count += 1
            
            parsed = {
                "timestamp": datetime.utcnow(),
                "packet_id": self.packet_count,
                "length": len(packet) if hasattr(packet, '__len__') else 0,
            }
            
            # Parse Ethernet layer
            if packet.haslayer(Ether):
                ether = packet[Ether]
                parsed["src_mac"] = ether.src
                parsed["dst_mac"] = ether.dst
                parsed["ether_type"] = ether.type
            
            # Parse IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                parsed.update(self._parse_ip(ip))
            
            # Parse IPv6 layer
            elif packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                parsed.update(self._parse_ipv6(ipv6))
            
            # Parse ARP layer
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                parsed.update(self._parse_arp(arp))
            
            # Parse transport layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                parsed.update(self._parse_tcp(tcp))
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                parsed.update(self._parse_udp(udp))
            
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                parsed.update(self._parse_icmp(icmp))
            
            # Parse DNS layer
            if packet.haslayer(DNS):
                dns = packet[DNS]
                parsed.update(self._parse_dns(dns))
            
            return parsed
        
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    def _parse_ip(self, ip: IP) -> Dict[str, Any]:
        """
        Parse IP layer
        
        Args:
            ip: Scapy IP layer
            
        Returns:
            Parsed IP data
        """
        return {
            "protocol": "IP",
            "ip_version": ip.version,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": ip.ttl,
            "ip_length": ip.len,
            "ip_flags": str(ip.flags),
            "ip_proto": ip.proto,
        }
    
    def _parse_ipv6(self, ipv6: IPv6) -> Dict[str, Any]:
        """
        Parse IPv6 layer
        
        Args:
            ipv6: Scapy IPv6 layer
            
        Returns:
            Parsed IPv6 data
        """
        return {
            "protocol": "IPv6",
            "ip_version": 6,
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "hop_limit": ipv6.hlim,
            "traffic_class": ipv6.tc,
        }
    
    def _parse_tcp(self, tcp: TCP) -> Dict[str, Any]:
        """
        Parse TCP layer
        
        Args:
            tcp: Scapy TCP layer
            
        Returns:
            Parsed TCP data
        """
        # Extract TCP flags
        flags = {
            "FIN": bool(tcp.flags & 0x01),
            "SYN": bool(tcp.flags & 0x02),
            "RST": bool(tcp.flags & 0x04),
            "PSH": bool(tcp.flags & 0x08),
            "ACK": bool(tcp.flags & 0x10),
            "URG": bool(tcp.flags & 0x20),
        }
        
        # Create flag string (e.g., "SA" for SYN-ACK)
        flag_str = ""
        if flags["SYN"]: flag_str += "S"
        if flags["ACK"]: flag_str += "A"
        if flags["FIN"]: flag_str += "F"
        if flags["RST"]: flag_str += "R"
        if flags["PSH"]: flag_str += "P"
        if flags["URG"]: flag_str += "U"
        
        return {
            "transport_protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_seq": tcp.seq,
            "tcp_ack": tcp.ack,
            "tcp_flags": flags,
            "tcp_flag_str": flag_str or "NONE",
            "tcp_window": tcp.window,
        }
    
    def _parse_udp(self, udp: UDP) -> Dict[str, Any]:
        """
        Parse UDP layer
        
        Args:
            udp: Scapy UDP layer
            
        Returns:
            Parsed UDP data
        """
        return {
            "transport_protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "udp_length": udp.len,
        }
    
    def _parse_icmp(self, icmp: ICMP) -> Dict[str, Any]:
        """
        Parse ICMP layer
        
        Args:
            icmp: Scapy ICMP layer
            
        Returns:
            Parsed ICMP data
        """
        return {
            "transport_protocol": "ICMP",
            "icmp_type": icmp.type,
            "icmp_code": icmp.code,
            "icmp_id": getattr(icmp, 'id', None),
            "icmp_seq": getattr(icmp, 'seq', None),
        }
    
    def _parse_arp(self, arp: ARP) -> Dict[str, Any]:
        """
        Parse ARP layer
        
        Args:
            arp: Scapy ARP layer
            
        Returns:
            Parsed ARP data
        """
        # ARP operation codes
        op_codes = {
            1: "request",
            2: "reply",
        }
        
        return {
            "protocol": "ARP",
            "arp_op": op_codes.get(arp.op, str(arp.op)),
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "src_mac": arp.hwsrc,
            "dst_mac": arp.hwdst,
        }
    
    def _parse_dns(self, dns: DNS) -> Dict[str, Any]:
        """
        Parse DNS layer
        
        Args:
            dns: Scapy DNS layer
            
        Returns:
            Parsed DNS data
        """
        parsed = {
            "dns_query": False,
            "dns_response": False,
            "dns_queries": [],
            "dns_answers": [],
        }
        
        # Check if this is a query or response
        if dns.qr == 0:  # Query
            parsed["dns_query"] = True
            
            # Extract queries
            if dns.qd:
                query = dns.qd
                if hasattr(query, 'qname'):
                    qname = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
                    parsed["dns_queries"].append({
                        "name": qname.rstrip('.'),
                        "type": query.qtype,
                        "class": query.qclass,
                    })
        
        else:  # Response
            parsed["dns_response"] = True
            parsed["dns_rcode"] = dns.rcode
            
            # Extract answers
            if dns.an:
                answer = dns.an
                count = 0
                while answer and count < 10:  # Limit to prevent infinite loops
                    if hasattr(answer, 'rdata'):
                        rdata = answer.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors='ignore')
                        
                        parsed["dns_answers"].append({
                            "name": getattr(answer, 'rrname', b'').decode(errors='ignore').rstrip('.'),
                            "type": getattr(answer, 'type', None),
                            "data": str(rdata),
                            "ttl": getattr(answer, 'ttl', None),
                        })
                    
                    answer = answer.payload if hasattr(answer, 'payload') else None
                    count += 1
        
        return parsed
    
    def get_five_tuple(self, parsed_packet: Dict[str, Any]) -> Optional[tuple]:
        """
        Extract 5-tuple from parsed packet for flow identification
        
        Args:
            parsed_packet: Parsed packet dictionary
            
        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        try:
            src_ip = parsed_packet.get("src_ip")
            dst_ip = parsed_packet.get("dst_ip")
            src_port = parsed_packet.get("src_port", 0)
            dst_port = parsed_packet.get("dst_port", 0)
            protocol = parsed_packet.get("transport_protocol", parsed_packet.get("protocol", "Unknown"))
            
            if src_ip and dst_ip:
                return (src_ip, dst_ip, src_port, dst_port, protocol)
        
        except Exception as e:
            logger.error(f"Error extracting 5-tuple: {e}")
        
        return None
```

---

## 📁 File 46: `backend/app/capture/flow_tracker.py`

```
Python
```

```
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
```

---

## 📁 File 47: `backend/app/capture/pcap_analyzer.py`

```
Python
```

```
"""
PCAP File Analyzer
Offline analysis of PCAP files
"""
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from datetime import datetime

from scapy.all import rdpcap, PcapReader, Packet

from app.core.logging import get_logger
from app.capture.parser import PacketParser
from app.capture.flow_tracker import FlowTracker

logger = get_logger(__name__)


class PcapAnalyzer:
    """
    Analyze PCAP files offline
    """
    
    def __init__(self, pcap_path: str):
        """
        Initialize PCAP analyzer
        
        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = Path(pcap_path)
        
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker()
        
        # Analysis results
        self.packets: List[Dict[str, Any]] = []
        self.statistics: Dict[str, Any] = {}
        
        logger.info(f"PCAP analyzer initialized for: {pcap_path}")
    
    def analyze(
        self,
        callback: Optional[Callable] = None,
        max_packets: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyze PCAP file
        
        Args:
            callback: Optional callback function for each packet
            max_packets: Maximum number of packets to analyze
            
        Returns:
            Analysis results
        """
        logger.info(f"Starting analysis of {self.pcap_path}")
        start_time = datetime.utcnow()
        
        packet_count = 0
        total_bytes = 0
        
        try:
            # Use PcapReader for memory efficiency with large files
            with PcapReader(str(self.pcap_path)) as pcap_reader:
                for packet in pcap_reader:
                    # Check packet limit
                    if max_packets and packet_count >= max_packets:
                        break
                    
                    # Parse packet
                    parsed = self.parser.parse(packet)
                    
                    if parsed:
                        packet_count += 1
                        total_bytes += parsed.get("length", 0)
                        
                        # Track flow
                        flow = self.flow_tracker.track_packet(parsed)
                        
                        # Store packet (optional, can be memory intensive)
                        # self.packets.append(parsed)
                        
                        # Call callback if provided
                        if callback:
                            callback(parsed, flow)
        
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}", exc_info=True)
            raise
        
        # Calculate statistics
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        self.statistics = {
            "filename": self.pcap_path.name,
            "file_size": self.pcap_path.stat().st_size,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "duration_seconds": duration,
            "packets_per_second": packet_count / duration if duration > 0 else 0,
            "flow_stats": self.flow_tracker.get_statistics(),
            "analyzed_at": datetime.utcnow(),
        }
        
        logger.info(
            f"Analysis complete: {packet_count} packets, "
            f"{self.statistics['flow_stats']['active_flows']} flows, "
            f"{duration:.2f}s"
        )
        
        return self.statistics
    
    def get_flows(self) -> List[Dict[str, Any]]:
        """
        Get all flows from analysis
        
        Returns:
            List of flows
        """
        return self.flow_tracker.get_active_flows(limit=10000)
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get protocol distribution
        
        Returns:
            Dictionary of protocol counts
        """
        return self.statistics.get("flow_stats", {}).get("protocol_distribution", {})
    
    def get_top_talkers(self, limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get top source and destination IPs
        
        Args:
            limit: Number of top talkers to return
            
        Returns:
            Dictionary with top sources and destinations
        """
        flows = self.flow_tracker.get_active_flows(limit=10000)
        
        # Count packets per IP
        src_counts = {}
        dst_counts = {}
        
        for flow in flows:
            src_ip = flow["src_ip"]
            dst_ip = flow["dst_ip"]
            packet_count = flow["packet_count"]
            byte_count = flow["byte_count"]
            
            if src_ip not in src_counts:
                src_counts[src_ip] = {"packets": 0, "bytes": 0}
            src_counts[src_ip]["packets"] += packet_count
            src_counts[src_ip]["bytes"] += byte_count
            
            if dst_ip not in dst_counts:
                dst_counts[dst_ip] = {"packets": 0, "bytes": 0}
            dst_counts[dst_ip]["packets"] += packet_count
            dst_counts[dst_ip]["bytes"] += byte_count
        
        # Sort and limit
        top_sources = sorted(
            [{"ip": ip, **counts} for ip, counts in src_counts.items()],
            key=lambda x: x["packets"],
            reverse=True
        )[:limit]
        
        top_destinations = sorted(
            [{"ip": ip, **counts} for ip, counts in dst_counts.items()],
            key=lambda x: x["packets"],
            reverse=True
        )[:limit]
        
        return {
            "top_sources": top_sources,
            "top_destinations": top_destinations
        }
    
    def get_summary(self) -> str:
        """
        Get analysis summary
        
        Returns:
            Summary string
        """
        stats = self.statistics
        
        summary = f"""
PCAP Analysis Summary
=====================
File: {stats.get('filename')}
Size: {stats.get('file_size', 0):,} bytes
Packets: {stats.get('packet_count', 0):,}
Bytes: {stats.get('total_bytes', 0):,}
Duration: {stats.get('duration_seconds', 0):.2f}s
Flows: {stats.get('flow_stats', {}).get('active_flows', 0):,}

Protocol Distribution:
"""
        
        protocols = self.get_protocol_distribution()
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            summary += f"  {proto}: {count:,}\n"
        
        return summary
```

---

## 📁 File 48: `backend/app/services/capture_service.py`

```
Python
```

```
"""
Capture service for managing packet capture operations
"""
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.capture.engine import CaptureEngine
from app.models.flow import Flow
from app.core.logging import get_logger

logger = get_logger(__name__)


class CaptureService:
    """
    Service for managing network capture
    """
    
    def __init__(self):
        """Initialize capture service"""
        self.engine: Optional[CaptureEngine] = None
    
    def start_capture(
        self,
        db: Session,
        interface: str,
        bpf_filter: Optional[str] = None
    ) -> bool:
        """
        Start network capture
        
        Args:
            db: Database session
            interface: Network interface
            bpf_filter: Optional BPF filter
            
        Returns:
            True if started successfully
        """
        if self.engine and self.engine.is_running:
            logger.warning("Capture already running")
            return False
        
        def packet_callback(packet: Dict[str, Any], flow: Optional[Dict[str, Any]]):
            """Handle captured packet"""
            try:
                # Store flow in database if new or updated
                if flow:
                    self._store_flow(db, flow)
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
        
        self.engine = CaptureEngine(
            interface=interface,
            callback=packet_callback
        )
        
        if bpf_filter:
            self.engine.set_filter(bpf_filter)
        
        return self.engine.start()
    
    def stop_capture(self) -> bool:
        """
        Stop network capture
        
        Returns:
            True if stopped successfully
        """
        if not self.engine:
            return False
        
        return self.engine.stop()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get capture statistics
        
        Returns:
            Statistics dictionary
        """
        if not self.engine:
            return {}
        
        return self.engine.get_statistics()
    
    def get_active_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get active flows
        
        Args:
            limit: Maximum number of flows
            
        Returns:
            List of flows
        """
        if not self.engine:
            return []
        
        return self.engine.get_active_flows(limit)
    
    def _store_flow(self, db: Session, flow_data: Dict[str, Any]) -> None:
        """
        Store or update flow in database
        
        Args:
            db: Database session
            flow_data: Flow data from tracker
        """
        try:
            # Check if flow exists
            flow_id = flow_data["flow_id"]
            
            # For now, we'll batch flow storage
            # In production, use a queue/background task
            
            # Create or update flow
            flow = db.query(Flow).filter(
                Flow.src_ip == flow_data["src_ip"],
                Flow.dst_ip == flow_data["dst_ip"],
                Flow.src_port == flow_data["src_port"],
                Flow.dst_port == flow_data["dst_port"],
                Flow.protocol == flow_data["protocol"],
                Flow.first_seen >= datetime.utcnow() - timedelta(hours=1)
            ).first()
            
            if not flow:
                flow = Flow(
                    src_ip=flow_data["src_ip"],
                    dst_ip=flow_data["dst_ip"],
                    src_port=flow_data["src_port"],
                    dst_port=flow_data["dst_port"],
                    protocol=flow_data["protocol"],
                    src_mac=flow_data.get("src_mac"),
                    dst_mac=flow_data.get("dst_mac"),
                    first_seen=flow_data["first_seen"],
                    last_seen=flow_data["last_seen"],
                    packet_count=flow_data["packet_count"],
                    byte_count=flow_data["byte_count"],
                    tcp_flags=dict(flow_data.get("tcp_flags", {})),
                    state=flow_data["state"]
                )
                db.add(flow)
            else:
                flow.last_seen = flow_data["last_seen"]
                flow.packet_count = flow_data["packet_count"]
                flow.byte_count = flow_data["byte_count"]
                flow.tcp_flags = dict(flow_data.get("tcp_flags", {}))
                flow.state = flow_data["state"]
            
            # Commit periodically (every 100 flows)
            if flow_data["packet_count"] % 100 == 0:
                db.commit()
        
        except Exception as e:
            logger.error(f"Error storing flow: {e}")
            db.rollback()


# Global capture service instance
capture_service = CaptureService()
```

---

## 📁 File 49: `backend/app/api/capture.py`

```
Python
```

```
"""
Capture API endpoints
"""
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.api.deps import get_db, require_analyst
from app.models.user import User
from app.services.capture_service import capture_service
from app.services.audit_service import create_audit_log

router = APIRouter()


class CaptureStartRequest(BaseModel):
    """Capture start request"""
    interface: str
    bpf_filter: Optional[str] = None


class CaptureResponse(BaseModel):
    """Capture response"""
    status: str
    message: str


@router.post("/start", response_model=CaptureResponse)
def start_capture(
    *,
    db: Session = Depends(get_db),
    request: CaptureStartRequest,
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Start packet capture
    
    Requires analyst or admin role
    """
    try:
        success = capture_service.start_capture(
            db=db,
            interface=request.interface,
            bpf_filter=request.bpf_filter
        )
        
        if success:
            create_audit_log(
                db=db,
                user_id=current_user.id,
                username=current_user.username,
                action="capture_started",
                resource_type="capture",
                details={
                    "interface": request.interface,
                    "filter": request.bpf_filter
                },
                success=True
            )
            
            return {
                "status": "success",
                "message": f"Capture started on {request.interface}"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to start capture. Check permissions and interface."
            )
    
    except Exception as e:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            action="capture_start_failed",
            resource_type="capture",
            details={"error": str(e)},
            success=False
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/stop", response_model=CaptureResponse)
def stop_capture(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Stop packet capture
    
    Requires analyst or admin role
    """
    success = capture_service.stop_capture()
    
    if success:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            action="capture_stopped",
            resource_type="capture",
            success=True
        )
        
        return {
            "status": "success",
            "message": "Capture stopped"
        }
    else:
        return {
            "status": "info",
            "message": "Capture was not running"
        }


@router.get("/status")
def get_capture_status(
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Get capture status and statistics
    """
    stats = capture_service.get_statistics()
    
    return {
        "is_running": capture_service.engine.is_running if capture_service.engine else False,
        "statistics": stats
    }


@router.get("/flows")
def get_active_flows(
    limit: int = 100,
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Get active flows from capture
    """
    flows = capture_service.get_active_flows(limit=limit)
    
    return {
        "count": len(flows),
        "flows": flows
    }
```

---

## 📁 File 50: `backend/app/main.py` (Updated)

```
Python
```

```
"""
Main FastAPI application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api import auth, capture

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Network Intrusion Detection System",
    lifespan=lifespan,
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_PREFIX}/auth",
    tags=["Authentication"]
)

app.include_router(
    capture.router,
    prefix=f"{settings.API_V1_PREFIX}/capture",
    tags=["Capture"]
)


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
```

---

## 📁 File 51: `backend/tests/test_capture/test_parser.py`

```
Python
```

```
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
```

---

## ✅ PHASE 3 COMPLETE

**Implemented:**

- ✅ Complete packet capture engine with Scapy
- ✅ Async packet capture support
- ✅ Packet parser for all major protocols (TCP, UDP, ICMP, ARP, DNS)
- ✅ Flow tracker with 5-tuple identification
- ✅ TCP state tracking
- ✅ Flow statistics and aggregation
- ✅ PCAP file analyzer for offline analysis
- ✅ Capture service for database integration
- ✅ Capture API endpoints
- ✅ Unit tests for parser
- ✅ Statistics collection
- ✅ BPF filter support

**Testing Phase 3:**

```
Bash
```

```
# 1. Run database migrations (if needed)
cd backend
alembic revision --autogenerate -m "add flow tracking"
alembic upgrade head

# 2. Test packet parser
pytest tests/test_capture/test_parser.py -v

# 3. Start the server
make dev

# 4. Test capture API (requires authentication)
# Login first
TOKEN=$(curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=ChangeThisPassword123!" | jq -r '.access_token')

# Start capture (requires root or CAP_NET_RAW)
curl -X POST http://localhost:8000/api/v1/capture/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface": "lo"}'

# Get capture status
curl http://localhost:8000/api/v1/capture/status \
  -H "Authorization: Bearer $TOKEN"

# Get active flows
curl http://localhost:8000/api/v1/capture/flows \
  -H "Authorization: Bearer $TOKEN"

# Stop capture
curl -X POST http://localhost:8000/api/v1/capture/stop \
  -H "Authorization: Bearer $TOKEN"
```

**Next Phase:** Phase 4 - Detection Engine

Ready to proceed? Reply **"START PHASE 4"** to build the detection engine with port scan, brute force, ARP spoofing, DNS anomaly, and traffic anomaly detectors.