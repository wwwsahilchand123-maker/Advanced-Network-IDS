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
