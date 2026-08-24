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
