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
