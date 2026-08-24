"""
DNS Anomaly Detector
Detects suspicious DNS activity
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import math

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class DNSAnomalyDetector(BaseDetector):
    """
    Detect DNS anomalies
    
    Detection methods:
    - Excessive query rates
    - High entropy domains (DGA detection)
    - Unusual query patterns
    - DNS tunneling indicators
    """
    
    def __init__(self):
        """Initialize DNS anomaly detector"""
        super().__init__("DNSAnomalyDetector")
        
        # Track queries per source
        # src_ip -> {timestamps: list, queries: list}
        self.queries: Dict[str, Dict] = defaultdict(
            lambda: {"timestamps": [], "queries": [], "unique_domains": set()}
        )
        
        # Thresholds
        self.query_rate_threshold = 50  # queries per minute
        self.time_window = 60  # seconds
        self.high_entropy_threshold = 3.5  # Shannon entropy
        self.long_domain_threshold = 50  # characters
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for DNS anomalies
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        # Only analyze DNS queries
        if not packet.get("dns_query"):
            return None
        
        src_ip = packet.get("src_ip")
        timestamp = packet.get("timestamp", datetime.utcnow())
        queries = packet.get("dns_queries", [])
        
        if not (src_ip and queries):
            return None
        
        for query in queries:
            query_name = query.get("name", "")
            
            if not query_name:
                continue
            
            # Track query
            self._track_query(src_ip, query_name, timestamp)
            
            # Check entropy
            entropy = self._calculate_entropy(query_name)
            if entropy > self.high_entropy_threshold:
                detection = self._detect_high_entropy_domain(
                    src_ip, query_name, entropy
                )
                if detection:
                    return detection
            
            # Check domain length
            if len(query_name) > self.long_domain_threshold:
                detection = self._detect_long_domain(src_ip, query_name)
                if detection:
                    return detection
        
        # Clean old entries
        self._cleanup_old_entries(src_ip, timestamp)
        
        # Check query rate
        rate_detection = self._check_query_rate(src_ip)
        if rate_detection:
            return rate_detection
        
        return None
    
    def _track_query(self, src_ip: str, query_name: str, timestamp: datetime) -> None:
        """
        Track a DNS query
        
        Args:
            src_ip: Source IP
            query_name: Queried domain
            timestamp: Query timestamp
        """
        tracker = self.queries[src_ip]
        tracker["timestamps"].append(timestamp)
        tracker["queries"].append(query_name)
        tracker["unique_domains"].add(query_name)
    
    def _cleanup_old_entries(self, src_ip: str, current_time: datetime) -> None:
        """
        Remove old query entries
        
        Args:
            src_ip: Source IP
            current_time: Current timestamp
        """
        if src_ip not in self.queries:
            return
        
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        tracker = self.queries[src_ip]
        
        # Filter old timestamps and corresponding queries
        new_timestamps = []
        new_queries = []
        
        for ts, query in zip(tracker["timestamps"], tracker["queries"]):
            if ts > cutoff_time:
                new_timestamps.append(ts)
                new_queries.append(query)
        
        tracker["timestamps"] = new_timestamps
        tracker["queries"] = new_queries
        tracker["unique_domains"] = set(new_queries)
        
        # Remove if no recent activity
        if not tracker["timestamps"]:
            del self.queries[src_ip]
    
    def _calculate_entropy(self, domain: str) -> float:
        """
        Calculate Shannon entropy of domain name
        
        Args:
            domain: Domain name
            
        Returns:
            Entropy value
        """
        if not domain:
            return 0.0
        
        # Remove dots and convert to lowercase
        domain = domain.replace('.', '').lower()
        
        # Calculate frequency of each character
        char_freq = defaultdict(int)
        for char in domain:
            char_freq[char] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(domain)
        
        for count in char_freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_query_rate(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Check if query rate is excessive
        
        Args:
            src_ip: Source IP
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.queries:
            return None
        
        tracker = self.queries[src_ip]
        query_count = len(tracker["timestamps"])
        
        if query_count < self.query_rate_threshold:
            return None
        
        # Calculate queries per minute
        if len(tracker["timestamps"]) < 2:
            return None
        
        time_span = (
            tracker["timestamps"][-1] - tracker["timestamps"][0]
        ).total_seconds()
        queries_per_minute = (query_count / time_span) * 60 if time_span > 0 else 0
        
        confidence = min(100, 70 + int((queries_per_minute - self.query_rate_threshold) / 10))
        
        unique_count = len(tracker["unique_domains"])
        
        return self._create_detection(
            rule_id="DNS_001",
            title="Excessive DNS Query Rate Detected",
            description=(
                f"Source {src_ip} made {query_count} DNS queries "
                f"({queries_per_minute:.1f} queries/min)"
            ),
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "query_count": query_count,
                "unique_domains": unique_count,
                "queries_per_minute": round(queries_per_minute, 2),
                "time_window": self.time_window,
                "sample_queries": tracker["queries"][:20]
            }
        )
    
    def _detect_high_entropy_domain(
        self,
        src_ip: str,
        domain: str,
        entropy: float
    ) -> Optional[Dict[str, Any]]:
        """
        Detect high entropy domain (possible DGA)
        
        Args:
            src_ip: Source IP
            domain: Domain name
            entropy: Calculated entropy
            
        Returns:
            Detection result or None
        """
        confidence = min(100, 75 + int((entropy - self.high_entropy_threshold) * 10))
        
        return self._create_detection(
            rule_id="DNS_002",
            title="High Entropy Domain Detected (Possible DGA)",
            description=(
                f"Source {src_ip} queried high-entropy domain: {domain} "
                f"(entropy: {entropy:.2f})"
            ),
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "domain": domain,
                "entropy": round(entropy, 2),
                "threshold": self.high_entropy_threshold,
                "domain_length": len(domain),
                "indicator": "possible_dga"
            }
        )
    
    def _detect_long_domain(self, src_ip: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Detect unusually long domain (possible tunneling)
        
        Args:
            src_ip: Source IP
            domain: Domain name
            
        Returns:
            Detection result or None
        """
        confidence = min(100, 70 + len(domain) - self.long_domain_threshold)
        
        return self._create_detection(
            rule_id="DNS_003",
            title="Unusually Long DNS Query (Possible Tunneling)",
            description=(
                f"Source {src_ip} queried unusually long domain: "
                f"{domain[:50]}... ({len(domain)} chars)"
            ),
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "domain": domain[:100],  # Limit for storage
                "domain_length": len(domain),
                "threshold": self.long_domain_threshold,
                "indicator": "possible_tunneling"
            }
        )
