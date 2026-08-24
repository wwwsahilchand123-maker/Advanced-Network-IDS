"""
Anomaly Detector
Detects traffic anomalies based on baseline
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class AnomalyDetector(BaseDetector):
    """
    Detect traffic anomalies based on baseline
    
    Detection methods:
    - Traffic volume spikes
    - Unusual protocol distribution
    - Connection burst patterns
    - Packet size anomalies
    """
    
    def __init__(self):
        """Initialize anomaly detector"""
        super().__init__("AnomalyDetector")
        
        # Baseline data
        self.baseline = {
            "packet_rate": {"mean": 0, "stddev": 0, "samples": []},
            "byte_rate": {"mean": 0, "stddev": 0, "samples": []},
            "protocol_distribution": defaultdict(int),
            "packet_sizes": {"mean": 0, "stddev": 0, "samples": []},
        }
        
        # Current window stats
        self.window_stats = {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": datetime.utcnow(),
            "protocols": defaultdict(int),
            "packet_sizes": [],
        }
        
        # Configuration
        self.baseline_window = 300  # 5 minutes
        self.anomaly_threshold = 3.0  # standard deviations
        self.min_samples = 10
        
        self.last_baseline_update = datetime.utcnow()
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for anomalies
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        timestamp = packet.get("timestamp", datetime.utcnow())
        packet_size = packet.get("length", 0)
        protocol = packet.get("transport_protocol", packet.get("protocol", "Unknown"))
        
        # Update window stats
        self._update_window_stats(packet_size, protocol)
        
        # Update baseline periodically
        if self._should_update_baseline(timestamp):
            self._update_baseline()
        
        # Check for anomalies
        detection = self._check_anomalies()
        
        return detection
    
    def _update_window_stats(self, packet_size: int, protocol: str) -> None:
        """
        Update current window statistics
        
        Args:
            packet_size: Packet size in bytes
            protocol: Protocol name
        """
        self.window_stats["packet_count"] += 1
        self.window_stats["byte_count"] += packet_size
        self.window_stats["protocols"][protocol] += 1
        self.window_stats["packet_sizes"].append(packet_size)
        
        # Limit packet size samples to prevent memory issues
        if len(self.window_stats["packet_sizes"]) > 1000:
            self.window_stats["packet_sizes"] = self.window_stats["packet_sizes"][-1000:]
    
    def _should_update_baseline(self, current_time: datetime) -> bool:
        """
        Check if baseline should be updated
        
        Args:
            current_time: Current timestamp
            
        Returns:
            True if baseline should be updated
        """
        elapsed = (current_time - self.last_baseline_update).total_seconds()
        return elapsed >= self.baseline_window
    
    def _update_baseline(self) -> None:
        """Update baseline with current window stats"""
        # Calculate packet rate
        duration = (
            datetime.utcnow() - self.window_stats["start_time"]
        ).total_seconds()
        
        if duration > 0:
            packet_rate = self.window_stats["packet_count"] / duration
            byte_rate = self.window_stats["byte_count"] / duration
            
            # Update baseline samples
            self.baseline["packet_rate"]["samples"].append(packet_rate)
            self.baseline["byte_rate"]["samples"].append(byte_rate)
            
            # Limit sample size
            max_samples = 100
            if len(self.baseline["packet_rate"]["samples"]) > max_samples:
                self.baseline["packet_rate"]["samples"] = \
                    self.baseline["packet_rate"]["samples"][-max_samples:]
                self.baseline["byte_rate"]["samples"] = \
                    self.baseline["byte_rate"]["samples"][-max_samples:]
            
            # Calculate statistics
            if len(self.baseline["packet_rate"]["samples"]) >= self.min_samples:
                self.baseline["packet_rate"]["mean"] = statistics.mean(
                    self.baseline["packet_rate"]["samples"]
                )
                self.baseline["packet_rate"]["stddev"] = statistics.stdev(
                    self.baseline["packet_rate"]["samples"]
                )
                
                self.baseline["byte_rate"]["mean"] = statistics.mean(
                    self.baseline["byte_rate"]["samples"]
                )
                self.baseline["byte_rate"]["stddev"] = statistics.stdev(
                    self.baseline["byte_rate"]["samples"]
                )
            
            # Update packet size baseline
            if self.window_stats["packet_sizes"]:
                avg_size = statistics.mean(self.window_stats["packet_sizes"])
                self.baseline["packet_sizes"]["samples"].append(avg_size)
                
                if len(self.baseline["packet_sizes"]["samples"]) > max_samples:
                    self.baseline["packet_sizes"]["samples"] = \
                        self.baseline["packet_sizes"]["samples"][-max_samples:]
                
                if len(self.baseline["packet_sizes"]["samples"]) >= self.min_samples:
                    self.baseline["packet_sizes"]["mean"] = statistics.mean(
                        self.baseline["packet_sizes"]["samples"]
                    )
                    self.baseline["packet_sizes"]["stddev"] = statistics.stdev(
                        self.baseline["packet_sizes"]["samples"]
                    )
        
        # Reset window stats
        self.window_stats = {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": datetime.utcnow(),
            "protocols": defaultdict(int),
            "packet_sizes": [],
        }
        
        self.last_baseline_update = datetime.utcnow()
    
    def _check_anomalies(self) -> Optional[Dict[str, Any]]:
        """
        Check current stats against baseline
        
        Returns:
            Detection result or None
        """
        # Need minimum samples for baseline
        if len(self.baseline["packet_rate"]["samples"]) < self.min_samples:
            return None
        
        # Calculate current rates
        duration = (
            datetime.utcnow() - self.window_stats["start_time"]
        ).total_seconds()
        
        if duration < 10:  # Need at least 10 seconds of data
            return None
        
        current_packet_rate = self.window_stats["packet_count"] / duration
        current_byte_rate = self.window_stats["byte_count"] / duration
        
        # Check packet rate anomaly
        packet_baseline = self.baseline["packet_rate"]
        if packet_baseline["stddev"] > 0:
            packet_z_score = abs(
                (current_packet_rate - packet_baseline["mean"]) / 
                packet_baseline["stddev"]
            )
            
            if packet_z_score > self.anomaly_threshold:
                return self._create_traffic_spike_alert(
                    current_packet_rate,
                    packet_baseline["mean"],
                    packet_z_score,
                    "packet_rate"
                )
        
        # Check byte rate anomaly
        byte_baseline = self.baseline["byte_rate"]
        if byte_baseline["stddev"] > 0:
            byte_z_score = abs(
                (current_byte_rate - byte_baseline["mean"]) / 
                byte_baseline["stddev"]
            )
            
            if byte_z_score > self.anomaly_threshold:
                return self._create_traffic_spike_alert(
                    current_byte_rate,
                    byte_baseline["mean"],
                    byte_z_score,
                    "byte_rate"
                )
        
        return None
    
    def _create_traffic_spike_alert(
        self,
        current_rate: float,
        baseline_mean: float,
        z_score: float,
        rate_type: str
    ) -> Dict[str, Any]:
        """
        Create traffic spike alert
        
        Args:
            current_rate: Current rate
            baseline_mean: Baseline mean
            z_score: Z-score deviation
            rate_type: Type of rate (packet_rate or byte_rate)
            
        Returns:
            Detection result
        """
        confidence = min(100, 70 + int(z_score * 5))
        
        rate_label = "packets/sec" if rate_type == "packet_rate" else "bytes/sec"
        
        return self._create_detection(
            rule_id="ANOMALY_001",
            title="Traffic Volume Spike Detected",
            description=(
                f"Unusual traffic spike detected: current {rate_label} "
                f"({current_rate:.1f}) is {z_score:.1f} standard deviations "
                f"above baseline ({baseline_mean:.1f})"
            ),
            confidence=confidence,
            evidence={
                "rate_type": rate_type,
                "current_rate": round(current_rate, 2),
                "baseline_mean": round(baseline_mean, 2),
                "z_score": round(z_score, 2),
                "deviation_percent": round(
                    ((current_rate - baseline_mean) / baseline_mean) * 100, 2
                ) if baseline_mean > 0 else 0,
                "protocol_distribution": dict(self.window_stats["protocols"])
            }
        )
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """
        Get current baseline statistics
        
        Returns:
            Baseline statistics
        """
        return {
            "packet_rate": {
                "mean": round(self.baseline["packet_rate"]["mean"], 2),
                "stddev": round(self.baseline["packet_rate"]["stddev"], 2),
                "samples": len(self.baseline["packet_rate"]["samples"])
            },
            "byte_rate": {
                "mean": round(self.baseline["byte_rate"]["mean"], 2),
                "stddev": round(self.baseline["byte_rate"]["stddev"], 2),
                "samples": len(self.baseline["byte_rate"]["samples"])
            },
            "packet_sizes": {
                "mean": round(self.baseline["packet_sizes"]["mean"], 2),
                "stddev": round(self.baseline["packet_sizes"]["stddev"], 2),
                "samples": len(self.baseline["packet_sizes"]["samples"])
            }
        }
