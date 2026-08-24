"""
Main Detection Engine
Coordinates all detection modules and manages rule execution
"""
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict

from app.core.logging import get_logger
from app.detection.rule_manager import RuleManager
from app.detection.detectors.port_scan import PortScanDetector
from app.detection.detectors.brute_force import BruteForceDetector
from app.detection.detectors.arp_spoofing import ARPSpoofingDetector
from app.detection.detectors.dns_anomaly import DNSAnomalyDetector
from app.detection.detectors.anomaly import AnomalyDetector
from app.detection.detectors.suspicious_traffic import SuspiciousTrafficDetector

logger = get_logger(__name__)


class DetectionEngine:
    """
    Main detection engine that coordinates all detection modules
    """
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """
        Initialize detection engine
        
        Args:
            alert_callback: Callback function for generated alerts
        """
        self.alert_callback = alert_callback
        
        # Rule manager
        self.rule_manager = RuleManager()
        
        # Detection modules
        self.detectors = {
            "port_scan": PortScanDetector(),
            "brute_force": BruteForceDetector(),
            "arp_spoofing": ARPSpoofingDetector(),
            "dns_anomaly": DNSAnomalyDetector(),
            "anomaly": AnomalyDetector(),
            "suspicious_traffic": SuspiciousTrafficDetector(),
        }
        
        # Alert cooldown tracking (rule_id -> last_alert_time)
        self.alert_cooldown: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            "packets_analyzed": 0,
            "alerts_generated": 0,
            "alerts_by_severity": defaultdict(int),
            "alerts_by_category": defaultdict(int),
            "detections_by_rule": defaultdict(int),
        }
        
        logger.info("Detection engine initialized")
    
    def analyze_packet(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze a packet for threats
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            List of generated alerts
        """
        self.stats["packets_analyzed"] += 1
        alerts = []
        
        try:
            # Run each detector
            for detector_name, detector in self.detectors.items():
                try:
                    detection_result = detector.analyze(packet, flow)
                    
                    if detection_result:
                        # Get associated rule
                        rule_id = detection_result.get("rule_id")
                        rule = self.rule_manager.get_rule(rule_id)
                        
                        if rule and rule.enabled:
                            # Check cooldown
                            if self._check_cooldown(rule_id, rule.cooldown_seconds):
                                # Create alert
                                alert = self._create_alert(detection_result, rule, packet, flow)
                                alerts.append(alert)
                                
                                # Update statistics
                                self._update_stats(alert)
                                
                                # Call callback
                                if self.alert_callback:
                                    self.alert_callback(alert)
                
                except Exception as e:
                    logger.error(f"Error in detector {detector_name}: {e}", exc_info=True)
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
        
        return alerts
    
    def analyze_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a flow for threats
        
        Args:
            flow: Flow data
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        try:
            # Run flow-based detections
            for detector_name, detector in self.detectors.items():
                if hasattr(detector, 'analyze_flow'):
                    try:
                        detection_result = detector.analyze_flow(flow)
                        
                        if detection_result:
                            rule_id = detection_result.get("rule_id")
                            rule = self.rule_manager.get_rule(rule_id)
                            
                            if rule and rule.enabled:
                                if self._check_cooldown(rule_id, rule.cooldown_seconds):
                                    alert = self._create_alert(detection_result, rule, None, flow)
                                    alerts.append(alert)
                                    self._update_stats(alert)
                                    
                                    if self.alert_callback:
                                        self.alert_callback(alert)
                    
                    except Exception as e:
                        logger.error(f"Error in flow analysis {detector_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error analyzing flow: {e}", exc_info=True)
        
        return alerts
    
    def _create_alert(
        self,
        detection: Dict[str, Any],
        rule: Any,
        packet: Optional[Dict[str, Any]],
        flow: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Create an alert from detection result
        
        Args:
            detection: Detection result
            rule: Detection rule
            packet: Packet data (optional)
            flow: Flow data (optional)
            
        Returns:
            Alert dictionary
        """
        alert = {
            "rule_id": rule.rule_id,
            "title": detection.get("title", rule.name),
            "description": detection.get("description", rule.description),
            "category": rule.category,
            "severity": rule.severity,
            "confidence": detection.get("confidence", 80),
            "timestamp": datetime.utcnow(),
            "evidence": detection.get("evidence", {}),
            "mitre_attack_id": rule.mitre_attack_id,
            "mitre_technique": rule.mitre_technique,
        }
        
        # Add packet/flow information
        if packet:
            alert.update({
                "src_ip": packet.get("src_ip"),
                "dst_ip": packet.get("dst_ip"),
                "src_port": packet.get("src_port"),
                "dst_port": packet.get("dst_port"),
                "protocol": packet.get("transport_protocol", packet.get("protocol")),
            })
        elif flow:
            alert.update({
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "src_port": flow.get("src_port"),
                "dst_port": flow.get("dst_port"),
                "protocol": flow.get("protocol"),
            })
        
        return alert
    
    def _check_cooldown(self, rule_id: str, cooldown_seconds: int) -> bool:
        """
        Check if alert cooldown has expired
        
        Args:
            rule_id: Rule identifier
            cooldown_seconds: Cooldown period in seconds
            
        Returns:
            True if alert can be generated, False if in cooldown
        """
        if rule_id not in self.alert_cooldown:
            self.alert_cooldown[rule_id] = datetime.utcnow()
            return True
        
        last_alert = self.alert_cooldown[rule_id]
        elapsed = (datetime.utcnow() - last_alert).total_seconds()
        
        if elapsed >= cooldown_seconds:
            self.alert_cooldown[rule_id] = datetime.utcnow()
            return True
        
        return False
    
    def _update_stats(self, alert: Dict[str, Any]) -> None:
        """
        Update detection statistics
        
        Args:
            alert: Alert data
        """
        self.stats["alerts_generated"] += 1
        self.stats["alerts_by_severity"][alert["severity"]] += 1
        self.stats["alerts_by_category"][alert["category"]] += 1
        self.stats["detections_by_rule"][alert["rule_id"]] += 1
    
    def load_rules(self, rules_path: str) -> None:
        """
        Load detection rules from path
        
        Args:
            rules_path: Path to rules directory
        """
        self.rule_manager.load_rules_from_directory(rules_path)
        logger.info(f"Loaded {len(self.rule_manager.rules)} detection rules")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection engine statistics
        
        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        stats["alerts_by_severity"] = dict(stats["alerts_by_severity"])
        stats["alerts_by_category"] = dict(stats["alerts_by_category"])
        stats["detections_by_rule"] = dict(stats["detections_by_rule"])
        stats["total_rules"] = len(self.rule_manager.rules)
        stats["enabled_rules"] = sum(1 for r in self.rule_manager.rules.values() if r.enabled)
        
        return stats
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a detection rule"""
        return self.rule_manager.enable_rule(rule_id)
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a detection rule"""
        return self.rule_manager.disable_rule(rule_id)
    
    def get_rule(self, rule_id: str) -> Optional[Any]:
        """Get a detection rule by ID"""
        return self.rule_manager.get_rule(rule_id)
    
    def get_all_rules(self) -> List[Any]:
        """Get all detection rules"""
        return list(self.rule_manager.rules.values())
