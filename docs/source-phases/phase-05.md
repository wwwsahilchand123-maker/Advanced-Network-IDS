# PHASE 4: Detection Engine

Building the complete threat detection system with multiple detection modules.

---

## 📁 File 52: `backend/app/detection/__init__.py`

```
Python
```

```
"""
Detection engine module initialization
"""
```

---

## 📁 File 53: `backend/app/detection/engine.py`

```
Python
```

```
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
```

---

## 📁 File 54: `backend/app/detection/rule_manager.py`

```
Python
```

```
"""
Detection Rule Manager
Loads and manages detection rules
"""
from typing import Dict, List, Optional
from pathlib import Path
import yaml

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.rule import DetectionRule

logger = get_logger(__name__)


class RuleManager:
    """
    Manages detection rules
    """
    
    def __init__(self):
        """Initialize rule manager"""
        self.rules: Dict[str, DetectionRule] = {}
    
    def load_rules_from_directory(self, rules_dir: str) -> int:
        """
        Load rules from YAML files in directory
        
        Args:
            rules_dir: Directory containing rule files
            
        Returns:
            Number of rules loaded
        """
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return 0
        
        count = 0
        
        for rule_file in rules_path.glob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    
                    rule = self._create_rule_from_dict(rule_data)
                    self.rules[rule.rule_id] = rule
                    count += 1
                    
                    logger.debug(f"Loaded rule: {rule.rule_id}")
            
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")
        
        logger.info(f"Loaded {count} rules from {rules_dir}")
        return count
    
    def load_rules_from_database(self, db: Session) -> int:
        """
        Load rules from database
        
        Args:
            db: Database session
            
        Returns:
            Number of rules loaded
        """
        try:
            db_rules = db.query(DetectionRule).all()
            
            for rule in db_rules:
                self.rules[rule.rule_id] = rule
            
            logger.info(f"Loaded {len(db_rules)} rules from database")
            return len(db_rules)
        
        except Exception as e:
            logger.error(f"Error loading rules from database: {e}")
            return 0
    
    def _create_rule_from_dict(self, rule_data: dict) -> DetectionRule:
        """
        Create DetectionRule object from dictionary
        
        Args:
            rule_data: Rule data from YAML
            
        Returns:
            DetectionRule object
        """
        # Extract MITRE ATT&CK information
        mitre = rule_data.get("mitre_attack", {})
        
        rule = DetectionRule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data.get("description"),
            category=rule_data.get("category"),
            severity=rule_data.get("severity", "MEDIUM"),
            enabled=rule_data.get("enabled", True),
            threshold_config=rule_data.get("detection_logic", {}).get("conditions"),
            cooldown_seconds=rule_data.get("response", {}).get("cooldown", 300),
            mitre_attack_id=mitre.get("technique"),
            mitre_technique=mitre.get("technique_name"),
            detection_logic=str(rule_data.get("detection_logic"))
        )
        
        return rule
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """
        Get rule by ID
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            DetectionRule or None
        """
        return self.rules.get(rule_id)
    
    def enable_rule(self, rule_id: str) -> bool:
        """
        Enable a rule
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            True if successful
        """
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = True
            logger.info(f"Enabled rule: {rule_id}")
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """
        Disable a rule
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            True if successful
        """
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = False
            logger.info(f"Disabled rule: {rule_id}")
            return True
        return False
    
    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """
        Get all rules in a category
        
        Args:
            category: Rule category
            
        Returns:
            List of rules
        """
        return [
            rule for rule in self.rules.values()
            if rule.category == category
        ]
    
    def get_enabled_rules(self) -> List[DetectionRule]:
        """
        Get all enabled rules
        
        Returns:
            List of enabled rules
        """
        return [rule for rule in self.rules.values() if rule.enabled]
```

---

## 📁 File 55: `backend/app/detection/detectors/base.py`

```
Python
```

```
"""
Base Detector Class
All detectors inherit from this base class
"""
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from app.core.logging import get_logger

logger = get_logger(__name__)


class BaseDetector(ABC):
    """
    Base class for all detectors
    """
    
    def __init__(self, name: str):
        """
        Initialize base detector
        
        Args:
            name: Detector name
        """
        self.name = name
        self.enabled = True
        
        logger.debug(f"Initialized {name} detector")
    
    @abstractmethod
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for threats
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result dictionary or None
        """
        pass
    
    def _create_detection(
        self,
        rule_id: str,
        title: str,
        description: str,
        confidence: int,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a detection result
        
        Args:
            rule_id: Associated rule ID
            title: Detection title
            description: Detection description
            confidence: Confidence score (0-100)
            evidence: Evidence data
            
        Returns:
            Detection dictionary
        """
        return {
            "rule_id": rule_id,
            "title": title,
            "description": description,
            "confidence": confidence,
            "evidence": evidence,
            "detector": self.name
        }
```

---

## 📁 File 56: `backend/app/detection/detectors/__init__.py`

```
Python
```

```
"""
Detection modules initialization
"""
```

---

## 📁 File 57: `backend/app/detection/detectors/port_scan.py`

```
Python
```

```
"""
Port Scan Detector
Detects port scanning behavior
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from app.detection.detectors.base import BaseDetector
from app.core.logging import get_logger

logger = get_logger(__name__)


class PortScanDetector(BaseDetector):
    """
    Detect port scanning activity
    
    Detection methods:
    - Vertical scan (many ports, one target)
    - Horizontal scan (one port, many targets)
    - SYN scan patterns
    - Failed connection patterns
    """
    
    def __init__(self):
        """Initialize port scan detector"""
        super().__init__("PortScanDetector")
        
        # Track connections per source IP
        # src_ip -> {dst_ip -> {ports: set, timestamps: list}}
        self.connections: Dict[str, Dict[str, Dict]] = defaultdict(
            lambda: defaultdict(lambda: {"ports": set(), "timestamps": []})
        )
        
        # Thresholds
        self.vertical_threshold = 25  # ports per target
        self.horizontal_threshold = 20  # targets per source
        self.time_window = 30  # seconds
        self.syn_ratio_threshold = 0.8  # SYN packets ratio
    
    def analyze(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet for port scan patterns
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            Detection result or None
        """
        # Only analyze TCP packets
        if packet.get("transport_protocol") != "TCP":
            return None
        
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp", datetime.utcnow())
        tcp_flags = packet.get("tcp_flags", {})
        
        if not (src_ip and dst_ip and dst_port):
            return None
        
        # Track connection
        self._track_connection(src_ip, dst_ip, dst_port, timestamp, tcp_flags)
        
        # Clean old entries
        self._cleanup_old_entries(src_ip, timestamp)
        
        # Check for vertical scan (many ports on one target)
        vertical_result = self._check_vertical_scan(src_ip, dst_ip)
        if vertical_result:
            return vertical_result
        
        # Check for horizontal scan (one port on many targets)
        horizontal_result = self._check_horizontal_scan(src_ip)
        if horizontal_result:
            return horizontal_result
        
        return None
    
    def _track_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: datetime,
        tcp_flags: Dict[str, bool]
    ) -> None:
        """
        Track a connection attempt
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Destination port
            timestamp: Packet timestamp
            tcp_flags: TCP flags
        """
        target = self.connections[src_ip][dst_ip]
        target["ports"].add(dst_port)
        target["timestamps"].append(timestamp)
        
        # Track SYN flags for scan detection
        if tcp_flags.get("SYN") and not tcp_flags.get("ACK"):
            if "syn_count" not in target:
                target["syn_count"] = 0
            target["syn_count"] += 1
    
    def _cleanup_old_entries(self, src_ip: str, current_time: datetime) -> None:
        """
        Remove entries older than time window
        
        Args:
            src_ip: Source IP to clean
            current_time: Current timestamp
        """
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for dst_ip in list(self.connections[src_ip].keys()):
            target = self.connections[src_ip][dst_ip]
            
            # Filter old timestamps
            target["timestamps"] = [
                ts for ts in target["timestamps"]
                if ts > cutoff_time
            ]
            
            # Remove target if no recent activity
            if not target["timestamps"]:
                del self.connections[src_ip][dst_ip]
        
        # Remove source if no targets
        if not self.connections[src_ip]:
            del self.connections[src_ip]
    
    def _check_vertical_scan(
        self,
        src_ip: str,
        dst_ip: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check for vertical port scan (many ports, one target)
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.connections:
            return None
        
        target = self.connections[src_ip].get(dst_ip)
        if not target:
            return None
        
        ports_contacted = len(target["ports"])
        
        if ports_contacted >= self.vertical_threshold:
            # Calculate confidence
            confidence = min(100, 70 + (ports_contacted - self.vertical_threshold))
            
            # Check SYN ratio
            total_packets = len(target["timestamps"])
            syn_count = target.get("syn_count", 0)
            syn_ratio = syn_count / total_packets if total_packets > 0 else 0
            
            if syn_ratio > self.syn_ratio_threshold:
                confidence = min(100, confidence + 15)
            
            # Check if ports are sequential
            sorted_ports = sorted(target["ports"])
            sequential = self._check_sequential_ports(sorted_ports)
            if sequential:
                confidence = min(100, confidence + 10)
            
            return self._create_detection(
                rule_id="SCAN_001",
                title="Possible Vertical Port Scan Detected",
                description=(
                    f"Source {src_ip} contacted {ports_contacted} ports "
                    f"on target {dst_ip} within {self.time_window} seconds"
                ),
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports_contacted": ports_contacted,
                    "ports": sorted_ports[:50],  # Limit for readability
                    "time_window": self.time_window,
                    "syn_ratio": round(syn_ratio, 2),
                    "sequential_ports": sequential,
                    "scan_type": "vertical"
                }
            )
        
        return None
    
    def _check_horizontal_scan(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Check for horizontal port scan (one port, many targets)
        
        Args:
            src_ip: Source IP
            
        Returns:
            Detection result or None
        """
        if src_ip not in self.connections:
            return None
        
        targets = self.connections[src_ip]
        num_targets = len(targets)
        
        if num_targets >= self.horizontal_threshold:
            # Find most common port
            port_counts = defaultdict(int)
            for target_data in targets.values():
                for port in target_data["ports"]:
                    port_counts[port] += 1
            
            most_common_port = max(port_counts.items(), key=lambda x: x[1]) if port_counts else (None, 0)
            
            confidence = min(100, 70 + (num_targets - self.horizontal_threshold))
            
            target_ips = list(targets.keys())
            
            return self._create_detection(
                rule_id="SCAN_002",
                title="Possible Horizontal Port Scan Detected",
                description=(
                    f"Source {src_ip} contacted {num_targets} different targets "
                    f"within {self.time_window} seconds"
                ),
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "targets_contacted": num_targets,
                    "target_ips": target_ips[:50],  # Limit for readability
                    "most_common_port": most_common_port[0],
                    "time_window": self.time_window,
                    "scan_type": "horizontal"
                }
            )
        
        return None
    
    def _check_sequential_ports(self, ports: list) -> bool:
        """
        Check if ports are mostly sequential
        
        Args:
            ports: Sorted list of ports
            
        Returns:
            True if ports appear sequential
        """
        if len(ports) < 3:
            return False
        
        sequential_count = 0
        for i in range(len(ports) - 1):
            if ports[i + 1] - ports[i] == 1:
                sequential_count += 1
        
        # Consider sequential if >70% of transitions are consecutive
        return (sequential_count / (len(ports) - 1)) > 0.7
```

---

## 📁 File 58: `backend/app/detection/detectors/brute_force.py`

```
Python
```

```
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
```

---

## 📁 File 59: `backend/app/detection/detectors/arp_spoofing.py`

```
Python
```

```
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
```

---

## 📁 File 60: `backend/app/detection/detectors/dns_anomaly.py`

```
Python
```

```
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
```