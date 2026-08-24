"""
Event Correlation Engine
Correlates multiple alerts into security incidents
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import threading

from app.core.logging import get_logger
from app.correlation.incident_builder import IncidentBuilder
from app.correlation.attack_chains import AttackChainAnalyzer
from app.scoring.risk_calculator import RiskCalculator

logger = get_logger(__name__)


class CorrelationEngine:
    """
    Correlates security alerts into incidents
    
    Correlation strategies:
    - Source IP grouping (same attacker)
    - Target grouping (same victim)
    - Time window proximity
    - Attack pattern progression (kill chain)
    """
    
    def __init__(self, incident_callback: Optional[callable] = None):
        """
        Initialize correlation engine
        
        Args:
            incident_callback: Callback function when incident is created/updated
        """
        self.incident_callback = incident_callback
        self.incident_builder = IncidentBuilder()
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.risk_calculator = RiskCalculator()
        
        # Correlation windows
        self.correlation_window = timedelta(seconds=300)  # 5 minutes
        self.incident_close_window = timedelta(minutes=30)
        
        # Alert buffer grouped by source IP
        # src_ip -> list of alerts
        self.alert_buffer: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Active incidents being tracked (in-memory working set)
        # src_ip -> incident data
        self.active_correlations: Dict[str, Dict[str, Any]] = {}
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "alerts_processed": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "alerts_correlated": 0,
        }
        
        logger.info("Correlation engine initialized")
    
    def process_alert(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a new alert for correlation
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Incident data if incident created/updated, None otherwise
        """
        with self._lock:
            self.stats["alerts_processed"] += 1
            
            src_ip = alert.get("src_ip")
            timestamp = alert.get("timestamp", datetime.utcnow())
            
            if not src_ip:
                return None
            
            # Buffer the alert
            self.alert_buffer[src_ip].append(alert)
            
            # Cleanup old alerts outside correlation window
            self._cleanup_buffer(src_ip, timestamp)
            
            # Try to correlate
            incident = self._correlate(src_ip, timestamp)
            
            return incident
    
    def _cleanup_buffer(self, src_ip: str, current_time: datetime) -> None:
        """
        Remove alerts older than correlation window
        
        Args:
            src_ip: Source IP
            current_time: Current timestamp
        """
        cutoff = current_time - self.correlation_window
        
        self.alert_buffer[src_ip] = [
            a for a in self.alert_buffer[src_ip]
            if a.get("timestamp", datetime.utcnow()) > cutoff
        ]
        
        # Remove empty buffers
        if not self.alert_buffer[src_ip]:
            del self.alert_buffer[src_ip]
    
    def _correlate(
        self,
        src_ip: str,
        timestamp: datetime
    ) -> Optional[Dict[str, Any]]:
        """
        Correlate buffered alerts for a source IP
        
        Args:
            src_ip: Source IP
            timestamp: Current timestamp
            
        Returns:
            Incident data or None
        """
        alerts = self.alert_buffer.get(src_ip, [])
        
        if not alerts:
            return None
        
        # Analyze for attack chain patterns
        chain_analysis = self.attack_chain_analyzer.analyze(alerts)
        
        # Determine if incident should be created or updated
        if src_ip in self.active_correlations:
            # Update existing incident
            return self._update_incident(src_ip, alerts, chain_analysis)
        
        # Check if new incident should be created
        if self._should_create_incident(alerts, chain_analysis):
            return self._create_incident(src_ip, alerts, chain_analysis)
        
        return None
    
    def _should_create_incident(
        self,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any]
    ) -> bool:
        """
        Determine if alerts warrant an incident
        
        Criteria:
        - Multiple distinct rules triggered
        - Attack chain pattern detected
        - Multiple high-severity alerts
        - Multi-stage attack indicators
        
        Args:
            alerts: Buffered alerts
            chain_analysis: Attack chain analysis
            
        Returns:
            True if incident should be created
        """
        # Attack chain detected = always create incident
        if chain_analysis.get("chain_detected"):
            return True
        
        # Multiple distinct rules triggered
        rule_ids = set(a.get("rule_id") for a in alerts)
        if len(rule_ids) >= 2:
            return True
        
        # Multiple high/critical alerts
        high_alerts = [
            a for a in alerts
            if a.get("severity") in ("HIGH", "CRITICAL")
        ]
        if len(high_alerts) >= 3:
            return True
        
        return False
    
    def _create_incident(
        self,
        src_ip: str,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new correlated incident
        
        Args:
            src_ip: Source IP
            alerts: Related alerts
            chain_analysis: Attack chain analysis
            
        Returns:
            Incident data
        """
        # Calculate risk score
        risk_result = self.risk_calculator.calculate(
            alerts=alerts,
            chain_analysis=chain_analysis
        )
        
        # Build incident via incident builder
        incident = self.incident_builder.build(
            src_ip=src_ip,
            alerts=alerts,
            chain_analysis=chain_analysis,
            risk_result=risk_result
        )
        
        # Track active correlation
        self.active_correlations[src_ip] = incident
        self.stats["incidents_created"] += 1
        self.stats["alerts_correlated"] += len(alerts)
        
        logger.info(
            f"Incident created: {incident['title']} "
            f"(severity={incident['severity']}, "
            f"risk={incident['risk_score']}, "
            f"alerts={len(alerts)})"
        )
        
        if self.incident_callback:
            self.incident_callback(incident, "created")
        
        return incident
    
    def _update_incident(
        self,
        src_ip: str,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Update an existing incident with new alerts
        
        Args:
            src_ip: Source IP
            alerts: Related alerts
            chain_analysis: Attack chain analysis
            
        Returns:
            Updated incident data or None
        """
        incident = self.active_correlations[src_ip]
        
        # Get alerts already in incident
        existing_alert_keys = set(incident.get("alert_keys", []))
        
        # Find new alerts
        new_alerts = []
        for alert in alerts:
            key = self._alert_key(alert)
            if key not in existing_alert_keys:
                new_alerts.append(alert)
        
        if not new_alerts:
            return None
        
        # Check escalation potential
        escalated = self._check_escalation(incident, alerts, chain_analysis)
        
        # Recalculate risk with all alerts
        risk_result = self.risk_calculator.calculate(
            alerts=alerts,
            chain_analysis=chain_analysis
        )
        
        # Update incident
        all_alerts = incident.get("all_alerts", []) + new_alerts
        incident.update({
            "all_alerts": all_alerts,
            "alert_count": len(all_alerts),
            "last_seen": max(a.get("timestamp", datetime.utcnow()) for a in all_alerts),
            "risk_score": risk_result["total_score"],
            "severity": risk_result["severity"],
            "risk_breakdown": risk_result["breakdown"],
            "attack_chain": chain_analysis,
            "escalated": escalated,
            "status": "open",
        })
        
        # Track alert keys
        incident["alert_keys"] = [
            self._alert_key(a) for a in all_alerts
        ]
        
        self.stats["incidents_updated"] += 1
        self.stats["alerts_correlated"] += len(new_alerts)
        
        if escalated:
            logger.warning(
                f"Incident ESCALATED: {incident['title']} "
                f"(risk={incident['risk_score']}, severity={incident['severity']})"
            )
        
        if self.incident_callback:
            action = "escalated" if escalated else "updated"
            self.incident_callback(incident, action)
        
        return incident
    
    def _check_escalation(
        self,
        incident: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any]
    ) -> bool:
        """
        Check if incident has escalated
        
        Escalation indicators:
        - Severity increased
        - Risk score increased significantly
        - New attack stage detected
        
        Args:
            incident: Current incident
            alerts: All alerts
            chain_analysis: Chain analysis
            
        Returns:
            True if escalated
        """
        old_risk = incident.get("risk_score", 0)
        
        new_risk_result = self.risk_calculator.calculate(
            alerts=alerts,
            chain_analysis=chain_analysis
        )
        new_risk = new_risk_result["total_score"]
        
        # Risk score increased by 10+ points
        if new_risk - old_risk >= 10:
            return True
        
        # Severity increased
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        old_sev = severity_order.index(incident.get("severity", "LOW"))
        new_sev = severity_order.index(new_risk_result["severity"])
        if new_sev > old_sev:
            return True
        
        # New chain stage detected
        old_stages = set(incident.get("attack_chain", {}).get("stages", []))
        new_stages = set(chain_analysis.get("stages", []))
        if new_stages - old_stages:
            return True
        
        return False
    
    def _alert_key(self, alert: Dict[str, Any]) -> str:
        """
        Generate unique key for alert deduplication
        
        Args:
            alert: Alert data
            
        Returns:
            Unique key string
        """
        return (
            f"{alert.get('rule_id')}:"
            f"{alert.get('src_ip')}:"
            f"{alert.get('dst_ip')}:"
            f"{alert.get('dst_port')}"
        )
    
    def close_stale_correlations(self) -> List[Dict[str, Any]]:
        """
        Close correlations that have been inactive
        
        Returns:
            List of closed incidents
        """
        closed = []
        current_time = datetime.utcnow()
        cutoff = current_time - self.incident_close_window
        
        with self._lock:
            for src_ip in list(self.active_correlations.keys()):
                incident = self.active_correlations[src_ip]
                last_seen = incident.get("last_seen", current_time)
                
                if last_seen < cutoff:
                    incident["status"] = "closed_pending_review"
                    closed.append(incident)
                    del self.active_correlations[src_ip]
                    logger.info(f"Correlation closed for {src_ip}")
        
        return closed
    
    def get_active_correlations(self) -> List[Dict[str, Any]]:
        """
        Get currently active correlations
        
        Returns:
            List of active incidents
        """
        with self._lock:
            return list(self.active_correlations.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get correlation statistics
        
        Returns:
            Statistics dictionary
        """
        with self._lock:
            stats = self.stats.copy()
            stats["active_correlations"] = len(self.active_correlations)
            stats["buffered_sources"] = len(self.alert_buffer)
            return stats
