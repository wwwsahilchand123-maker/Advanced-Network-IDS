"""
Incident Builder
Constructs incident objects from correlated alerts
"""
from typing import Dict, Any, List
from datetime import datetime
import uuid

from app.core.logging import get_logger

logger = get_logger(__name__)


class IncidentBuilder:
    """
    Builds structured incident objects
    """
    
    def build(
        self,
        src_ip: str,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any],
        risk_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build incident from correlated data
        
        Args:
            src_ip: Attack source IP
            alerts: Related alerts
            chain_analysis: Attack chain analysis
            risk_result: Risk calculation result
            
        Returns:
            Incident dictionary
        """
        # Extract affected targets
        dst_ips = list(set(
            a.get("dst_ip") for a in alerts if a.get("dst_ip")
        ))
        
        # Extract involved rules
        rules_involved = list(set(
            a.get("rule_id") for a in alerts if a.get("rule_id")
        ))
        
        # Extract MITRE techniques
        mitre_techniques = list(set(
            a.get("mitre_attack_id") for a in alerts if a.get("mitre_attack_id")
        ))
        
        # Build timeline
        timeline = self._build_timeline(alerts)
        
        # Build title
        title = self._build_title(src_ip, chain_analysis, rules_involved)
        
        # Build description
        description = self._build_description(
            src_ip, alerts, chain_analysis, dst_ips
        )
        
        timestamps = [a.get("timestamp", datetime.utcnow()) for a in alerts]
        
        incident = {
            "incident_uuid": str(uuid.uuid4()),
            "title": title,
            "description": description,
            "severity": risk_result["severity"],
            "risk_score": risk_result["total_score"],
            "risk_breakdown": risk_result["breakdown"],
            "status": "open",
            "src_ip": src_ip,
            "dst_ips": dst_ips,
            "affected_hosts": len(dst_ips),
            "attack_chain": chain_analysis,
            "timeline": timeline,
            "rules_involved": rules_involved,
            "mitre_techniques": mitre_techniques,
            "alerts": alerts,
            "alert_keys": [
                f"{a.get('rule_id')}:{a.get('src_ip')}:"
                f"{a.get('dst_ip')}:{a.get('dst_port')}"
                for a in alerts
            ],
            "all_alerts": alerts,
            "alert_count": len(alerts),
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "created_at": datetime.utcnow(),
            "correlated": True,
        }
        
        return incident
    
    def _build_timeline(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build chronological event timeline
        
        Args:
            alerts: Related alerts
            
        Returns:
            Timeline events
        """
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", datetime.utcnow())
        )
        
        timeline = []
        
        for alert in sorted_alerts:
            timeline.append({
                "timestamp": alert.get("timestamp"),
                "event": alert.get("title"),
                "severity": alert.get("severity"),
                "rule_id": alert.get("rule_id"),
                "dst_ip": alert.get("dst_ip"),
                "dst_port": alert.get("dst_port"),
                "confidence": alert.get("confidence"),
                "description": alert.get("description"),
            })
        
        return timeline
    
    def _build_title(
        self,
        src_ip: str,
        chain_analysis: Dict[str, Any],
        rules_involved: List[str]
    ) -> str:
        """
        Build incident title
        
        Args:
            src_ip: Source IP
            chain_analysis: Chain analysis
            rules_involved: Rules involved
            
        Returns:
            Title string
        """
        if chain_analysis.get("chain_detected"):
            chain_name = chain_analysis.get("chain_name", "Multi-stage Attack")
            return f"{chain_name} from {src_ip}"
        
        if len(rules_involved) == 1:
            return f"Correlated Activity from {src_ip} ({rules_involved[0]})"
        
        return f"Multiple Security Events from {src_ip}"
    
    def _build_description(
        self,
        src_ip: str,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any],
        dst_ips: List[str]
    ) -> str:
        """
        Build incident description
        
        Args:
            src_ip: Source IP
            alerts: Related alerts
            chain_analysis: Chain analysis
            dst_ips: Affected destinations
            
        Returns:
            Description string
        """
        parts = []
        
        parts.append(
            f"Source {src_ip} generated {len(alerts)} security alerts "
            f"affecting {len(dst_ips)} host(s)."
        )
        
        if chain_analysis.get("chain_detected"):
            parts.append(
                f"Attack chain detected: {chain_analysis.get('chain_description', '')}"
            )
            stages = chain_analysis.get("stages", [])
            if stages:
                parts.append(f"Attack stages: {' → '.join(stages)}")
        
        # Summarize by category
        categories = {}
        for alert in alerts:
            cat = alert.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        
        cat_summary = ", ".join(f"{cat} ({count})" for cat, count in categories.items())
        parts.append(f"Alert categories: {cat_summary}")
        
        return " ".join(parts)
