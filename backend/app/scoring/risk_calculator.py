"""
Risk Score Calculator
Transparent, explainable risk scoring system
"""
from typing import Dict, Any, List

from app.core.logging import get_logger

logger = get_logger(__name__)


class RiskCalculator:
    """
    Calculates risk scores with full transparency
    
    Score Components (0-100 total):
    
    1. Severity Base (0-45 points)
       - Derived from highest alert severity
    
    2. Confidence Factor (0-15 points)
       - Average detection confidence
    
    3. Correlation Factor (0-15 points)
       - Multiple rules/events correlated
    
    4. Affected Hosts Factor (0-10 points)
       - Number of targets
    
    5. Attack Chain Factor (0-10 points)
       - Multi-stage attack detected
    
    6. MITRE Factor (0-5 points)
       - Known attack techniques mapped
    
    Severity Mapping:
    - 90-100: CRITICAL
    - 70-89:  HIGH
    - 50-69:  MEDIUM
    - 25-49:  LOW
    - 0-24:   INFO
    """
    
    # Base severity scores
    SEVERITY_BASE = {
        "INFO": 5,
        "LOW": 12,
        "MEDIUM": 25,
        "HIGH": 38,
        "CRITICAL": 45,
    }
    
    SEVERITY_THRESHOLDS = [
        (90, "CRITICAL"),
        (70, "HIGH"),
        (50, "MEDIUM"),
        (25, "LOW"),
        (0, "INFO"),
    ]
    
    def calculate(
        self,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate risk score for correlated alerts
        
        Args:
            alerts: List of alerts
            chain_analysis: Attack chain analysis result
            
        Returns:
            {
                "total_score": int (0-100),
                "severity": str,
                "breakdown": {
                    component_name: {
                        "points": int,
                        "max_points": int,
                        "explanation": str
                    }
                },
                "calculation_summary": str
            }
        """
        if not alerts:
            return self._empty_result()
        
        chain_analysis = chain_analysis or {}
        breakdown = {}
        
        # 1. Severity base
        severity_result = self._calc_severity_base(alerts)
        breakdown["severity_base"] = severity_result
        
        # 2. Confidence factor
        confidence_result = self._calc_confidence_factor(alerts)
        breakdown["confidence"] = confidence_result
        
        # 3. Correlation factor
        correlation_result = self._calc_correlation_factor(alerts)
        breakdown["correlation"] = correlation_result
        
        # 4. Affected hosts factor
        hosts_result = self._calc_affected_hosts_factor(alerts)
        breakdown["affected_hosts"] = hosts_result
        
        # 5. Attack chain factor
        chain_result = self._calc_attack_chain_factor(chain_analysis)
        breakdown["attack_chain"] = chain_result
        
        # 6. MITRE factor
        mitre_result = self._calc_mitre_factor(alerts, chain_analysis)
        breakdown["mitre_mapping"] = mitre_result
        
        # Sum up
        total_score = sum(
            component["points"] for component in breakdown.values()
        )
        total_score = min(100, max(0, total_score))
        
        # Map to severity
        severity = self._score_to_severity(total_score)
        
        # Build explanation
        summary = self._build_summary(total_score, severity, breakdown)
        
        return {
            "total_score": total_score,
            "severity": severity,
            "breakdown": breakdown,
            "calculation_summary": summary,
        }
    
    def _calc_severity_base(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate severity base score
        
        Args:
            alerts: Alerts
            
        Returns:
            Component result
        """
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        highest_severity = "INFO"
        for alert in alerts:
            alert_sev = alert.get("severity", "INFO")
            if severity_order.index(alert_sev) > severity_order.index(highest_severity):
                highest_severity = alert_sev
        
        points = self.SEVERITY_BASE.get(highest_severity, 5)
        
        return {
            "points": points,
            "max_points": 45,
            "explanation": (
                f"Highest alert severity: {highest_severity} "
                f"(base score: {points}/45)"
            ),
            "highest_severity": highest_severity,
        }
    
    def _calc_confidence_factor(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate confidence factor
        
        Args:
            alerts: Alerts
            
        Returns:
            Component result
        """
        confidences = [
            a.get("confidence", 50) for a in alerts
            if a.get("confidence") is not None
        ]
        
        if not confidences:
            avg_confidence = 50
        else:
            avg_confidence = sum(confidences) / len(confidences)
        
        # Scale 0-100 confidence to 0-15 points
        points = int((avg_confidence / 100) * 15)
        
        return {
            "points": points,
            "max_points": 15,
            "explanation": (
                f"Average detection confidence: {avg_confidence:.0f}% "
                f"({points}/15 points)"
            ),
            "avg_confidence": round(avg_confidence, 1),
        }
    
    def _calc_correlation_factor(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate correlation factor
        
        Multiple distinct rules firing = stronger signal
        
        Args:
            alerts: Alerts
            
        Returns:
            Component result
        """
        rule_ids = set(
            a.get("rule_id") for a in alerts if a.get("rule_id")
        )
        distinct_rules = len(rule_ids)
        
        # 1 rule: 3 points, 2 rules: 8 points, 3+: 15 points
        if distinct_rules >= 3:
            points = 15
        elif distinct_rules == 2:
            points = 8
        elif distinct_rules == 1:
            points = 3
        else:
            points = 0
        
        return {
            "points": points,
            "max_points": 15,
            "explanation": (
                f"{distinct_rules} distinct detection rule(s) triggered "
                f"({points}/15 points)"
            ),
            "distinct_rules": distinct_rules,
        }
    
    def _calc_affected_hosts_factor(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate affected hosts factor
        
        Args:
            alerts: Alerts
            
        Returns:
            Component result
        """
        dst_ips = set(
            a.get("dst_ip") for a in alerts if a.get("dst_ip")
        )
        host_count = len(dst_ips)
        
        # 1 host: 2 points, 2-3: 5 points, 4-9: 8 points, 10+: 10 points
        if host_count >= 10:
            points = 10
        elif host_count >= 4:
            points = 8
        elif host_count >= 2:
            points = 5
        elif host_count == 1:
            points = 2
        else:
            points = 0
        
        return {
            "points": points,
            "max_points": 10,
            "explanation": (
                f"{host_count} host(s) affected "
                f"({points}/10 points)"
            ),
            "host_count": host_count,
        }
    
    def _calc_attack_chain_factor(
        self,
        chain_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate attack chain factor
        
        Args:
            chain_analysis: Chain analysis
            
        Returns:
            Component result
        """
        if chain_analysis.get("chain_detected"):
            points = 10
            explanation = (
                f"Multi-stage attack chain detected: "
                f"{chain_analysis.get('chain_name', 'Unknown')} "
                f"(10/10 points)"
            )
        elif chain_analysis.get("partial_chain"):
            stages = chain_analysis.get("stages", [])
            points = 5
            explanation = (
                f"Partial attack pattern detected "
                f"(stages: {', '.join(stages)}) (5/10 points)"
            )
        else:
            points = 0
            explanation = "No attack chain pattern detected (0/10 points)"
        
        return {
            "points": points,
            "max_points": 10,
            "explanation": explanation,
            "chain_detected": chain_analysis.get("chain_detected", False),
        }
    
    def _calc_mitre_factor(
        self,
        alerts: List[Dict[str, Any]],
        chain_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate MITRE ATT&CK factor
        
        Args:
            alerts: Alerts
            chain_analysis: Chain analysis
            
        Returns:
            Component result
        """
        techniques = set()
        for alert in alerts:
            if alert.get("mitre_attack_id"):
                techniques.add(alert["mitre_attack_id"])
        
        if chain_analysis.get("matched_chain"):
            techniques.add(f"chain:{chain_analysis['matched_chain']}")
        
        technique_count = len(techniques)
        
        # 1+ techniques: 5 points (capped)
        points = min(5, technique_count * 2)
        
        return {
            "points": points,
            "max_points": 5,
            "explanation": (
                f"{technique_count} MITRE ATT&CK technique(s) mapped "
                f"({points}/5 points)"
            ),
            "techniques": list(techniques),
        }
    
    def _score_to_severity(self, score: int) -> str:
        """
        Map score to severity
        
        Args:
            score: Risk score
            
        Returns:
            Severity string
        """
        for threshold, severity in self.SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return "INFO"
    
    def _build_summary(
        self,
        total_score: int,
        severity: str,
        breakdown: Dict[str, Dict[str, Any]]
    ) -> str:
        """
        Build human-readable calculation summary
        
        Args:
            total_score: Total score
            severity: Severity
            breakdown: Score breakdown
            
        Returns:
            Summary string
        """
        parts = [f"Risk Score: {total_score}/100 ({severity})"]
        parts.append("Calculation:")
        
        for name, component in breakdown.items():
            parts.append(
                f"  • {name}: {component['points']}/{component['max_points']} - "
                f"{component['explanation']}"
            )
        
        return "\n".join(parts)
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result"""
        return {
            "total_score": 0,
            "severity": "INFO",
            "breakdown": {},
            "calculation_summary": "No alerts to score",
        }
