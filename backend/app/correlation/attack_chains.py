"""
Attack Chain Analyzer
Detects multi-stage attack patterns (kill chain analysis)
"""
from typing import Dict, Any, List
from datetime import datetime

from app.core.logging import get_logger

logger = get_logger(__name__)


# Define known attack chain patterns
# Each stage maps to rule IDs or categories that indicate that stage
ATTACK_CHAINS = {
    "recon_to_access": {
        "name": "Reconnaissance to Brute Force Attack",
        "description": (
            "Port scanning followed by authentication brute force - "
            "classic attack progression from discovery to access attempts"
        ),
        "stages": [
            {
                "stage": "reconnaissance",
                "rule_ids": ["SCAN_001", "SCAN_002", "SUSP_002"],
                "categories": ["reconnaissance"],
            },
            {
                "stage": "credential_access",
                "rule_ids": ["BRUTE_001"],
                "categories": ["credential_access"],
            },
        ],
        "severity_boost": 15,
    },
    "recon_to_c2": {
        "name": "Reconnaissance to C2 Communication",
        "description": (
            "Scanning followed by suspicious connections - "
            "possible post-compromise or attacker infrastructure probing"
        ),
        "stages": [
            {
                "stage": "reconnaissance",
                "rule_ids": ["SCAN_001", "SCAN_002"],
                "categories": ["reconnaissance"],
            },
            {
                "stage": "command_and_control",
                "rule_ids": ["SUSP_001", "DNS_001", "DNS_002"],
                "categories": ["command_and_control"],
            },
        ],
        "severity_boost": 20,
    },
    "mitm_attack": {
        "name": "Man-in-the-Middle Attack",
        "description": (
            "ARP spoofing detected - active traffic interception attempt"
        ),
        "stages": [
            {
                "stage": "man_in_the_middle",
                "rule_ids": ["ARP_001"],
                "categories": ["man_in_the_middle"],
            },
        ],
        "severity_boost": 10,
    },
    "dns_exfiltration": {
        "name": "DNS Exfiltration Pattern",
        "description": (
            "High DNS volume combined with anomalous domains - "
            "possible data exfiltration over DNS"
        ),
        "stages": [
            {
                "stage": "command_and_control",
                "rule_ids": ["DNS_001"],
                "categories": ["command_and_control"],
            },
            {
                "stage": "exfiltration",
                "rule_ids": ["DNS_002", "DNS_003"],
                "categories": ["exfiltration"],
            },
        ],
        "severity_boost": 15,
    },
}


class AttackChainAnalyzer:
    """
    Analyzes alerts for multi-stage attack patterns
    """
    
    def analyze(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze alerts for attack chain patterns
        
        Args:
            alerts: Buffered alerts for a source
            
        Returns:
            Chain analysis result:
            {
                "chain_detected": bool,
                "chain_name": str or None,
                "chain_description": str or None,
                "stages": [stage names],
                "matched_chain": dict or None,
                "severity_boost": int
            }
        """
        result = {
            "chain_detected": False,
            "chain_name": None,
            "chain_description": None,
            "stages": [],
            "matched_chain": None,
            "severity_boost": 0,
        }
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", datetime.utcnow())
        )
        
        # Get triggered rule IDs and categories
        triggered_rules = set(
            a.get("rule_id") for a in sorted_alerts if a.get("rule_id")
        )
        triggered_categories = set(
            a.get("category") for a in sorted_alerts if a.get("category")
        )
        
        # Check each chain pattern
        best_match = None
        best_match_stages = 0
        
        for chain_id, chain in ATTACK_CHAINS.items():
            match_result = self._match_chain(
                chain, sorted_alerts, triggered_rules, triggered_categories
            )
            
            if match_result["matched_stages"] > best_match_stages:
                best_match = (chain_id, chain, match_result)
                best_match_stages = match_result["matched_stages"]
        
        # If full chain matched (all stages), report it
        if best_match and best_match_stages >= len(best_match[1]["stages"]):
            chain_id, chain, match_result = best_match
            
            result.update({
                "chain_detected": True,
                "chain_name": chain["name"],
                "chain_description": chain["description"],
                "stages": match_result["stage_names"],
                "matched_chain": chain_id,
                "severity_boost": chain["severity_boost"],
                "stage_evidence": match_result["stage_evidence"],
            })
        
        # Even without full chain, record detected stages
        elif best_match and best_match_stages > 0:
            result["stages"] = best_match[2]["stage_names"]
            result["partial_chain"] = True
        
        return result
    
    def _match_chain(
        self,
        chain: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        triggered_rules: set,
        triggered_categories: set
    ) -> Dict[str, Any]:
        """
        Check if alerts match a chain pattern
        
        Args:
            chain: Chain pattern definition
            alerts: Sorted alerts
            triggered_rules: Set of triggered rule IDs
            triggered_categories: Set of triggered categories
            
        Returns:
            Match result with stage details
        """
        matched_stages = 0
        stage_names = []
        stage_evidence = []
        
        for stage in chain["stages"]:
            stage_rules = set(stage["rule_ids"])
            stage_categories = set(stage["categories"])
            
            # Check if stage triggered (by rule ID or category)
            if triggered_rules & stage_rules or triggered_categories & stage_categories:
                matched_stages += 1
                stage_names.append(stage["stage"])
                
                # Collect evidence for this stage
                evidence = []
                for alert in alerts:
                    if (
                        alert.get("rule_id") in stage_rules or
                        alert.get("category") in stage_categories
                    ):
                        evidence.append({
                            "rule_id": alert.get("rule_id"),
                            "title": alert.get("title"),
                            "timestamp": str(alert.get("timestamp")),
                        })
                
                stage_evidence.append({
                    "stage": stage["stage"],
                    "alerts": evidence[:5],  # Limit evidence
                })
        
        return {
            "matched_stages": matched_stages,
            "total_stages": len(chain["stages"]),
            "stage_names": stage_names,
            "stage_evidence": stage_evidence,
        }
