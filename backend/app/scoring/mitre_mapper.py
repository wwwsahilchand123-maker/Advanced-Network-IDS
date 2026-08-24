"""
MITRE ATT&CK Mapper
Maps detections to MITRE ATT&CK techniques
Only includes verified, genuine mappings
"""
from typing import Dict, Any, List, Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


# Verified MITRE ATT&CK technique mappings
# Only techniques where the detected behavior genuinely corresponds
MITRE_TECHNIQUES = {
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running "
            "on remote hosts, including those that may be vulnerable to "
            "remote software exploitation."
        ),
        "url": "https://attack.mitre.org/techniques/T1046",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to attempt access "
            "to accounts when passwords are unknown or when password "
            "hashes are obtained."
        ),
        "url": "https://attack.mitre.org/techniques/T1110",
    },
    "T1557.002": {
        "name": "ARP Cache Poisoning",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may poison Address Resolution Protocol (ARP) "
            "caches to position themselves between the communication "
            "of two or more networked devices."
        ),
        "url": "https://attack.mitre.org/techniques/T1557/002",
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using the Domain Name System "
            "(DNS) application layer protocol to avoid detection."
        ),
        "url": "https://attack.mitre.org/techniques/T1071/004",
    },
    "T1568.002": {
        "name": "Domain Generation Algorithms",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may make use of Domain Generation Algorithms "
            "(DGAs) to dynamically identify a destination domain for "
            "command and control traffic."
        ),
        "url": "https://attack.mitre.org/techniques/T1568/002",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using OSI application layer "
            "protocols to avoid detection/network filtering."
        ),
        "url": "https://attack.mitre.org/techniques/T1071",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an "
            "existing command and control channel."
        ),
        "url": "https://attack.mitre.org/techniques/T1041",
    },
}


class MitreMapper:
    """
    Maps detections to MITRE ATT&CK techniques
    """
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get technique details by ID
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            Technique details or None
        """
        return MITRE_TECHNIQUES.get(technique_id)
    
    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich alert with MITRE technique details
        
        Args:
            alert: Alert data
            
        Returns:
            Enriched alert
        """
        technique_id = alert.get("mitre_attack_id")
        
        if technique_id:
            technique = self.get_technique(technique_id)
            if technique:
                alert["mitre_details"] = {
                    "id": technique_id,
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "description": technique["description"],
                    "url": technique["url"],
                }
        
        return alert
    
    def enrich_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich incident with MITRE technique details
        
        Args:
            incident: Incident data
            
        Returns:
            Enriched incident
        """
        technique_ids = incident.get("mitre_techniques", [])
        enriched = []
        
        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                enriched.append({
                    "id": tech_id,
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "url": technique["url"],
                })
        
        incident["mitre_details"] = enriched
        return incident
    
    def get_all_techniques(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all supported techniques
        
        Returns:
            All technique mappings
        """
        return MITRE_TECHNIQUES.copy()


# Global mapper instance
mitre_mapper = MitreMapper()
