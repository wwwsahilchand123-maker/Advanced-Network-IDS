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
