"""
Detection service for managing detection engine
Now broadcasts alerts via WebSocket
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.services.incident_service import incident_service
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.core.config import settings
from app.core.logging import get_logger

# Import WebSocket manager
from app.websocket.manager import manager as ws_manager

logger = get_logger(__name__)


class DetectionService:
    """
    Service for managing detection engine and correlation
    """
    
    def __init__(self):
        """Initialize detection service"""
        self.engine: Optional[DetectionEngine] = None
        self.correlation_engine: Optional[CorrelationEngine] = None
        self._db = None
    
    def initialize(self, db: Session) -> bool:
        """
        Initialize detection engine and correlation
        
        Args:
            db: Database session
            
        Returns:
            True if initialized successfully
        """
        try:
            self._db = db
            
            # Alert callback: stores alert, broadcasts via WebSocket, then correlates
            def alert_callback(alert_data: Dict[str, Any]):
                try:
                    stored = self._store_alert(db, alert_data)
                    
                    if stored:
                        # Attach DB ID for incident linking
                        alert_data["id"] = stored.id
                        
                        # Broadcast via WebSocket (async call from sync context)
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                asyncio.create_task(
                                    ws_manager.broadcast_alert(self._format_alert_for_ws(stored))
                                )
                            else:
                                loop.run_until_complete(
                                    ws_manager.broadcast_alert(self._format_alert_for_ws(stored))
                                )
                        except Exception as e:
                            logger.error(f"Error broadcasting alert via WebSocket: {e}")
                        
                        # Send to correlation engine
                        if self.correlation_engine:
                            incident = self.correlation_engine.process_alert(alert_data)
                            
                            if incident:
                                stored_incident = incident_service.store_incident(db, incident)
                                
                                # Broadcast incident via WebSocket
                                if stored_incident:
                                    try:
                                        loop = asyncio.get_event_loop()
                                        if loop.is_running():
                                            asyncio.create_task(
                                                ws_manager.broadcast_incident(
                                                    self._format_incident_for_ws(stored_incident)
                                                )
                                            )
                                    except Exception as e:
                                        logger.error(f"Error broadcasting incident: {e}")
                
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}", exc_info=True)
            
            # Initialize detection engine
            self.engine = DetectionEngine(alert_callback=alert_callback)
            
            # Load rules
            self._load_rules_from_db(db)
            self.engine.load_rules(settings.DETECTION_RULES_PATH)
            
            # Initialize correlation engine
            def incident_callback(incident: Dict[str, Any], action: str):
                """Callback when incident created/updated"""
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    
                    message = {
                        "incident": incident,
                        "action": action,  # created, updated, escalated
                    }
                    
                    if loop.is_running():
                        asyncio.create_task(ws_manager.broadcast_incident(message))
                except Exception as e:
                    logger.error(f"Error in incident callback: {e}")
            
            self.correlation_engine = CorrelationEngine(incident_callback=incident_callback)
            
            logger.info("Detection and correlation engines initialized")
            return True
        
        except Exception as e:
            logger.error(f"Error initializing detection service: {e}", exc_info=True)
            return False
    
    def analyze_packet(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze packet for threats (includes correlation and WebSocket broadcast)
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            List of generated alerts
        """
        if not self.engine:
            return []
        
        return self.engine.analyze_packet(packet, flow)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection and correlation statistics
        
        Returns:
            Statistics dictionary
        """
        stats = {}
        
        if self.engine:
            stats["detection"] = self.engine.get_statistics()
        
        if self.correlation_engine:
            stats["correlation"] = self.correlation_engine.get_statistics()
        
        return stats
    
    def _load_rules_from_db(self, db: Session) -> None:
        """Load rules from database"""
        try:
            if self.engine:
                count = self.engine.rule_manager.load_rules_from_database(db)
                logger.info(f"Loaded {count} rules from database")
        except Exception as e:
            logger.error(f"Error loading rules from database: {e}")
    
    def _store_alert(self, db: Session, alert_data: Dict[str, Any]) -> Optional[Alert]:
        """
        Store alert in database
        
        Args:
            db: Database session
            alert_data: Alert data
            
        Returns:
            Stored alert or None
        """
        try:
            alert = Alert(
                rule_id=alert_data.get("rule_id"),
                title=alert_data["title"],
                description=alert_data.get("description"),
                category=alert_data.get("category"),
                severity=alert_data["severity"],
                confidence=alert_data.get("confidence"),
                src_ip=alert_data.get("src_ip"),
                dst_ip=alert_data.get("dst_ip"),
                src_port=alert_data.get("src_port"),
                dst_port=alert_data.get("dst_port"),
                protocol=alert_data.get("protocol"),
                evidence=alert_data.get("evidence"),
                mitre_attack_id=alert_data.get("mitre_attack_id"),
                timestamp=alert_data.get("timestamp", datetime.utcnow()),
                status="new"
            )
            
            db.add(alert)
            db.commit()
            db.refresh(alert)
            
            logger.info(f"Alert stored: {alert.title} ({alert.severity})")
            return alert
        
        except Exception as e:
            logger.error(f"Error storing alert: {e}", exc_info=True)
            db.rollback()
            return None
    
    def _format_alert_for_ws(self, alert: Alert) -> Dict[str, Any]:
        """Format alert for WebSocket broadcast"""
        return {
            "id": alert.id,
            "alert_uuid": alert.alert_uuid,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "category": alert.category,
            "confidence": alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol,
            "timestamp": alert.timestamp.isoformat(),
            "status": alert.status,
        }
    
    def _format_incident_for_ws(self, incident) -> Dict[str, Any]:
        """Format incident for WebSocket broadcast"""
        return {
            "id": incident.id,
            "incident_uuid": incident.incident_uuid,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "src_ip": incident.src_ip,
            "alert_count": incident.alert_count,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
        }


# Global detection service instance
detection_service = DetectionService()
