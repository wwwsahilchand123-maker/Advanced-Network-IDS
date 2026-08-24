"""
Incident Service
Manages incident persistence and lifecycle
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime
import json

from app.models.incident import Incident, incident_alerts
from app.models.alert import Alert
from app.core.logging import get_logger
from app.scoring.mitre_mapper import mitre_mapper

logger = get_logger(__name__)


class IncidentService:
    """
    Service for incident management
    """
    
    def store_incident(
        self,
        db: Session,
        incident_data: Dict[str, Any]
    ) -> Optional[Incident]:
        """
        Store or update incident in database
        
        Args:
            db: Database session
            incident_data: Incident data from correlation engine
            
        Returns:
            Stored incident or None
        """
        try:
            # Check if incident already exists
            existing = db.query(Incident).filter(
                Incident.src_ip == incident_data["src_ip"],
                Incident.status.in_(["open", "investigating"])
            ).first()
            
            if existing:
                # Update existing incident
                self._update_existing(db, existing, incident_data)
                return existing
            
            # Create new incident
            incident = Incident(
                incident_uuid=incident_data["incident_uuid"],
                title=incident_data["title"],
                description=incident_data["description"],
                severity=incident_data["severity"],
                risk_score=incident_data["risk_score"],
                status="open",
                src_ip=incident_data["src_ip"],
                dst_ips=incident_data["dst_ips"],
                attack_chain=incident_data["attack_chain"],
                first_seen=incident_data["first_seen"],
                last_seen=incident_data["last_seen"],
                alert_count=incident_data["alert_count"],
                affected_hosts=incident_data["affected_hosts"],
                mitre_techniques=incident_data["mitre_techniques"],
            )
            
            db.add(incident)
            db.flush()  # Get ID
            
            # Link related alerts
            self._link_alerts(db, incident, incident_data.get("alerts", []))
            
            db.commit()
            db.refresh(incident)
            
            logger.info(
                f"Incident stored: {incident.incident_uuid} "
                f"({incident.severity}, risk={incident.risk_score})"
            )
            
            return incident
        
        except Exception as e:
            logger.error(f"Error storing incident: {e}", exc_info=True)
            db.rollback()
            return None
    
    def _update_existing(
        self,
        db: Session,
        incident: Incident,
        incident_data: Dict[str, Any]
    ) -> None:
        """
        Update existing incident
        
        Args:
            db: Database session
            incident: Existing incident
            incident_data: New incident data
        """
        incident.severity = incident_data["severity"]
        incident.risk_score = incident_data["risk_score"]
        incident.last_seen = incident_data["last_seen"]
        incident.alert_count = incident_data["alert_count"]
        incident.affected_hosts = incident_data["affected_hosts"]
        incident.attack_chain = incident_data["attack_chain"]
        incident.dst_ips = incident_data["dst_ips"]
        incident.mitre_techniques = incident_data["mitre_techniques"]
        
        # Link any new alerts
        self._link_alerts(db, incident, incident_data.get("alerts", []))
        
        db.commit()
    
    def _link_alerts(
        self,
        db: Session,
        incident: Incident,
        alerts_data: List[Dict[str, Any]]
    ) -> None:
        """
        Link alerts to incident
        
        Args:
            db: Database session
            incident: Incident
            alerts_data: Alert data
        """
        # Find matching stored alerts
        for alert_data in alerts_data:
            if not alert_data.get("id"):
                continue
            
            # Check if link already exists
            existing_link = db.execute(
                incident_alerts.select().where(
                    incident_alerts.c.incident_id == incident.id,
                    incident_alerts.c.alert_id == alert_data["id"]
                )
            ).first()
            
            if not existing_link:
                db.execute(
                    incident_alerts.insert().values(
                        incident_id=incident.id,
                        alert_id=alert_data["id"]
                    )
                )
    
    def get_incident_with_details(
        self,
        db: Session,
        incident_id: int
    ) -> Optional[Dict[str, Any]]:
        """
        Get incident with full details
        
        Args:
            db: Database session
            incident_id: Incident ID
            
        Returns:
            Detailed incident data
        """
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return None
        
        # Get related alerts
        alerts = db.query(Alert).join(
            incident_alerts,
            Alert.id == incident_alerts.c.alert_id
        ).filter(
            incident_alerts.c.incident_id == incident.id
        ).order_by(Alert.timestamp).all()
        
        # Build response
        result = {
            "id": incident.id,
            "incident_uuid": incident.incident_uuid,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "src_ip": incident.src_ip,
            "dst_ips": incident.dst_ips,
            "attack_chain": incident.attack_chain,
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "alert_count": incident.alert_count,
            "affected_hosts": incident.affected_hosts,
            "mitre_techniques": incident.mitre_techniques,
            "assigned_to": incident.assigned_to,
            "created_at": incident.created_at,
            "resolved_at": incident.resolved_at,
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "category": a.category,
                    "confidence": a.confidence,
                    "timestamp": a.timestamp,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                    "evidence": a.evidence,
                    "mitre_attack_id": a.mitre_attack_id,
                    "status": a.status,
                }
                for a in alerts
            ],
        }
        
        # Enrich with MITRE details
        result = mitre_mapper.enrich_incident(result)
        
        # Build timeline from alerts
        result["timeline"] = [
            {
                "timestamp": a.timestamp,
                "event": a.title,
                "severity": a.severity,
                "rule_id": a.rule_id,
                "description": a.description,
            }
            for a in alerts
        ]
        
        return result


# Global incident service instance
incident_service = IncidentService()
