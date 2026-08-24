"""
Incident Management API
Correlated security incidents with full investigation workflow
"""
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta

from app.api.deps import get_db, require_analyst, require_viewer, get_current_user
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.user import User
from app.schemas.incident import (
    Incident as IncidentSchema,
    IncidentDetail,
    IncidentUpdate,
    IncidentStats
)
from app.services.incident_service import incident_service
from app.services.audit_service import create_audit_log
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


@router.get("/", response_model=List[IncidentSchema])
def list_incidents(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    min_risk_score: Optional[int] = Query(None, ge=0, le=100),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> Any:
    """
    List incidents with filtering and pagination
    
    Filters:
    - severity: Filter by severity
    - status: Filter by status (open, investigating, contained, resolved)
    - src_ip: Filter by source IP
    - min_risk_score: Minimum risk score
    - start_date: Filter from timestamp
    - end_date: Filter to timestamp
    """
    query = db.query(Incident)
    
    # Apply filters
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    
    if status:
        query = query.filter(Incident.status == status.lower())
    
    if src_ip:
        query = query.filter(Incident.src_ip == src_ip)
    
    if min_risk_score is not None:
        query = query.filter(Incident.risk_score >= min_risk_score)
    
    if start_date:
        query = query.filter(Incident.first_seen >= start_date)
    
    if end_date:
        query = query.filter(Incident.last_seen <= end_date)
    
    # Order by risk score descending, then by last seen
    query = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen))
    
    # Pagination
    incidents = query.offset(skip).limit(limit).all()
    
    return incidents


@router.get("/stats", response_model=IncidentStats)
def get_incident_statistics(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    days: int = Query(7, ge=1, le=90),
) -> Any:
    """
    Get incident statistics
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Total incidents
    total = db.query(func.count(Incident.id)).scalar()
    
    # By status
    status_query = db.query(
        Incident.status,
        func.count(Incident.id)
    ).filter(Incident.first_seen >= cutoff).group_by(Incident.status).all()
    
    by_status = {status: count for status, count in status_query}
    
    # By severity
    severity_query = db.query(
        Incident.severity,
        func.count(Incident.id)
    ).filter(Incident.first_seen >= cutoff).group_by(Incident.severity).all()
    
    by_severity = {severity: count for severity, count in severity_query}
    
    # Average risk score
    avg_risk = db.query(func.avg(Incident.risk_score)).filter(
        Incident.first_seen >= cutoff
    ).scalar() or 0.0
    
    return {
        "total": total,
        "open": by_status.get("open", 0),
        "investigating": by_status.get("investigating", 0),
        "contained": by_status.get("contained", 0),
        "resolved": by_status.get("resolved", 0),
        "by_severity": by_severity,
        "avg_risk_score": round(avg_risk, 2),
    }


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    incident_id: int,
) -> Any:
    """
    Get incident by ID with full details including related alerts
    """
    incident_data = incident_service.get_incident_with_details(db, incident_id)
    
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident_data


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    incident_id: int,
    incident_update: IncidentUpdate,
) -> Any:
    """
    Update incident
    
    Requires analyst or admin role
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    changes = {}
    
    # Update fields
    if incident_update.title is not None:
        old_title = incident.title
        incident.title = incident_update.title
        changes["title"] = {"old": old_title, "new": incident.title}
    
    if incident_update.description is not None:
        incident.description = incident_update.description
    
    if incident_update.severity is not None:
        old_severity = incident.severity
        incident.severity = incident_update.severity
        changes["severity"] = {"old": old_severity, "new": incident.severity}
    
    if incident_update.risk_score is not None:
        old_risk = incident.risk_score
        incident.risk_score = incident_update.risk_score
        changes["risk_score"] = {"old": old_risk, "new": incident.risk_score}
    
    if incident_update.status is not None:
        old_status = incident.status
        incident.status = incident_update.status
        changes["status"] = {"old": old_status, "new": incident.status}
        
        # If resolved, record timestamp
        if incident.status == "resolved":
            incident.resolved_at = datetime.utcnow()
    
    if incident_update.assigned_to is not None:
        old_assigned = incident.assigned_to
        incident.assigned_to = incident_update.assigned_to
        changes["assigned_to"] = {"old": old_assigned, "new": incident.assigned_to}
    
    db.commit()
    db.refresh(incident)
    
    # Audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="incident_updated",
        resource_type="incident",
        resource_id=str(incident.id),
        details={
            "changes": changes,
            "incident_uuid": incident.incident_uuid
        },
        success=True
    )
    
    logger.info(
        f"Incident {incident.incident_uuid} updated by {current_user.username}: {changes}"
    )
    
    # Return updated incident with details
    return incident_service.get_incident_with_details(db, incident_id)


@router.post("/{incident_id}/escalate")
def escalate_incident(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    incident_id: int,
    notes: Optional[str] = None,
) -> Any:
    """
    Escalate incident to CRITICAL severity
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    old_severity = incident.severity
    incident.severity = "CRITICAL"
    incident.status = "investigating"
    
    # Increase risk score if not already max
    if incident.risk_score < 95:
        incident.risk_score = min(100, incident.risk_score + 10)
    
    db.commit()
    
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="incident_escalated",
        resource_type="incident",
        resource_id=str(incident.id),
        details={
            "incident_uuid": incident.incident_uuid,
            "old_severity": old_severity,
            "new_severity": "CRITICAL",
            "notes": notes
        },
        success=True
    )
    
    logger.warning(
        f"Incident {incident.incident_uuid} ESCALATED to CRITICAL by {current_user.username}"
    )
    
    return {
        "message": "Incident escalated to CRITICAL",
        "severity": "CRITICAL",
        "risk_score": incident.risk_score
    }


@router.post("/{incident_id}/resolve")
def resolve_incident(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    incident_id: int,
    resolution_summary: str,
) -> Any:
    """
    Resolve an incident
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    incident.status = "resolved"
    incident.resolved_at = datetime.utcnow()
    
    # Store resolution summary in attack_chain or dedicated field
    if isinstance(incident.attack_chain, dict):
        incident.attack_chain["resolution_summary"] = resolution_summary
    
    db.commit()
    
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="incident_resolved",
        resource_type="incident",
        resource_id=str(incident.id),
        details={
            "incident_uuid": incident.incident_uuid,
            "resolution_summary": resolution_summary
        },
        success=True
    )
    
    logger.info(
        f"Incident {incident.incident_uuid} RESOLVED by {current_user.username}"
    )
    
    return {
        "message": "Incident resolved",
        "status": "resolved",
        "resolved_at": incident.resolved_at
    }


@router.get("/{incident_id}/alerts")
def get_incident_alerts(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    incident_id: int,
) -> Any:
    """
    Get all alerts associated with an incident
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Get related alerts through relationship
    alerts = incident.alerts
    
    return {
        "incident_id": incident_id,
        "incident_uuid": incident.incident_uuid,
        "alert_count": len(alerts),
        "alerts": [
            {
                "id": alert.id,
                "alert_uuid": alert.alert_uuid,
                "title": alert.title,
                "severity": alert.severity,
                "category": alert.category,
                "timestamp": alert.timestamp,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "status": alert.status,
            }
            for alert in sorted(alerts, key=lambda a: a.timestamp)
        ]
    }


@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    incident_id: int,
) -> Any:
    """
    Get incident timeline with chronological events
    """
    incident_data = incident_service.get_incident_with_details(db, incident_id)
    
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return {
        "incident_id": incident_id,
        "incident_uuid": incident_data["incident_uuid"],
        "timeline": incident_data.get("timeline", []),
        "first_seen": incident_data["first_seen"],
        "last_seen": incident_data["last_seen"],
        "duration_seconds": (
            incident_data["last_seen"] - incident_data["first_seen"]
        ).total_seconds() if incident_data["first_seen"] and incident_data["last_seen"] else 0
    }


@router.get("/live/active")
def get_active_incidents(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    limit: int = Query(20, ge=1, le=100),
) -> Any:
    """
    Get currently active (open or investigating) incidents
    """
    incidents = db.query(Incident).filter(
        Incident.status.in_(["open", "investigating"])
    ).order_by(
        desc(Incident.risk_score),
        desc(Incident.last_seen)
    ).limit(limit).all()
    
    return {
        "count": len(incidents),
        "incidents": [
            {
                "id": inc.id,
                "incident_uuid": inc.incident_uuid,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "status": inc.status,
                "src_ip": inc.src_ip,
                "alert_count": inc.alert_count,
                "first_seen": inc.first_seen,
                "last_seen": inc.last_seen,
            }
            for inc in incidents
        ]
    }
