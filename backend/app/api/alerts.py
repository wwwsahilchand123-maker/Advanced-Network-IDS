"""
Alert Management API
Complete alert lifecycle and analyst workflow
"""
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from datetime import datetime, timedelta

from app.api.deps import get_db, require_analyst, require_viewer, get_current_user
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import (
    Alert as AlertSchema,
    AlertDetail,
    AlertUpdate,
    AlertStats
)
from app.services.audit_service import create_audit_log
from app.scoring.mitre_mapper import mitre_mapper
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


@router.get("/", response_model=List[AlertDetail])
def list_alerts(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    search: Optional[str] = None,
) -> Any:
    """
    List alerts with filtering and pagination
    
    Filters:
    - severity: Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    - status: Filter by status (new, acknowledged, investigating, resolved, false_positive)
    - category: Filter by category
    - src_ip: Filter by source IP
    - dst_ip: Filter by destination IP
    - rule_id: Filter by detection rule
    - start_date: Filter from timestamp
    - end_date: Filter to timestamp
    - search: Search in title/description
    """
    query = db.query(Alert)
    
    # Apply filters
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    
    if status:
        query = query.filter(Alert.status == status.lower())
    
    if category:
        query = query.filter(Alert.category == category)
    
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)
    
    if dst_ip:
        query = query.filter(Alert.dst_ip == dst_ip)
    
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    
    if start_date:
        query = query.filter(Alert.timestamp >= start_date)
    
    if end_date:
        query = query.filter(Alert.timestamp <= end_date)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Alert.title.ilike(search_term)) |
            (Alert.description.ilike(search_term))
        )
    
    # Order by timestamp descending (newest first)
    query = query.order_by(desc(Alert.timestamp))
    
    # Pagination
    alerts = query.offset(skip).limit(limit).all()
    
    # Build detailed response
    results = []
    for alert in alerts:
        alert_dict = {
            "id": alert.id,
            "alert_uuid": alert.alert_uuid,
            "rule_id": alert.rule_id,
            "title": alert.title,
            "description": alert.description,
            "category": alert.category,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol,
            "evidence": alert.evidence,
            "mitre_attack_id": alert.mitre_attack_id,
            "timestamp": alert.timestamp,
            "status": alert.status,
            "assigned_to": alert.assigned_to,
            "resolution_notes": alert.resolution_notes,
            "resolved_at": alert.resolved_at,
            "resolved_by": alert.resolved_by,
        }
        
        # Add rule name if available
        if alert.rule:
            alert_dict["rule_name"] = alert.rule.name
        
        # Add assigned user name
        if alert.assigned_user:
            alert_dict["assigned_user_name"] = alert.assigned_user.username
        
        # Add resolver name
        if alert.resolver:
            alert_dict["resolver_name"] = alert.resolver.username
        
        # Enrich with MITRE details
        alert_dict = mitre_mapper.enrich_alert(alert_dict)
        
        results.append(alert_dict)
    
    return results


@router.get("/stats", response_model=AlertStats)
def get_alert_statistics(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    days: int = Query(7, ge=1, le=90),
) -> Any:
    """
    Get alert statistics
    
    Args:
        days: Number of days to include in stats
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Total alerts
    total = db.query(func.count(Alert.id)).scalar()
    
    # Alerts by status
    status_query = db.query(
        Alert.status,
        func.count(Alert.id)
    ).filter(Alert.timestamp >= cutoff).group_by(Alert.status).all()
    
    by_status = {status: count for status, count in status_query}
    
    # Alerts by severity
    severity_query = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).filter(Alert.timestamp >= cutoff).group_by(Alert.severity).all()
    
    by_severity = {severity: count for severity, count in severity_query}
    
    # Alerts by category
    category_query = db.query(
        Alert.category,
        func.count(Alert.id)
    ).filter(
        Alert.timestamp >= cutoff,
        Alert.category.isnot(None)
    ).group_by(Alert.category).all()
    
    by_category = {category: count for category, count in category_query}
    
    return {
        "total": total,
        "new": by_status.get("new", 0),
        "acknowledged": by_status.get("acknowledged", 0),
        "investigating": by_status.get("investigating", 0),
        "resolved": by_status.get("resolved", 0),
        "false_positive": by_status.get("false_positive", 0),
        "by_severity": by_severity,
        "by_category": by_category,
    }


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    alert_id: int,
) -> Any:
    """
    Get alert by ID with full details
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Build response
    result = {
        "id": alert.id,
        "alert_uuid": alert.alert_uuid,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "category": alert.category,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "protocol": alert.protocol,
        "evidence": alert.evidence,
        "mitre_attack_id": alert.mitre_attack_id,
        "timestamp": alert.timestamp,
        "status": alert.status,
        "assigned_to": alert.assigned_to,
        "resolution_notes": alert.resolution_notes,
        "resolved_at": alert.resolved_at,
        "resolved_by": alert.resolved_by,
    }
    
    # Add relationships
    if alert.rule:
        result["rule_name"] = alert.rule.name
    
    if alert.assigned_user:
        result["assigned_user_name"] = alert.assigned_user.username
    
    if alert.resolver:
        result["resolver_name"] = alert.resolver.username
    
    # Enrich with MITRE
    result = mitre_mapper.enrich_alert(result)
    
    return result


@router.patch("/{alert_id}", response_model=AlertDetail)
def update_alert(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    alert_id: int,
    alert_update: AlertUpdate,
) -> Any:
    """
    Update alert status and assignment
    
    Requires analyst or admin role
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Track what changed
    changes = {}
    
    # Update status
    if alert_update.status is not None:
        old_status = alert.status
        alert.status = alert_update.status
        changes["status"] = {"old": old_status, "new": alert.status}
        
        # If resolved or false positive, record resolver
        if alert.status in ["resolved", "false_positive"]:
            alert.resolved_at = datetime.utcnow()
            alert.resolved_by = current_user.id
    
    # Update assignment
    if alert_update.assigned_to is not None:
        old_assigned = alert.assigned_to
        alert.assigned_to = alert_update.assigned_to
        changes["assigned_to"] = {"old": old_assigned, "new": alert.assigned_to}
    
    # Update resolution notes
    if alert_update.resolution_notes is not None:
        alert.resolution_notes = alert_update.resolution_notes
    
    db.commit()
    db.refresh(alert)
    
    # Audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="alert_updated",
        resource_type="alert",
        resource_id=str(alert.id),
        details={"changes": changes, "alert_uuid": alert.alert_uuid},
        success=True
    )
    
    logger.info(
        f"Alert {alert.alert_uuid} updated by {current_user.username}: {changes}"
    )
    
    # Return updated alert
    return get_alert(db=db, current_user=current_user, alert_id=alert_id)


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    alert_id: int,
) -> Any:
    """
    Acknowledge an alert
    
    Shortcut for updating status to 'acknowledged'
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = "acknowledged"
    alert.assigned_to = current_user.id
    
    db.commit()
    
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="alert_acknowledged",
        resource_type="alert",
        resource_id=str(alert.id),
        details={"alert_uuid": alert.alert_uuid},
        success=True
    )
    
    return {"message": "Alert acknowledged", "status": "acknowledged"}


@router.post("/{alert_id}/false-positive")
def mark_false_positive(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    alert_id: int,
    notes: Optional[str] = None,
) -> Any:
    """
    Mark alert as false positive
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = "false_positive"
    alert.resolution_notes = notes or "Marked as false positive"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    
    db.commit()
    
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="alert_false_positive",
        resource_type="alert",
        resource_id=str(alert.id),
        details={
            "alert_uuid": alert.alert_uuid,
            "notes": notes
        },
        success=True
    )
    
    return {"message": "Alert marked as false positive", "status": "false_positive"}


@router.delete("/{alert_id}")
def delete_alert(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
    alert_id: int,
) -> Any:
    """
    Delete an alert
    
    Note: Prefer marking as false positive over deletion for audit trail
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert_uuid = alert.alert_uuid
    
    db.delete(alert)
    db.commit()
    
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="alert_deleted",
        resource_type="alert",
        resource_id=str(alert_id),
        details={"alert_uuid": alert_uuid},
        success=True
    )
    
    return {"message": "Alert deleted"}


@router.get("/timeline/recent")
def get_recent_alerts_timeline(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=500),
) -> Any:
    """
    Get recent alerts for timeline view
    
    Args:
        hours: Number of hours to look back
        limit: Maximum alerts to return
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    alerts = db.query(Alert).filter(
        Alert.timestamp >= cutoff
    ).order_by(desc(Alert.timestamp)).limit(limit).all()
    
    timeline = []
    for alert in alerts:
        timeline.append({
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "title": alert.title,
            "severity": alert.severity,
            "category": alert.category,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "status": alert.status,
        })
    
    return {
        "hours": hours,
        "count": len(timeline),
        "alerts": timeline
    }
