"""
Audit log service
"""
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True
) -> AuditLog:
    """
    Create an audit log entry
    
    Args:
        db: Database session
        action: Action performed
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        details: Additional details
        user_id: User ID who performed the action
        username: Username who performed the action
        ip_address: IP address of the user
        success: Whether the action was successful
        
    Returns:
        Created audit log entry
    """
    audit_log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        timestamp=datetime.utcnow(),
        success=success
    )
    
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    
    return audit_log
