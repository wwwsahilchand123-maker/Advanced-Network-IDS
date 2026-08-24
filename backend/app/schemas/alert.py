"""
Pydantic schemas for Alert
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    """Base alert schema"""
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: str
    confidence: Optional[int] = Field(None, ge=0, le=100)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    mitre_attack_id: Optional[str] = None


class AlertCreate(AlertBase):
    """Schema for creating an alert"""
    rule_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlertUpdate(BaseModel):
    """Schema for updating an alert"""
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    resolution_notes: Optional[str] = None


class AlertInDBBase(AlertBase):
    """Base schema for alert in database"""
    id: int
    alert_uuid: str
    rule_id: Optional[str]
    timestamp: datetime
    status: str
    assigned_to: Optional[int]
    resolution_notes: Optional[str]
    resolved_at: Optional[datetime]
    resolved_by: Optional[int]
    
    class Config:
        from_attributes = True


class Alert(AlertInDBBase):
    """Schema for alert response"""
    pass


class AlertDetail(Alert):
    """Detailed alert schema with relationships"""
    rule_name: Optional[str] = None
    assigned_user_name: Optional[str] = None
    resolver_name: Optional[str] = None


class AlertStats(BaseModel):
    """Alert statistics schema"""
    total: int
    new: int
    acknowledged: int
    investigating: int
    resolved: int
    false_positive: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
