"""
Pydantic schemas for Incident
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class IncidentBase(BaseModel):
    """Base incident schema"""
    title: str
    description: Optional[str] = None
    severity: str
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    src_ip: Optional[str] = None
    dst_ips: Optional[List[str]] = None
    attack_chain: Optional[List[Dict[str, Any]]] = None
    mitre_techniques: Optional[List[str]] = None


class IncidentCreate(IncidentBase):
    """Schema for creating an incident"""
    alert_ids: List[int] = []
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class IncidentUpdate(BaseModel):
    """Schema for updating an incident"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[str] = None
    assigned_to: Optional[int] = None


class IncidentInDBBase(IncidentBase):
    """Base schema for incident in database"""
    id: int
    incident_uuid: str
    status: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    affected_hosts: int
    assigned_to: Optional[int]
    created_at: datetime
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class Incident(IncidentInDBBase):
    """Schema for incident response"""
    pass


class IncidentDetail(Incident):
    """Detailed incident schema with alerts"""
    alert_ids: List[int] = []
    assigned_user_name: Optional[str] = None


class IncidentStats(BaseModel):
    """Incident statistics schema"""
    total: int
    open: int
    investigating: int
    contained: int
    resolved: int
    by_severity: Dict[str, int]
    avg_risk_score: float
