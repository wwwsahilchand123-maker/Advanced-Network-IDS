"""
Pydantic schemas for Audit Log
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class AuditLogBase(BaseModel):
    """Base audit log schema"""
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    success: bool = True


class AuditLogCreate(AuditLogBase):
    """Schema for creating an audit log"""
    user_id: Optional[int] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogInDBBase(AuditLogBase):
    """Base schema for audit log in database"""
    id: int
    user_id: Optional[int]
    username: Optional[str]
    ip_address: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True


class AuditLog(AuditLogInDBBase):
    """Schema for audit log response"""
    pass
