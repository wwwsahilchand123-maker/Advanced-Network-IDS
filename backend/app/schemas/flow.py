"""
Pydantic schemas for Flow
"""
from typing import Optional, Dict
from datetime import datetime
from pydantic import BaseModel


class FlowBase(BaseModel):
    """Base flow schema"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None


class FlowCreate(FlowBase):
    """Schema for creating a flow"""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    packet_count: int = 0
    byte_count: int = 0
    tcp_flags: Optional[Dict[str, int]] = None
    interface: Optional[str] = None
    state: Optional[str] = None


class FlowUpdate(BaseModel):
    """Schema for updating a flow"""
    last_seen: datetime
    packet_count: int
    byte_count: int
    tcp_flags: Optional[Dict[str, int]] = None
    duration_ms: Optional[int] = None
    state: Optional[str] = None


class FlowInDBBase(FlowBase):
    """Base schema for flow in database"""
    id: int
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int
    tcp_flags: Optional[Dict[str, int]]
    duration_ms: Optional[int]
    interface: Optional[str]
    state: Optional[str]
    
    class Config:
        from_attributes = True


class Flow(FlowInDBBase):
    """Schema for flow response"""
    pass


class FlowStats(BaseModel):
    """Flow statistics schema"""
    total_flows: int
    active_flows: int
    total_packets: int
    total_bytes: int
    by_protocol: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
