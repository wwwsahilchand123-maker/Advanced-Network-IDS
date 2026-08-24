"""
Pydantic schemas for PCAP Analysis
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class PcapSessionBase(BaseModel):
    """Base PCAP session schema"""
    filename: str
    file_size: Optional[int] = None


class PcapSessionCreate(PcapSessionBase):
    """Schema for creating a PCAP session"""
    uploaded_by: Optional[int] = None


class PcapSessionUpdate(BaseModel):
    """Schema for updating a PCAP session"""
    status: str
    packet_count: Optional[int] = None
    flow_count: Optional[int] = None
    alert_count: Optional[int] = None
    analysis_report: Optional[Dict[str, Any]] = None
    processed_at: Optional[datetime] = None


class PcapSessionInDBBase(PcapSessionBase):
    """Base schema for PCAP session in database"""
    id: int
    session_uuid: str
    uploaded_by: Optional[int]
    uploaded_at: datetime
    status: Optional[str]
    packet_count: Optional[int]
    flow_count: Optional[int]
    alert_count: Optional[int]
    analysis_report: Optional[Dict[str, Any]]
    processed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class PcapSession(PcapSessionInDBBase):
    """Schema for PCAP session response"""
    pass


class PcapAnalysisReport(BaseModel):
    """PCAP analysis report schema"""
    session_uuid: str
    filename: str
    packet_count: int
    flow_count: int
    alert_count: int
    duration_seconds: float
    protocols: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    summary: str
