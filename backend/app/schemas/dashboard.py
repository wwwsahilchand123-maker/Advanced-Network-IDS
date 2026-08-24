"""
Pydantic schemas for Dashboard
"""
from typing import List, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

class DashboardStats(BaseModel):
    """Overall dashboard statistics"""
    packets_analyzed: int
    active_flows: int
    alerts_today: int
    critical_alerts: int
    high_risk_sources: int
    total_bytes: int
    events_per_second: float


class TimeSeriesData(BaseModel):
    """Time series data point"""
    timestamp: datetime
    value: float
    label: Optional[str] = None


class ProtocolDistribution(BaseModel):
    """Protocol distribution data"""
    protocol: str
    count: int
    percentage: float


class TopHost(BaseModel):
    """Top host data"""
    ip_address: str
    count: int
    bytes: int
    risk_score: int = 0


class TopPort(BaseModel):
    """Top port data"""
    port: int
    protocol: str
    count: int


class AlertTrend(BaseModel):
    """Alert trend data"""
    timestamp: datetime
    severity: str
    count: int


class DashboardData(BaseModel):
    """Complete dashboard data"""
    stats: DashboardStats
    traffic_over_time: List[TimeSeriesData]
    protocol_distribution: List[ProtocolDistribution]
    top_sources: List[TopHost]
    top_destinations: List[TopHost]
    top_ports: List[TopPort]
    alert_trends: List[AlertTrend]
    recent_alerts: List[Dict[str, Any]]
