"""
Incident model for correlated security events
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, BigInteger, Table
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.base_class import Base


# Association table for incident-alert many-to-many relationship
incident_alerts = Table(
    'incident_alerts',
    Base.metadata,
    Column('incident_id', Integer, ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
    Column('alert_id', BigInteger, ForeignKey('alerts.id', ondelete='CASCADE'), primary_key=True)
)


class Incident(Base):
    """Security incident model (correlated alerts)"""
    
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Integer, nullable=True)  # 0-100
    status = Column(String(50), default="open", index=True)
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ips = Column(JSON, nullable=True)  # Array of target IPs
    attack_chain = Column(JSON, nullable=True)  # Timeline of events
    first_seen = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    alert_count = Column(Integer, default=0)
    affected_hosts = Column(Integer, default=0)
    mitre_techniques = Column(JSON, nullable=True)  # Array of MITRE ATT&CK IDs
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    alerts = relationship("Alert", secondary=incident_alerts, backref="incidents")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    
    def __repr__(self):
        return (
            f"<Incident(id={self.id}, "
            f"title='{self.title}', "
            f"severity='{self.severity}', "
            f"status='{self.status}', "
            f"alert_count={self.alert_count})>"
        )


# Create IncidentAlert class for the association table
class IncidentAlert(Base):
    """Association between incidents and alerts"""
    __table__ = incident_alerts
