"""
Alert model for security events
"""
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.base_class import Base


class Alert(Base):
    """Security alert model"""
    
    __tablename__ = "alerts"
    
    id = Column(BigInteger, primary_key=True, index=True)
    alert_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(50), ForeignKey("detection_rules.rule_id"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True, index=True)
    severity = Column(String(20), nullable=False, index=True)
    confidence = Column(Integer, nullable=True)  # 0-100
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    evidence = Column(JSON, nullable=True)
    mitre_attack_id = Column(String(50), nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    status = Column(String(50), default="new", index=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    rule = relationship("DetectionRule", foreign_keys=[rule_id])
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    resolver = relationship("User", foreign_keys=[resolved_by])
    
    def __repr__(self):
        return (
            f"<Alert(id={self.id}, "
            f"title='{self.title}', "
            f"severity='{self.severity}', "
            f"status='{self.status}')>"
        )
