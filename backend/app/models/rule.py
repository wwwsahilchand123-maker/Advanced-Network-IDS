"""
Detection rule model
"""
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime
from datetime import datetime

from app.db.base_class import Base


class DetectionRule(Base):
    """Detection rule model"""
    
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True, index=True)
    severity = Column(String(20), nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    enabled = Column(Boolean, default=True, index=True)
    threshold_config = Column(JSON, nullable=True)
    cooldown_seconds = Column(Integer, default=300)
    mitre_attack_id = Column(String(50), nullable=True)
    mitre_technique = Column(String(255), nullable=True)
    detection_logic = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return (
            f"<DetectionRule(id={self.id}, "
            f"rule_id='{self.rule_id}', "
            f"name='{self.name}', "
            f"severity='{self.severity}')>"
        )
