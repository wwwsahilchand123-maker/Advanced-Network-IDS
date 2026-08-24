"""
Threat intelligence cache model (optional)
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON
from datetime import datetime

from app.db.base_class import Base


class ThreatIntel(Base):
    """Threat intelligence cache model"""
    
    __tablename__ = "threat_intel"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), unique=True, nullable=False, index=True)
    indicator_type = Column(String(50), nullable=True, index=True)  # ip, domain, hash
    threat_level = Column(String(20), nullable=True)
    categories = Column(JSON, nullable=True)
    source = Column(String(100), nullable=True)
    confidence = Column(Integer, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_checked = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(JSON, nullable=True)
    
    def __repr__(self):
        return (
            f"<ThreatIntel(id={self.id}, "
            f"indicator='{self.indicator}', "
            f"type='{self.indicator_type}')>"
        )
