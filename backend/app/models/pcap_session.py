"""
PCAP analysis session model
"""
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.base_class import Base


class PcapSession(Base):
    """PCAP analysis session model"""
    
    __tablename__ = "pcap_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(BigInteger, nullable=True)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), nullable=True)  # processing, completed, failed
    packet_count = Column(Integer, nullable=True)
    flow_count = Column(Integer, nullable=True)
    alert_count = Column(Integer, nullable=True)
    analysis_report = Column(JSON, nullable=True)
    processed_at = Column(DateTime, nullable=True)
    
    # Relationships
    uploader = relationship("User", foreign_keys=[uploaded_by])
    
    def __repr__(self):
        return (
            f"<PcapSession(id={self.id}, "
            f"filename='{self.filename}', "
            f"status='{self.status}')>"
        )
