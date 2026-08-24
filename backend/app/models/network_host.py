"""
Network host model for discovered hosts
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON
from datetime import datetime

from app.db.base_class import Base


class NetworkHost(Base):
    """Discovered network host model"""
    
    __tablename__ = "network_hosts"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    packet_count = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    tags = Column(JSON, nullable=True)  # [internal, server, workstation]
    
    def __repr__(self):
        return (
            f"<NetworkHost(id={self.id}, "
            f"ip='{self.ip_address}', "
            f"hostname='{self.hostname}')>"
        )
