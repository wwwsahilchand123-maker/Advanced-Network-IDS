"""
ARP cache model for ARP spoofing detection
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON
from datetime import datetime

from app.db.base_class import Base


class ARPCache(Base):
    """ARP cache model"""
    
    __tablename__ = "arp_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    mac_address = Column(String(17), nullable=False)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    change_count = Column(Integer, default=0)
    previous_macs = Column(JSON, nullable=True)  # Historical MAC addresses
    
    def __repr__(self):
        return (
            f"<ARPCache(id={self.id}, "
            f"ip='{self.ip_address}', "
            f"mac='{self.mac_address}')>"
        )
