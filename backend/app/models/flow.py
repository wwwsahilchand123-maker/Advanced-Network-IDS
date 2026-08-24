"""
Network flow model for tracking connections
"""
from sqlalchemy import Column, BigInteger, Integer, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import INET
from datetime import datetime

from app.db.base_class import Base


class Flow(Base):
    """Network flow model (5-tuple aggregation)"""
    
    __tablename__ = "flows"
    
    id = Column(BigInteger, primary_key=True, index=True)
    src_ip = Column(String(45), nullable=False, index=True)  # Support IPv6
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False, index=True)
    src_mac = Column(String(17), nullable=True)
    dst_mac = Column(String(17), nullable=True)
    first_seen = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    packet_count = Column(Integer, default=0)
    byte_count = Column(BigInteger, default=0)
    tcp_flags = Column(JSON, nullable=True)  # {SYN: 5, ACK: 10, FIN: 2}
    duration_ms = Column(Integer, nullable=True)
    interface = Column(String(50), nullable=True)
    state = Column(String(20), nullable=True)  # NEW, ESTABLISHED, CLOSED
    
    def __repr__(self):
        return (
            f"<Flow(id={self.id}, "
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port}, "
            f"protocol={self.protocol})>"
        )
