"""
DNS query model for DNS anomaly detection
"""
from sqlalchemy import Column, BigInteger, String, DateTime, JSON, Float
from datetime import datetime

from app.db.base_class import Base


class DNSQuery(Base):
    """DNS query log model"""
    
    __tablename__ = "dns_queries"
    
    id = Column(BigInteger, primary_key=True, index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    query_name = Column(String(255), nullable=False, index=True)
    query_type = Column(String(10), nullable=True)  # A, AAAA, MX, etc.
    response_ips = Column(JSON, nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    query_entropy = Column(Float, nullable=True)  # Shannon entropy
    
    def __repr__(self):
        return (
            f"<DNSQuery(id={self.id}, "
            f"src='{self.src_ip}', "
            f"query='{self.query_name}')>"
        )
