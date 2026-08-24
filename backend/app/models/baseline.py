"""
Traffic baseline model for anomaly detection
"""
from sqlalchemy import Column, Integer, String, JSON, DateTime
from datetime import datetime

from app.db.base_class import Base


class TrafficBaseline(Base):
    """Traffic baseline model"""
    
    __tablename__ = "traffic_baseline"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    baseline_value = Column(JSON, nullable=False)  # {mean, stddev, min, max}
    time_period = Column(String(50), nullable=True)  # hourly, daily, weekly
    calculated_at = Column(DateTime, default=datetime.utcnow)
    sample_count = Column(Integer, nullable=True)
    
    def __repr__(self):
        return (
            f"<TrafficBaseline(id={self.id}, "
            f"metric='{self.metric_name}', "
            f"period='{self.time_period}')>"
        )
