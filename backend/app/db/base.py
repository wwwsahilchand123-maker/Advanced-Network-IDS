"""
Database base configuration
Import all models here for Alembic migrations
"""
from app.db.base_class import Base

# Import all models so Alembic can detect them
from app.models.user import User
from app.models.flow import Flow
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.models.rule import DetectionRule
from app.models.baseline import TrafficBaseline
from app.models.arp_cache import ARPCache
from app.models.dns_query import DNSQuery
from app.models.pcap_session import PcapSession
from app.models.audit_log import AuditLog
from app.models.network_host import NetworkHost
from app.models.threat_intel import ThreatIntel

__all__ = [
    "Base",
    "User",
    "Flow",
    "Alert",
    "Incident",
    "IncidentAlert",
    "DetectionRule",
    "TrafficBaseline",
    "ARPCache",
    "DNSQuery",
    "PcapSession",
    "AuditLog",
    "NetworkHost",
    "ThreatIntel",
]
