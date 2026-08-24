1.

# PHASE 2: Backend Core Implementation

Let me build the complete backend foundation with all core components.

---

## 📁 File 1: `backend/requirements.txt`

```
txt
```

```
# Web Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-multipart==0.0.6

# Database
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.9

# Data Validation
pydantic==2.5.0
pydantic-settings==2.1.0

# Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4

# Network Analysis
scapy==2.5.0

# Async/Background Tasks
redis==5.0.1
aiofiles==23.2.1

# Utilities
python-dotenv==1.0.0
PyYAML==6.0.1

# Data Processing
pandas==2.1.3
numpy==1.26.2

# Reporting
reportlab==4.0.7

# WebSocket
websockets==12.0

# Date/Time
python-dateutil==2.8.2
```

---

## 📁 File 2: `backend/requirements-dev.txt`

```
txt
```

```
-r requirements.txt

# Testing
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
httpx==0.25.2

# Code Quality
black==23.11.0
flake8==6.1.0
mypy==1.7.1
isort==5.12.0

# Development
ipython==8.18.1
```

---

## 📁 File 3: `.env.example`

```
Bash
```

```
# Application
APP_NAME=Advanced IDS
APP_VERSION=1.0.0
ENVIRONMENT=development
DEBUG=True

# API
API_V1_PREFIX=/api/v1
BACKEND_CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]

# Database
DATABASE_URL=postgresql://ids_user:ids_password@localhost:5432/ids_db
# Fallback for development
# DATABASE_URL=sqlite:///./ids.db

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-change-in-production-min-32-chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Admin User (for initial setup)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@ids.local
ADMIN_PASSWORD=ChangeThisPassword123!

# Network Capture
DEFAULT_INTERFACE=eth0
CAPTURE_BUFFER_SIZE=2048
MAX_PACKET_RETENTION_HOURS=24
MAX_FLOW_RETENTION_DAYS=7

# Detection Engine
DETECTION_RULES_PATH=./detection_rules
BASELINE_CALCULATION_INTERVAL=3600
CORRELATION_TIME_WINDOW=300

# Alert Configuration
ALERT_RETENTION_DAYS=90
INCIDENT_RETENTION_DAYS=365

# PCAP Analysis
PCAP_UPLOAD_DIR=./uploads/pcaps
MAX_PCAP_SIZE_MB=500

# Report Generation
REPORTS_OUTPUT_DIR=./reports

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/ids.log

# Demo Mode
DEMO_MODE=False
DEMO_EVENT_INTERVAL=5

# Optional: Threat Intelligence
ENABLE_THREAT_INTEL=False
# VIRUSTOTAL_API_KEY=
# ABUSEIPDB_API_KEY=
```

---

## 📁 File 4: `backend/app/core/config.py`

```
Python
```

```
"""
Application Configuration
Centralized settings management using Pydantic
"""
from typing import List, Optional
from pydantic import AnyHttpUrl, PostgresDsn, validator
from pydantic_settings import BaseSettings
import secrets


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Advanced IDS"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # API
    API_V1_PREFIX: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173"
    ]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # Database
    DATABASE_URL: str = "sqlite:///./ids.db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Admin User
    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@ids.local"
    ADMIN_PASSWORD: str = "ChangeThisPassword123!"
    
    # Network Capture
    DEFAULT_INTERFACE: str = "eth0"
    CAPTURE_BUFFER_SIZE: int = 2048
    MAX_PACKET_RETENTION_HOURS: int = 24
    MAX_FLOW_RETENTION_DAYS: int = 7
    
    # Detection Engine
    DETECTION_RULES_PATH: str = "./detection_rules"
    BASELINE_CALCULATION_INTERVAL: int = 3600
    CORRELATION_TIME_WINDOW: int = 300
    
    # Alert Configuration
    ALERT_RETENTION_DAYS: int = 90
    INCIDENT_RETENTION_DAYS: int = 365
    
    # PCAP Analysis
    PCAP_UPLOAD_DIR: str = "./uploads/pcaps"
    MAX_PCAP_SIZE_MB: int = 500
    
    # Report Generation
    REPORTS_OUTPUT_DIR: str = "./reports"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/ids.log"
    
    # Demo Mode
    DEMO_MODE: bool = False
    DEMO_EVENT_INTERVAL: int = 5
    
    # Threat Intelligence
    ENABLE_THREAT_INTEL: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()
```

---

## 📁 File 5: `backend/app/core/security.py`

```
Python
```

```
"""
Security utilities for authentication and authorization
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password from database
        
    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token
    
    Args:
        data: Dictionary containing user data to encode
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token
    
    Args:
        data: Dictionary containing user data to encode
        
    Returns:
        Encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def validate_password_strength(password: str) -> bool:
    """
    Validate password meets minimum security requirements
    
    Requirements:
    - At least 8 characters
    - Contains uppercase letter
    - Contains lowercase letter
    - Contains digit
    - Contains special character
    
    Args:
        password: Password to validate
        
    Returns:
        True if password meets requirements
        
    Raises:
        ValueError: If password doesn't meet requirements
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        raise ValueError("Password must contain at least one special character")
    
    return True
```

---

## 📁 File 6: `backend/app/core/logging.py`

```
Python
```

```
"""
Logging configuration
"""
import logging
import sys
from pathlib import Path
from typing import Optional

from app.core.config import settings


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """
    Configure application logging
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
    """
    level = log_level or settings.LOG_LEVEL
    file_path = log_file or settings.LOG_FILE
    
    # Create logs directory if it doesn't exist
    if file_path:
        log_dir = Path(file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure logging format
    log_format = (
        "%(asctime)s - %(name)s - %(levelname)s - "
        "%(filename)s:%(lineno)d - %(message)s"
    )
    
    # Configure handlers
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if file_path:
        handlers.append(
            logging.FileHandler(file_path, encoding='utf-8')
        )
    
    # Basic configuration
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=log_format,
        handlers=handlers
    )
    
    # Set third-party loggers to WARNING
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
```

---

## 📁 File 7: `backend/app/db/base.py`

```
Python
```

```
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
```

---

## 📁 File 8: `backend/app/db/base_class.py`

```
Python
```

```
"""
Base class for SQLAlchemy models
"""
from typing import Any
from sqlalchemy.ext.declarative import as_declarative, declared_attr


@as_declarative()
class Base:
    """Base class for all database models"""
    
    id: Any
    __name__: str
    
    # Generate __tablename__ automatically
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
```

---

## 📁 File 9: `backend/app/db/session.py`

```
Python
```

```
"""
Database session management
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.core.config import settings


# Create database engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Verify connections before using
    echo=settings.DEBUG,  # Log SQL queries in debug mode
)

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session
    
    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

---

## 📁 File 10: `backend/app/models/user.py`

```
Python
```

```
"""
User model for authentication and authorization
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from datetime import datetime

from app.db.base_class import Base


class User(Base):
    """User model"""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(
        String(50),
        nullable=False,
        default="viewer"
    )  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
```

---

## 📁 File 11: `backend/app/models/flow.py`

```
Python
```

```
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
```

---

## 📁 File 12: `backend/app/models/rule.py`

```
Python
```

```
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
```

---

## 📁 File 13: `backend/app/models/alert.py`

```
Python
```

```
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
```

---

## 📁 File 14: `backend/app/models/incident.py`

```
Python
```

```
"""
Incident model for correlated security events
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, BigInteger, Table
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.base_class import Base


# Association table for incident-alert many-to-many relationship
incident_alerts = Table(
    'incident_alerts',
    Base.metadata,
    Column('incident_id', Integer, ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
    Column('alert_id', BigInteger, ForeignKey('alerts.id', ondelete='CASCADE'), primary_key=True)
)


class Incident(Base):
    """Security incident model (correlated alerts)"""
    
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Integer, nullable=True)  # 0-100
    status = Column(String(50), default="open", index=True)
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ips = Column(JSON, nullable=True)  # Array of target IPs
    attack_chain = Column(JSON, nullable=True)  # Timeline of events
    first_seen = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    alert_count = Column(Integer, default=0)
    affected_hosts = Column(Integer, default=0)
    mitre_techniques = Column(JSON, nullable=True)  # Array of MITRE ATT&CK IDs
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    alerts = relationship("Alert", secondary=incident_alerts, backref="incidents")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    
    def __repr__(self):
        return (
            f"<Incident(id={self.id}, "
            f"title='{self.title}', "
            f"severity='{self.severity}', "
            f"status='{self.status}', "
            f"alert_count={self.alert_count})>"
        )


# Create IncidentAlert class for the association table
class IncidentAlert(Base):
    """Association between incidents and alerts"""
    __table__ = incident_alerts
```

---

## 📁 File 15: `backend/app/models/baseline.py`

```
Python
```

```
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
```

---

## 📁 File 16: `backend/app/models/arp_cache.py`

```
Python
```

```
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
```

---

## 📁 File 17: `backend/app/models/dns_query.py`

```
Python
```

```
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
```

---

## 📁 File 18: `backend/app/models/pcap_session.py`

```
Python
```

```
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
```

---

## 📁 File 19: `backend/app/models/audit_log.py`

```
Python
```

```
"""
Audit log model for security-sensitive actions
"""
from sqlalchemy import Column, BigInteger, Integer, String, DateTime, JSON, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.db.base_class import Base


class AuditLog(Base):
    """Audit log model"""
    
    __tablename__ = "audit_log"
    
    id = Column(BigInteger, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return (
            f"<AuditLog(id={self.id}, "
            f"user='{self.username}', "
            f"action='{self.action}')>"
        )
```

---

## 📁 File 20: `backend/app/models/network_host.py`

```
Python
```

```
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
```

---

## 📁 File 21: `backend/app/models/threat_intel.py`

```
Python
```

```
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
    metadata = Column(JSON, nullable=True)
    
    def __repr__(self):
        return (
            f"<ThreatIntel(id={self.id}, "
            f"indicator='{self.indicator}', "
            f"type='{self.indicator_type}')>"
        )
```

---

## 📁 File 22: `backend/app/schemas/user.py`

```
Python
```

```
"""
Pydantic schemas for User
"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, validator

from app.core.security import validate_password_strength


class UserBase(BaseModel):
    """Base user schema"""
    username: str
    email: EmailStr
    role: str = "viewer"


class UserCreate(UserBase):
    """Schema for creating a user"""
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        validate_password_strength(v)
        return v
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['admin', 'analyst', 'viewer']
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user"""
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if v:
            validate_password_strength(v)
        return v


class UserInDBBase(UserBase):
    """Base schema for user in database"""
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True


class User(UserInDBBase):
    """Schema for user response"""
    pass


class UserInDB(UserInDBBase):
    """Schema for user in database with password hash"""
    password_hash: str
```

---

## 📁 File 23: `backend/app/schemas/token.py`

```
Python
```

```
"""
Pydantic schemas for authentication tokens
"""
from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    """Token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Token payload schema"""
    sub: Optional[int] = None
    exp: Optional[int] = None
    type: Optional[str] = None


class RefreshToken(BaseModel):
    """Refresh token request schema"""
    refresh_token: str
```

---

I'll continue with more schemas and the Alembic migration setup in the next response. This establishes the core backend foundation with:

✅ Configuration management
✅ Security utilities
✅ Logging
✅ Database session
✅ All SQLAlchemy models
✅ Initial Pydantic schemas

**Ready to continue with Phase 2?** Reply with "**CONTINUE**" for the rest of the backend core (more schemas, Alembic setup, and initial API structure).