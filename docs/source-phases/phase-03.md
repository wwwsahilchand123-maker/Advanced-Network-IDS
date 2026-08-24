# PHASE 2 CONTINUED: Schemas, Migrations, and Initial API

---

## 📁 File 24: `backend/app/schemas/alert.py`

```
Python
```

```
"""
Pydantic schemas for Alert
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    """Base alert schema"""
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: str
    confidence: Optional[int] = Field(None, ge=0, le=100)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    mitre_attack_id: Optional[str] = None


class AlertCreate(AlertBase):
    """Schema for creating an alert"""
    rule_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlertUpdate(BaseModel):
    """Schema for updating an alert"""
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    resolution_notes: Optional[str] = None


class AlertInDBBase(AlertBase):
    """Base schema for alert in database"""
    id: int
    alert_uuid: str
    rule_id: Optional[str]
    timestamp: datetime
    status: str
    assigned_to: Optional[int]
    resolution_notes: Optional[str]
    resolved_at: Optional[datetime]
    resolved_by: Optional[int]
    
    class Config:
        from_attributes = True


class Alert(AlertInDBBase):
    """Schema for alert response"""
    pass


class AlertDetail(Alert):
    """Detailed alert schema with relationships"""
    rule_name: Optional[str] = None
    assigned_user_name: Optional[str] = None
    resolver_name: Optional[str] = None


class AlertStats(BaseModel):
    """Alert statistics schema"""
    total: int
    new: int
    acknowledged: int
    investigating: int
    resolved: int
    false_positive: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
```

---

## 📁 File 25: `backend/app/schemas/incident.py`

```
Python
```

```
"""
Pydantic schemas for Incident
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class IncidentBase(BaseModel):
    """Base incident schema"""
    title: str
    description: Optional[str] = None
    severity: str
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    src_ip: Optional[str] = None
    dst_ips: Optional[List[str]] = None
    attack_chain: Optional[List[Dict[str, Any]]] = None
    mitre_techniques: Optional[List[str]] = None


class IncidentCreate(IncidentBase):
    """Schema for creating an incident"""
    alert_ids: List[int] = []
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class IncidentUpdate(BaseModel):
    """Schema for updating an incident"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[str] = None
    assigned_to: Optional[int] = None


class IncidentInDBBase(IncidentBase):
    """Base schema for incident in database"""
    id: int
    incident_uuid: str
    status: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    affected_hosts: int
    assigned_to: Optional[int]
    created_at: datetime
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class Incident(IncidentInDBBase):
    """Schema for incident response"""
    pass


class IncidentDetail(Incident):
    """Detailed incident schema with alerts"""
    alert_ids: List[int] = []
    assigned_user_name: Optional[str] = None


class IncidentStats(BaseModel):
    """Incident statistics schema"""
    total: int
    open: int
    investigating: int
    contained: int
    resolved: int
    by_severity: Dict[str, int]
    avg_risk_score: float
```

---

## 📁 File 26: `backend/app/schemas/flow.py`

```
Python
```

```
"""
Pydantic schemas for Flow
"""
from typing import Optional, Dict
from datetime import datetime
from pydantic import BaseModel


class FlowBase(BaseModel):
    """Base flow schema"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None


class FlowCreate(FlowBase):
    """Schema for creating a flow"""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    packet_count: int = 0
    byte_count: int = 0
    tcp_flags: Optional[Dict[str, int]] = None
    interface: Optional[str] = None
    state: Optional[str] = None


class FlowUpdate(BaseModel):
    """Schema for updating a flow"""
    last_seen: datetime
    packet_count: int
    byte_count: int
    tcp_flags: Optional[Dict[str, int]] = None
    duration_ms: Optional[int] = None
    state: Optional[str] = None


class FlowInDBBase(FlowBase):
    """Base schema for flow in database"""
    id: int
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int
    tcp_flags: Optional[Dict[str, int]]
    duration_ms: Optional[int]
    interface: Optional[str]
    state: Optional[str]
    
    class Config:
        from_attributes = True


class Flow(FlowInDBBase):
    """Schema for flow response"""
    pass


class FlowStats(BaseModel):
    """Flow statistics schema"""
    total_flows: int
    active_flows: int
    total_packets: int
    total_bytes: int
    by_protocol: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
```

---

## 📁 File 27: `backend/app/schemas/rule.py`

```
Python
```

```
"""
Pydantic schemas for Detection Rule
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class DetectionRuleBase(BaseModel):
    """Base detection rule schema"""
    rule_id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: str
    enabled: bool = True
    threshold_config: Optional[Dict[str, Any]] = None
    cooldown_seconds: int = 300
    mitre_attack_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    detection_logic: Optional[str] = None


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating a detection rule"""
    pass


class DetectionRuleUpdate(BaseModel):
    """Schema for updating a detection rule"""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    threshold_config: Optional[Dict[str, Any]] = None
    cooldown_seconds: Optional[int] = None
    severity: Optional[str] = None


class DetectionRuleInDBBase(DetectionRuleBase):
    """Base schema for detection rule in database"""
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class DetectionRule(DetectionRuleInDBBase):
    """Schema for detection rule response"""
    pass


class DetectionRuleStats(BaseModel):
    """Detection rule statistics"""
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
```

---

## 📁 File 28: `backend/app/schemas/dashboard.py`

```
Python
```

```
"""
Pydantic schemas for Dashboard
"""
from typing import List, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class DashboardStats(BaseModel):
    """Overall dashboard statistics"""
    packets_analyzed: int
    active_flows: int
    alerts_today: int
    critical_alerts: int
    high_risk_sources: int
    total_bytes: int
    events_per_second: float


class TimeSeriesData(BaseModel):
    """Time series data point"""
    timestamp: datetime
    value: float
    label: Optional[str] = None


class ProtocolDistribution(BaseModel):
    """Protocol distribution data"""
    protocol: str
    count: int
    percentage: float


class TopHost(BaseModel):
    """Top host data"""
    ip_address: str
    count: int
    bytes: int
    risk_score: int = 0


class TopPort(BaseModel):
    """Top port data"""
    port: int
    protocol: str
    count: int


class AlertTrend(BaseModel):
    """Alert trend data"""
    timestamp: datetime
    severity: str
    count: int


class DashboardData(BaseModel):
    """Complete dashboard data"""
    stats: DashboardStats
    traffic_over_time: List[TimeSeriesData]
    protocol_distribution: List[ProtocolDistribution]
    top_sources: List[TopHost]
    top_destinations: List[TopHost]
    top_ports: List[TopPort]
    alert_trends: List[AlertTrend]
    recent_alerts: List[Dict[str, Any]]
```

---

## 📁 File 29: `backend/app/schemas/pcap.py`

```
Python
```

```
"""
Pydantic schemas for PCAP Analysis
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class PcapSessionBase(BaseModel):
    """Base PCAP session schema"""
    filename: str
    file_size: Optional[int] = None


class PcapSessionCreate(PcapSessionBase):
    """Schema for creating a PCAP session"""
    uploaded_by: Optional[int] = None


class PcapSessionUpdate(BaseModel):
    """Schema for updating a PCAP session"""
    status: str
    packet_count: Optional[int] = None
    flow_count: Optional[int] = None
    alert_count: Optional[int] = None
    analysis_report: Optional[Dict[str, Any]] = None
    processed_at: Optional[datetime] = None


class PcapSessionInDBBase(PcapSessionBase):
    """Base schema for PCAP session in database"""
    id: int
    session_uuid: str
    uploaded_by: Optional[int]
    uploaded_at: datetime
    status: Optional[str]
    packet_count: Optional[int]
    flow_count: Optional[int]
    alert_count: Optional[int]
    analysis_report: Optional[Dict[str, Any]]
    processed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class PcapSession(PcapSessionInDBBase):
    """Schema for PCAP session response"""
    pass


class PcapAnalysisReport(BaseModel):
    """PCAP analysis report schema"""
    session_uuid: str
    filename: str
    packet_count: int
    flow_count: int
    alert_count: int
    duration_seconds: float
    protocols: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    summary: str
```

---

## 📁 File 30: `backend/app/schemas/audit.py`

```
Python
```

```
"""
Pydantic schemas for Audit Log
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class AuditLogBase(BaseModel):
    """Base audit log schema"""
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    success: bool = True


class AuditLogCreate(AuditLogBase):
    """Schema for creating an audit log"""
    user_id: Optional[int] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogInDBBase(AuditLogBase):
    """Base schema for audit log in database"""
    id: int
    user_id: Optional[int]
    username: Optional[str]
    ip_address: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True


class AuditLog(AuditLogInDBBase):
    """Schema for audit log response"""
    pass
```

---

## 📁 File 31: `backend/alembic.ini`

```
ini
```

```
# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration files
file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
timezone = UTC

# max length of characters to apply to the
# "slug" field
truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
sourceless = false

# version location specification; This defaults
# to alembic/versions.  When using multiple version
# directories, initial revisions must be specified with --version-path.
version_locations = %(here)s/alembic/versions

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses os.pathsep.
# If this key is omitted entirely, it falls back to the legacy behavior of splitting on spaces and/or commas.
version_path_separator = os  # Use os.pathsep. Default configuration used for new projects.

# the output encoding used when revision files
# are written from script.py.mako
output_encoding = utf-8

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

---

## 📁 File 32: `backend/alembic/env.py`

```
Python
```

```
"""
Alembic environment configuration
"""
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from app.core.config import settings
from app.db.base import Base

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set database URL from settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

---

## 📁 File 33: `backend/alembic/script.py.mako`

```
Python
```

```
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
```

---

## 📁 File 34: `backend/app/api/deps.py`

```
Python
```

```
"""
API dependencies
"""
from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User
from app.schemas.token import TokenPayload

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login"
)


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    Get current authenticated user
    
    Args:
        db: Database session
        token: JWT token
        
    Returns:
        Current user
        
    Raises:
        HTTPException: If authentication fails
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = decode_token(token)
        user_id: int = payload.get("sub")
        token_type: str = payload.get("type")
        
        if user_id is None or token_type != "access":
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current active user
    
    Args:
        current_user: Current user from token
        
    Returns:
        Current active user
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def require_role(allowed_roles: list):
    """
    Dependency factory for role-based access control
    
    Args:
        allowed_roles: List of allowed roles
        
    Returns:
        Dependency function
    """
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(allowed_roles)}"
            )
        return current_user
    
    return role_checker


# Common role dependencies
require_admin = require_role(["admin"])
require_analyst = require_role(["admin", "analyst"])
require_viewer = require_role(["admin", "analyst", "viewer"])
```

---

## 📁 File 35: `backend/app/api/__init__.py`

```
Python
```

```
"""
API module initialization
"""
```

---

## 📁 File 36: `backend/app/api/auth.py`

```
Python
```

```
"""
Authentication endpoints
"""
from datetime import datetime, timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.core.config import settings
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_password_strength
)
from app.models.user import User
from app.schemas.token import Token, RefreshToken
from app.schemas.user import User as UserSchema, UserCreate
from app.services.audit_service import create_audit_log

router = APIRouter()


@router.post("/register", response_model=UserSchema)
def register(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate
) -> Any:
    """
    Register a new user
    
    Note: In production, this should be restricted or require admin approval
    """
    # Check if username exists
    user = db.query(User).filter(User.username == user_in.username).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email exists
    user = db.query(User).filter(User.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate password strength
    try:
        validate_password_strength(user_in.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    # Create user
    user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=True
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Audit log
    create_audit_log(
        db=db,
        action="user_registered",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username, "role": user.role},
        success=True
    )
    
    return user


@router.post("/login", response_model=Token)
def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login
    """
    # Authenticate user
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        # Audit failed login
        create_audit_log(
            db=db,
            username=form_data.username,
            action="login_failed",
            resource_type="auth",
            details={"reason": "invalid_credentials"},
            success=False
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        create_audit_log(
            db=db,
            user_id=user.id,
            username=user.username,
            action="login_failed",
            resource_type="auth",
            details={"reason": "inactive_user"},
            success=False
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create tokens
    access_token = create_access_token(data={"sub": user.id})
    refresh_token = create_refresh_token(data={"sub": user.id})
    
    # Audit successful login
    create_audit_log(
        db=db,
        user_id=user.id,
        username=user.username,
        action="login_success",
        resource_type="auth",
        details={"role": user.role},
        success=True
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh", response_model=Token)
def refresh_token(
    *,
    db: Session = Depends(get_db),
    token_data: RefreshToken
) -> Any:
    """
    Refresh access token using refresh token
    """
    try:
        payload = decode_token(token_data.refresh_token)
        user_id: int = payload.get("sub")
        token_type: str = payload.get("type")
        
        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new tokens
        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


@router.get("/me", response_model=UserSchema)
def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user information
    """
    return current_user


@router.post("/logout")
def logout(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Logout current user
    
    Note: With JWT, actual logout requires token blacklisting (not implemented here)
    This endpoint is mainly for audit logging
    """
    create_audit_log(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action="logout",
        resource_type="auth",
        success=True
    )
    
    return {"message": "Successfully logged out"}
```

---

## 📁 File 37: `backend/app/services/audit_service.py`

```
Python
```

```
"""
Audit log service
"""
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True
) -> AuditLog:
    """
    Create an audit log entry
    
    Args:
        db: Database session
        action: Action performed
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        details: Additional details
        user_id: User ID who performed the action
        username: Username who performed the action
        ip_address: IP address of the user
        success: Whether the action was successful
        
    Returns:
        Created audit log entry
    """
    audit_log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        timestamp=datetime.utcnow(),
        success=success
    )
    
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    
    return audit_log
```

---

## 📁 File 38: `backend/app/main.py`

```
Python
```

```
"""
Main FastAPI application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api import auth

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    """
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Network Intrusion Detection System",
    lifespan=lifespan,
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_PREFIX}/auth",
    tags=["Authentication"]
)


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
```

---

## 📁 File 39: `backend/scripts/init_db.py`

```
Python
```

```
"""
Initialize database with tables and initial data
"""
import sys
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.session import engine
from app.db.base import Base
from app.core.logging import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


def init_db():
    """Initialize database tables"""
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully!")


if __name__ == "__main__":
    init_db()
```

---

## 📁 File 40: `backend/scripts/create_admin.py`

```
Python
```

```
"""
Create admin user
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash
from app.core.config import settings
from app.core.logging import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


def create_admin_user():
    """Create admin user from settings"""
    db = SessionLocal()
    
    try:
        # Check if admin exists
        admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        
        if admin:
            logger.warning(f"Admin user '{settings.ADMIN_USERNAME}' already exists")
            return
        
        # Create admin user
        admin = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            password_hash=get_password_hash(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True
        )
        
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        logger.info(f"Admin user created successfully!")
        logger.info(f"Username: {admin.username}")
        logger.info(f"Email: {admin.email}")
        logger.warning(f"Please change the default password immediately!")
        
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    create_admin_user()
```

---

## 📁 File 41: `Makefile`

```
Makefile
```

```
.PHONY: help install migrate admin dev test clean

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make migrate    - Run database migrations"
	@echo "  make admin      - Create admin user"
	@echo "  make dev        - Run development server"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean temporary files"

install:
	cd backend && pip install -r requirements.txt

install-dev:
	cd backend && pip install -r requirements-dev.txt

migrate:
	cd backend && alembic upgrade head

init-db:
	cd backend && python scripts/init_db.py

admin:
	cd backend && python scripts/create_admin.py

dev:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	cd backend && pytest

test-coverage:
	cd backend && pytest --cov=app --cov-report=html

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf backend/htmlcov
```

---

## 📁 File 42: `README.md` (Initial Version)

```
Markdown
```

```
# Advanced Network Intrusion Detection System (IDS)

A production-grade, real-time network intrusion detection and monitoring system built for SOC environments.

## 🚀 Features

- **Real-time Packet Capture** - Scapy-based network traffic analysis
- **Flow-Based Tracking** - 5-tuple flow aggregation and statistics
- **Detection Engine** - Rule-based threat detection with configurable thresholds
- **Event Correlation** - Multi-event incident creation and attack chain detection
- **Risk Scoring** - Transparent, explainable risk calculation
- **MITRE ATT&CK Mapping** - Technique identification and mapping
- **Alert Management** - Complete alert lifecycle with analyst workflow
- **PCAP Analysis** - Upload and analyze capture files offline
- **SOC Dashboard** - Real-time monitoring with WebSocket updates
- **Role-Based Access Control** - Admin, Analyst, and Viewer roles
- **Audit Logging** - Complete security event audit trail
- **Report Generation** - PDF, CSV, and JSON export

## 🏗️ Architecture

```

Network → Capture Engine → Parser → Flow Tracker
↓
Detection Engine → Correlation → Risk Scoring
↓
Alert Manager → Database → API → Dashboard

```
text
```

````

## 🛠️ Technology Stack

**Backend:**
- Python 3.11+
- FastAPI
- SQLAlchemy + PostgreSQL
- Scapy
- Redis

**Frontend:**
- React + TypeScript
- Tailwind CSS
- Recharts
- WebSocket

## 📦 Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Node.js 18+ (for frontend)

### Backend Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/advanced-ids.git
cd advanced-ids
````

2. Create virtual environment:

```
Bash
```

```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```
Bash
```

```
make install
```

4. Configure environment:

```
Bash
```

```
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize database:

```
Bash
```

```
make init-db
make migrate
make admin
```

6. Run development server:

```
Bash
```

```
make dev
```

The API will be available at **`http://localhost:8000`**

API Documentation: **`http://localhost:8000/api/v1/docs`**

## 📝 Current Progress

### ✅ Phase 2 Complete: Backend Core

-  Project structure
-  Configuration management
-  Security utilities (JWT, password hashing)
-  Logging system
-  Database models (SQLAlchemy)
-  Pydantic schemas
-  Database migrations (Alembic)
-  Authentication API
-  RBAC dependencies
-  Audit logging service
-  Initial scripts

### 🔄 Next: Phase 3 - Packet Capture Engine

Coming next: Network packet capture, parsing, and flow tracking.

## 🔐 Security

- Bcrypt password hashing
- JWT authentication
- Role-based access control
- Input validation
- Audit logging
- SQL injection prevention

## 📄 License

MIT License - See LICENSE file

## ⚠️ Disclaimer

This tool is for **authorized security testing and monitoring only**. Use only on networks you own or have explicit permission to monitor.

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📧 Contact

For questions or support, please open an issue.

```
text
```

````

---

## ✅ PHASE 2 COMPLETE

**Implemented:**
- ✅ Complete configuration management
- ✅ Security utilities (JWT, bcrypt, RBAC)
- ✅ Logging system
- ✅ All database models (12 models)
- ✅ All Pydantic schemas
- ✅ Alembic migration setup
- ✅ Authentication API endpoints
- ✅ API dependencies and RBAC
- ✅ Audit logging service
- ✅ Database initialization scripts
- ✅ Admin user creation
- ✅ Makefile for common tasks
- ✅ Initial README

**Testing Phase 2:**

```bash
# 1. Create .env file
cp .env.example .env

# 2. Install dependencies
make install

# 3. Initialize database
make init-db

# 4. Create admin user
make admin

# 5. Run server
make dev

# 6. Test authentication
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=ChangeThisPassword123!"
````