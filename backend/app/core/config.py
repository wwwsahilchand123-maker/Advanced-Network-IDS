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
        "http://localhost:3001",
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
    SECRET_KEY: str = "your-secret-key-change-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Admin User
    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@ids.example.com"
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
