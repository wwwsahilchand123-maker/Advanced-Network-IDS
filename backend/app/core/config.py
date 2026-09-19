"""Application configuration with safe validation for deployments."""
from typing import List, Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Advanced IDS"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    API_V1_PREFIX: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5173",
    ]

    DATABASE_URL: str = "sqlite:///./ids.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "CHANGE_ME_IN_ENVIRONMENT"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@ids.example.com"
    ADMIN_PASSWORD: str = "CHANGE_ME_IN_ENVIRONMENT"

    DEFAULT_INTERFACE: str = ""
    CAPTURE_BUFFER_SIZE: int = 2048
    MAX_PACKET_RETENTION_HOURS: int = 24
    MAX_FLOW_RETENTION_DAYS: int = 7

    DETECTION_RULES_PATH: str = "./detection_rules"
    BASELINE_CALCULATION_INTERVAL: int = 3600
    CORRELATION_TIME_WINDOW: int = 300

    ALERT_RETENTION_DAYS: int = 90
    INCIDENT_RETENTION_DAYS: int = 365

    PCAP_UPLOAD_DIR: str = "./uploads/pcaps"
    MAX_PCAP_SIZE_MB: int = 500
    REPORTS_OUTPUT_DIR: str = "./reports"

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/ids.log"

    DEMO_MODE: bool = False
    DEMO_EVENT_INTERVAL: int = 5

    ENABLE_THREAT_INTEL: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_runtime_secrets(self):
        """Prevent placeholder credentials from being used outside local development."""
        if self.ENVIRONMENT.lower() != "development":
            if self.SECRET_KEY == "CHANGE_ME_IN_ENVIRONMENT":
                raise ValueError("SECRET_KEY must be set outside development")
            if self.ADMIN_PASSWORD == "CHANGE_ME_IN_ENVIRONMENT":
                raise ValueError("ADMIN_PASSWORD must be set outside development")
            if len(self.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must contain at least 32 characters")
        return self


settings = Settings()
