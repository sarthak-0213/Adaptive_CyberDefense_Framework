import os
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Adaptive Cyber Defense Framework"
    API_V1_STR: str = "/api/v1"
    
    # Database
    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "cyberdefense"
    DATABASE_URL: str = "postgresql://postgres:postgres@db:5432/cyberdefense"
    REDIS_URL: str = ""

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str, info) -> str:
        # Check environment variable directly first
        env_url = os.environ.get("DATABASE_URL")
        if env_url:
            v = env_url.strip()

        # If DATABASE_URL is set, normalize legacy Render/Heroku 'postgres://' scheme to 'postgresql://'
        if v and isinstance(v, str):
            v = v.strip()
            if v.startswith("postgres://"):
                v = v.replace("postgres://", "postgresql://", 1)
            if v != "postgresql://postgres:postgres@db:5432/cyberdefense":
                return v

        # Build URL dynamically from components
        data = info.data if hasattr(info, "data") else {}
        server = os.environ.get("POSTGRES_SERVER") or (data.get("POSTGRES_SERVER") if isinstance(data, dict) else None) or "db"
        user = os.environ.get("POSTGRES_USER") or (data.get("POSTGRES_USER") if isinstance(data, dict) else None) or "postgres"
        password = os.environ.get("POSTGRES_PASSWORD") or (data.get("POSTGRES_PASSWORD") if isinstance(data, dict) else None) or "postgres"
        db = os.environ.get("POSTGRES_DB") or (data.get("POSTGRES_DB") if isinstance(data, dict) else None) or "cyberdefense"

        return f"postgresql://{user}:{password}@{server}:5432/{db}"

    # JWT Settings
    JWT_SECRET_KEY: str = "supersecretaccesskeyplaceholder_please_change_in_production"
    JWT_REFRESH_SECRET_KEY: str = "supersecretrefreshkeyplaceholder_please_change_in_production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    # Moving Target Defense (MTD) Settings
    MTD_ENABLED: bool = True
    MTD_ROTATION_INTERVAL_SECONDS: int = 60
    MTD_DECOY_PATHS: List[str] = [
        "/api/v1/admin/debug",
        "/api/v1/system/env",
        "/api/v1/auth/keys",
        "/api/v1/database/export",
        "/api/v1/config/credentials",
        "/api/v1/admin/backup",
        "/api/v1/phpinfo.php",
        "/api/v1/wp-admin",
        "/api/v1/.env",
        "/api/v1/ssh_keys"
    ]
    MTD_SEED: str = "adaptive-defense-framework-seed"
    MTD_ROTATION_HISTORY_LIMIT: int = 10
    UPLOAD_DIR: str = "uploads"

    # Threat Mitigation Settings
    THREAT_DETECTION_WINDOW_SECONDS: int = 10
    THREAT_HONEYPOT_THRESHOLD: int = 3
    THREAT_BLOCK_DURATION_SECONDS: int = 600

    # Notification & Alerting Settings
    ALERT_DISPATCH_ENABLED: bool = True
    ALERT_COOLDOWN_SECONDS: int = 300
    ALERT_EMAIL_ENABLED: bool = False
    ALERT_EMAIL_SMTP_HOST: str = "smtp.example.com"
    ALERT_EMAIL_SMTP_PORT: int = 587
    ALERT_EMAIL_SMTP_USER: str = ""
    ALERT_EMAIL_SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "alerts@cyberdefense.local"
    ALERT_EMAIL_TO: str = "admin@cyberdefense.local"
    ALERT_SLACK_ENABLED: bool = False
    ALERT_SLACK_WEBHOOK_URL: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
