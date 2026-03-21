"""
Centralized configuration for SecurityScarletAI.
All settings are validated at startup. Missing required values cause immediate failure
with a clear error message — not a silent None that blows up later.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Optional
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- Database ---
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "scarletai"
    db_user: str = "scarletai"
    db_password: str = Field(..., description="Database password — required, no default")
    db_pool_min: int = 2
    db_pool_max: int = 10

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def database_url_sync(self) -> str:
        """Sync URL for Alembic migrations."""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- API ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_secret_key: str = Field(..., min_length=32, description="JWT signing key — generate with: openssl rand -hex 64")
    api_bearer_token: str = Field(..., min_length=16, description="Ingestion API auth token")
    api_cors_origins: list[str] = ["http://localhost:8501"]

    # --- Ollama ---
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:8b"
    ollama_timeout: int = 30

    # --- osquery ---
    osquery_log_path: str = "/opt/homebrew/var/log/osquery/osqueryd.results.log"
    osquery_config_path: str = "/opt/homebrew/etc/osquery/osquery.conf"

    # --- Threat Intel ---
    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    # --- Notifications ---
    slack_webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    alert_email_to: Optional[str] = None

    # --- Logging ---
    log_level: str = "INFO"
    log_format: str = "json"  # "json" for production, "console" for dev

    @field_validator("db_password")
    @classmethod
    def password_not_default(cls, v: str) -> str:
        if "CHANGE_ME" in v:
            raise ValueError("You must set a real DB_PASSWORD in .env — do not use the placeholder")
        return v


# Singleton — import this everywhere
settings = Settings()
