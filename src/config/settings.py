"""
Centralized configuration for SecurityScarletAI.
All settings are validated at startup. Missing required values cause immediate failure
with a clear error message — not a silent None that blows up later.
"""
from typing import Optional
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
        # URL-encode user/password so special chars (e.g. '/' in the rotated
        # DB password) don't break the DSN. Callers that pass this to asyncpg
        # strip the "+asyncpg" driver suffix; raw asyncpg DSNs accept the
        # percent-encoded form. get_pool() uses keyword args instead, but any
        # DSN consumer (seeders, scripts) needs this to be safe.
        return (
            f"postgresql+asyncpg://{quote_plus(self.db_user)}:{quote_plus(self.db_password)}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- API ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_secret_key: SecretStr = Field(
        ..., min_length=32, description="JWT signing key — generate with: openssl rand -hex 64"
    )
    api_bearer_token: SecretStr = Field(..., min_length=16, description="Ingestion API auth token")
    # P2.6: optional SCOPED ingest token — viewer-class and valid ONLY on the
    # ingest router (a leaked ingest token must not be a full admin bearer).
    # Unset → behavior identical to pre-P2.6.
    ingest_bearer_token: Optional[SecretStr] = None
    api_cors_origins: list[str] = ["http://localhost:8501"]

    # --- Ollama ---
    ollama_base_url: str = "http://localhost:11434"
    # Default is the model actually installed in the reference deploy
    # (`mistral:7b`, verified 2026-08-26). Override per deployment.
    ollama_model: str = "mistral:7b"
    ollama_timeout: int = 30

    # --- OpenAPI docs exposure ---
    # When False, docs_url/redoc_url/openapi_url are all disabled so the
    # Swagger/ReDoc UI and the openapi.json schema are not served (prod).
    # Default True so dev/CI keeps the interactive docs. The prod overlay
    # sets DOCS_ENABLED=false.
    docs_enabled: bool = True

    # --- Bootstrap ---
    # POST /auth/seed-admin is a localhost-only dev bootstrap that creates an
    # admin with the known weak password "admin" (must_change_password=true).
    # It must NOT be reachable in prod -- the Docker entrypoint is the prod
    # bootstrap (random password written to data/admin_initial_password, not
    # a second weak-password path). Default false; enable explicitly for dev.
    seed_admin_enabled: bool = False

    # --- osquery ---
    osquery_log_path: str = "/opt/homebrew/var/log/osquery/osqueryd.results.log"
    osquery_config_path: str = "/opt/homebrew/etc/osquery/osquery.conf"
    # Start the osquery FileShipper (tails osquery_log_path) on API startup.
    # OFF by default so existing deployments and CI are unaffected; enable in
    # .env to wire the real telemetry pipe (see scripts/run_osquery_demo.sh).
    enable_ingestion_shipper: bool = False

    # --- Threat Intel ---
    # When False, the threat-intel refresh scheduler is NOT started and no
    # external feed calls are made (URLhaus/AbuseIPDB/OTX). IOC enrichment
    # still matches against the local threat_intel cache (pre-load IOCs
    # offline before going dark). Set THREAT_INTEL_ENABLED=false for
    # air-gapped / no-egress deployments (see docs/AIR-GAPPED.md).
    threat_intel_enabled: bool = True
    abuseipdb_api_key: Optional[str] = None
    # P2.5: per-feed hourly live-call budget for AbuseIPDB (quota protection).
    # A hostile agent spraying fresh IPs burned the DAILY quota on clean lookups
    # before this — the negative cache + budget cap the live-call rate.
    abuseipdb_hourly_budget: int = 500
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

    # --- JWT lifetimes (Epic 5) ---
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7

    # --- Rate limits (slowapi limit strings; env-configurable so the login
    # brute-force limit can be relaxed for interactive/demo use without a
    # code change. Defaults stay aggressive for production.) ---
    login_rate_limit: str = "5/minute"
    ingest_rate_limit: str = "100/minute"
    # Per-user LLM quota (F-14): /ai/* + /query + hunt execute. One analyst
    # can otherwise pin the single local model (OWASP LLM10 unbounded
    # consumption). limits-grammar string; 30 per 5 minutes per user.
    llm_rate_limit: str = "30/5minutes"

    # --- Retention (P1-D). 0 = keep forever (the pre-retention behaviour).
    # Defaults are conservative hot-retention windows; tune per deployment.
    # The retention job runs hourly and deletes rows older than the window in
    # batched parameterized DELETEs (no table-wide lock). ---
    logs_retention_days: int = 30
    alerts_retention_days: int = 180
    audit_retention_days: int = 365
    correlation_retention_days: int = 90
    ai_usage_retention_days: int = 90
    retention_interval_hours: int = 1
    retention_batch_size: int = 5000

    # --- Password pepper (optional, P2-9) ---
    # A server-side secret mixed into the password hash BEFORE the SHA-256
    # pre-hash + bcrypt. A pepper protects against DB-only leaks: an attacker
    # who steals the siem_users table but NOT this secret cannot offline-crack
    # the hashes. It does NOT protect against an attacker who has both DB + env.
    # Backward compat: when unset, hash_password/verify_password behave exactly
    # as before (no pepper), so existing hashes keep validating. Rotating the
    # pepper requires rehashing all passwords (password reset flow).
    password_pepper: Optional[SecretStr] = None

    # --- Demo seed gate (Phase 1, 2026-09-01) ---
    # scripts/seed_demo_data.py previously ran unconditionally from the Docker
    # entrypoint on any first boot (empty alerts table), seeding synthetic
    # alerts AND the publicly documented demo credential
    # (demo_analyst / demo_analyst_2026) into production deployments. Demo
    # seeding now requires DEMO_SEED_ENABLED=true (demo hosts opt in;
    # production boots stay empty). See docs/DEMO.md.
    demo_seed_enabled: bool = False

    @field_validator("db_password")
    @classmethod
    def password_not_default(cls, v: str) -> str:
        if "CHANGE_ME" in v:
            raise ValueError("You must set a real DB_PASSWORD in .env — do not use the placeholder")
        return v

    # Phase 1.5 (trust & truth), 2026-09-01: all three required secrets are
    # placeholder-gated — a deployment booting with a documented placeholder
    # crashes at startup instead of running on a public secret.
    @field_validator("api_secret_key")
    @classmethod
    def api_secret_key_not_placeholder(cls, v: SecretStr) -> SecretStr:
        if "CHANGE_ME" in v.get_secret_value():
            raise ValueError(
                "You must set a real API_SECRET_KEY in .env — do not use the placeholder. "
                "Generate with: openssl rand -hex 64"
            )
        return v

    @field_validator("api_bearer_token")
    @classmethod
    def api_bearer_token_not_placeholder(cls, v: SecretStr) -> SecretStr:
        if "CHANGE_ME" in v.get_secret_value():
            raise ValueError(
                "You must set a real API_BEARER_TOKEN in .env — do not use the placeholder. "
                "Generate with: openssl rand -hex 32"
            )
        return v

    @field_validator("ingest_bearer_token")
    @classmethod
    def ingest_bearer_token_not_placeholder(cls, v: Optional[SecretStr]) -> Optional[SecretStr]:
        # Optional field — None (unset) disables the scoped token entirely.
        if v is not None and "CHANGE_ME" in v.get_secret_value():
            raise ValueError(
                "INGEST_BEARER_TOKEN is set to the placeholder — generate a real one "
                "with: openssl rand -hex 32 (or unset it to disable scoping)"
            )
        return v


# Singleton — import this everywhere
settings = Settings()
