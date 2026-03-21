# SecurityScarletAI — AI-Native SIEM
## Corrected & Hardened Execution Plan v2.0

**Project:** SecurityScarletAI — Custom AI-Native SIEM  
**Platform:** macOS ARM64 (Apple Silicon — M1/M2/M3/M4)  
**Stack:** Python 3.11+, PostgreSQL 16 + TimescaleDB, FastAPI, osquery, scikit-learn, Ollama  
**Created:** March 21, 2026  
**Revised By:** Security Engineering Review  
**Estimated Real Time:** 6–10 weeks (part-time student pace)  
**Phases:** Foundation → Ingestion → Detection → Dashboard → AI-Native → Hardening & Docs

---

## REVIEW SUMMARY — WHAT WAS GOOD, WHAT WAS WRONG, WHAT WAS MISSING

### ✅ What the Original Plan Did Well
- **Phased approach** — Building incrementally from ingestion to detection to AI is the correct order. Never skip the boring plumbing.
- **ECS normalization** — Adopting Elastic Common Schema for field naming is industry-standard and makes everything downstream (rules, correlation, dashboards) dramatically easier.
- **Sigma rules** — Using the open Sigma standard instead of inventing a proprietary detection format is the right call. It's portable and community-backed.
- **TimescaleDB** — Good choice for time-series log data. Regular PostgreSQL chokes on time-range queries at scale; hypertables solve this.
- **MITRE ATT&CK mapping** — Every detection rule must map to a technique. This was correctly included from the start.
- **Commit discipline** — Conventional commits with scoped messages (`feat(detection):`, `test:`, etc.) show professional habits. Keep this.
- **Integration tests per phase** — Testing at phase boundaries catches integration rot early.

### ❌ What Was Wrong
1. **Time estimates are dangerously unrealistic.** A Sigma-to-SQL compiler is not a 5-minute task. A UEBA behavioral baseline is not a 5-minute task. These estimates will frustrate you and mislead any agent executing the plan. The original plan claims ~4.5 hours total — this is a 6–10 week project minimum. Every chunk has been re-estimated below with honest times.
2. **Project location `~/Desktop/`** — Never put a git repo on your Desktop. Use `~/projects/` or `~/dev/`. Desktop syncing (iCloud) will corrupt `.git` internals.
3. **osquery paths are wrong for ARM Mac.** The plan uses `/usr/local/etc/osquery/` which is the Intel Homebrew prefix. On Apple Silicon, Homebrew installs to `/opt/homebrew/`. The plan also ignores macOS-specific permission requirements (Full Disk Access, TCC).
4. **Celery + Redis is overkill** for a single-machine local build. APScheduler is lighter, has no external dependency, and is more than sufficient for a learning project running on one Mac.
5. **MISP and OpenCTI are enterprise-grade stacks** that each require their own Docker infrastructure. For a local learning build, use free API-based threat intel feeds (AbuseIPDB, AlienVault OTX, URLhaus) that don't need separate servers.
6. **Prophet for time-series forecasting** is a heavy, Facebook-maintained dependency with installation issues on ARM. Use `statsmodels` (already in the scipy ecosystem) or simple z-score anomaly detection — both are more debuggable and teach you more.
7. **Feature Store and A/B Testing (Chunks 4.17, 4.18)** — These are MLOps patterns for production teams with hundreds of models. They add complexity with zero learning value at this stage. Removed.
8. **Raw SQL in the threat hunting UI** — Your own SIEM has a SQL injection surface. The original plan gives analysts a raw SQL editor pointed at the production database. This must be parameterized or sandboxed.

### 🔴 What Was Completely Missing
1. **Security of the SIEM itself.** The plan builds a security tool with almost no self-security: no TLS, no input sanitization on log ingestion (log injection attacks), no RBAC, no secrets management beyond `.env`, no CSRF/XSS protection. An insecure SIEM is worse than no SIEM.
2. **macOS permissions model.** osquery on macOS requires Full Disk Access (FDA) and TCC entitlements. Without these, half your queries return empty results and you'll waste hours debugging.
3. **Self-observability.** Who watches the watchers? The SIEM needs structured logging of its own operations, health check endpoints, and a way to know if ingestion has stopped.
4. **Data retention and compression.** TimescaleDB's killer feature is compression policies and automated retention. The plan creates hypertables but never configures them. Without this, your disk fills up.
5. **Test data generation.** You cannot test a SIEM without attack simulation data. The plan has no strategy for generating malicious-looking events. Atomic Red Team and custom scripts are needed.
6. **Log enrichment.** Raw logs are barely useful. GeoIP lookups, DNS resolution, and user-agent parsing turn raw events into actionable intelligence.
7. **Graceful degradation.** What happens when Ollama is slow or down? When the DB is full? When osquery crashes? Every external dependency needs a failure mode.
8. **`.env` template** with all required variables documented. The plan mentions `.env.example` but never defines what goes in it.
9. **Database migrations strategy.** The plan mentions Alembic but never sets it up. Schema changes without migrations corrupt data.
10. **Backup and recovery.** A single `pg_dump` cron job. Without it, a bad migration or disk failure destroys everything.

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SecurityScarletAI                            │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  osquery  │───▶│  Log Shipper │───▶│  Normalizer  │              │
│  │  (agent)  │    │  (file tail) │    │  (ECS map)   │              │
│  └──────────┘    └──────────────┘    └──────┬───────┘              │
│                                             │                       │
│  ┌──────────┐    ┌──────────────┐           ▼                      │
│  │ External  │───▶│  HTTP Ingest │───▶┌───────────┐                │
│  │  Sources  │    │  (FastAPI)   │    │ Enrichment │                │
│  └──────────┘    └──────────────┘    │  Pipeline  │                │
│                                      └─────┬─────┘                 │
│                                            │                        │
│                    ┌───────────────────────▼──────────────┐         │
│                    │     PostgreSQL + TimescaleDB          │         │
│                    │  ┌──────┐ ┌────────┐ ┌───────┐      │         │
│                    │  │ logs │ │ alerts │ │ cases │ ...   │         │
│                    │  └──────┘ └────────┘ └───────┘      │         │
│                    └───────────────┬──────────────────────┘         │
│                                   │                                 │
│               ┌───────────────────┼───────────────────┐            │
│               ▼                   ▼                   ▼            │
│  ┌────────────────┐  ┌──────────────────┐  ┌────────────────┐     │
│  │ Detection Eng.  │  │   AI / ML Layer  │  │   Dashboard    │     │
│  │ - Sigma Rules   │  │ - Ollama (LLM)   │  │ - Streamlit    │     │
│  │ - Correlation   │  │ - UEBA (sklearn) │  │ - WebSocket    │     │
│  │ - Scheduler     │  │ - NL→SQL         │  │ - Auth (RBAC)  │     │
│  └────────┬───────┘  └────────┬─────────┘  └────────────────┘     │
│           │                   │                                     │
│           ▼                   ▼                                     │
│  ┌──────────────────────────────────┐                              │
│  │        Response / SOAR Lite      │                              │
│  │  - Slack webhook  - pf firewall  │                              │
│  │  - Email alert    - Case mgmt    │                              │
│  └──────────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## PREREQUISITES — DO THESE BEFORE CHUNK 0.1

These are not chunks. These are one-time system-level installs your agent should verify, not blindly re-run.

### Install Homebrew (if not present)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Install System Dependencies
```bash
# Core tools
brew install python@3.11 git postgresql@16 redis osquery ollama

# TimescaleDB (tap + install)
brew tap timescale/tap
brew install timescaledb

# Run TimescaleDB tuning (sets shared_preload_libraries in postgresql.conf)
timescaledb-tune --quiet --yes

# Poetry (Python package manager)
curl -sSL https://install.python-poetry.org | python3 -
```

### Grant osquery Full Disk Access (CRITICAL for macOS)
> **Why:** macOS TCC (Transparency, Consent, and Control) blocks osquery from reading process lists, file events, and user data without explicit permission. Without FDA, most of your queries return empty results.

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click the lock icon, authenticate
3. Click `+`, navigate to `/opt/homebrew/bin/osqueryd` and add it
4. Also add `/opt/homebrew/bin/osqueryi` for interactive queries
5. Restart osquery after granting

### Pull an Ollama Model
```bash
ollama pull llama3.2:8b
# Verify
ollama run llama3.2:8b "Say hello"
```
> **Note:** The original plan specified `qwen2.5-coder:7b`. That model is optimized for code generation, not security analysis or natural language reasoning. Use `llama3.2:8b` (or `mistral:7b`) for better NL→SQL and alert explanation quality. You can always swap later.

### Start Services
```bash
# Start PostgreSQL
brew services start postgresql@16

# Start Redis
brew services start redis

# Start Ollama server (runs in background)
ollama serve &
```

### Verify Everything Works
```bash
# PostgreSQL
psql postgres -c "SELECT version();"

# TimescaleDB
psql postgres -c "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';"

# Redis
redis-cli ping  # Should return PONG

# osquery (with FDA granted)
osqueryi "SELECT pid, name, path FROM processes LIMIT 5;"

# Ollama
curl http://localhost:11434/api/tags  # Should list models

# Python
python3.11 --version
poetry --version
```

> **Agent instruction:** If any of the above verification commands fail, stop and fix it before proceeding. Do not continue to Phase 0 with broken prerequisites.

---

## PHASE 0: FOUNDATION

### Chunk 0.1: Project Structure & Repo Init
**Time estimate:** 5–10 minutes  
**Goal:** Create the full directory tree, initialize git, add .gitignore and a skeleton README.

**Why this structure matters:** Flat repos become unmaintainable fast. Separating `src/` by domain (ingestion, detection, ai, api, response) means your agent can work on detection without touching ingestion code. The `tests/` tree mirrors `src/` so you always know where the test for a module lives.

```bash
mkdir -p ~/projects/SecurityScarletAI/{src/{ingestion,detection,ai,api,db,response,intel,case,enrichment,config},tests/{unit,integration},docs,rules/sigma,dashboard/pages,scripts,data}

cd ~/projects/SecurityScarletAI
git init

# Create __init__.py files so Python treats directories as packages
find src -type d -exec touch {}/__init__.py \;
touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
```

**.gitignore** — This is more complete than the original. It covers Python, macOS, IDE, secrets, and data files:
```gitignore
# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
dist/
build/
.venv/
*.so

# Environment & Secrets — NEVER commit these
.env
.env.production
*.pem
*.key

# Data & Logs — too large for git, regenerable
data/
logs/
*.db
*.log

# macOS
.DS_Store
._*

# IDE
.vscode/
.idea/
*.swp
*.swo

# Docker volumes
pgdata/
redisdata/

# Model artifacts
models/
*.pkl
*.joblib
```

**.env.example** — Every environment variable your project needs, documented. Copy to `.env` and fill in real values. This was completely missing from the original plan:
```bash
# === Database ===
DB_HOST=localhost
DB_PORT=5432
DB_NAME=scarletai
DB_USER=scarletai
DB_PASSWORD=CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32
DB_POOL_MIN=2
DB_POOL_MAX=10

# === Redis ===
REDIS_URL=redis://localhost:6379/0

# === API ===
API_HOST=127.0.0.1
API_PORT=8000
API_SECRET_KEY=CHANGE_ME_GENERATE_WITH_openssl_rand_hex_64
API_BEARER_TOKEN=CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32
API_CORS_ORIGINS=["http://localhost:8501"]

# === Ollama ===
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:8b
OLLAMA_TIMEOUT=30

# === osquery ===
OSQUERY_LOG_PATH=/opt/homebrew/var/log/osquery/osqueryd.results.log
OSQUERY_CONFIG_PATH=/opt/homebrew/etc/osquery/osquery.conf

# === Threat Intel (free tier API keys) ===
ABUSEIPDB_API_KEY=
OTX_API_KEY=

# === Notifications (optional) ===
SLACK_WEBHOOK_URL=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ALERT_EMAIL_TO=

# === Logging ===
LOG_LEVEL=INFO
LOG_FORMAT=json
```

**Commit:** `chore: initialize project structure with security-conscious .gitignore and env template`

---

### Chunk 0.2: Python Environment & Dependencies
**Time estimate:** 10–15 minutes  
**Goal:** Set up Poetry, install all dependencies, verify imports.

**Key change from original:** Removed Celery and Redis as Python dependencies. Replaced with APScheduler (lighter, no external broker needed for single-machine). Added `httpx` for async HTTP calls, `bcrypt` for password hashing, `python-jose` for JWT tokens, `geoip2` for log enrichment.

```bash
cd ~/projects/SecurityScarletAI

# Initialize Poetry project
poetry init --name securityscarletai --python "^3.11" --no-interaction

# Core dependencies
poetry add \
  fastapi==0.115.* \
  uvicorn[standard] \
  asyncpg \
  sqlalchemy[asyncio]==2.0.* \
  alembic \
  pydantic==2.* \
  pydantic-settings \
  python-dotenv \
  httpx \
  websockets \
  apscheduler==3.10.* \
  pandas \
  numpy \
  scikit-learn \
  joblib \
  streamlit==1.* \
  watchfiles \
  bcrypt \
  python-jose[cryptography] \
  passlib[bcrypt] \
  geoip2 \
  pyyaml \
  structlog \
  rich

# Dev dependencies
poetry add --group dev \
  pytest \
  pytest-asyncio \
  pytest-cov \
  black \
  ruff \
  mypy \
  httpx  # for TestClient

# Verify
poetry run python -c "import fastapi, asyncpg, pandas, sklearn, structlog; print('All imports OK')"
```

**pyproject.toml additions** — Add these tool configs for code quality:
```toml
[tool.black]
line-length = 100
target-version = ["py311"]

[tool.ruff]
line-length = 100
select = ["E", "F", "W", "I", "S", "B"]
# S = bandit security checks — important for a security project

[tool.mypy]
python_version = "3.11"
strict = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

> **Agent note:** If `asyncpg` fails to install, you may need `brew install libpq` and set `LDFLAGS`/`CPPFLAGS`. This is a common ARM Mac issue.

**Commit:** `chore: configure Poetry with security-aware dependencies and linting`

---

### Chunk 0.3: Configuration Module
**Time estimate:** 15–20 minutes  
**Goal:** Centralized, validated configuration using Pydantic Settings. Every other module imports from here — never reads `.env` directly.

**Why this was missing from the original plan:** Without a config module, every file does its own `os.getenv()` with no validation, no type safety, and inconsistent defaults. When Ollama is offline, you get a cryptic `None` error instead of a clear "OLLAMA_BASE_URL not configured" message.

**File: `src/config/settings.py`**
```python
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
```

**File: `src/config/__init__.py`**
```python
from src.config.settings import settings

__all__ = ["settings"]
```

**Test: `tests/unit/test_config.py`**
```python
import pytest
from unittest.mock import patch
import os


def test_settings_loads_from_env():
    """Settings should load and validate all required fields."""
    env = {
        "DB_PASSWORD": "test_password_not_default",
        "API_SECRET_KEY": "a" * 64,
        "API_BEARER_TOKEN": "b" * 32,
    }
    with patch.dict(os.environ, env, clear=False):
        from src.config.settings import Settings
        s = Settings()
        assert s.db_host == "localhost"
        assert s.db_password == "test_password_not_default"


def test_settings_rejects_placeholder_password():
    """Settings must reject the CHANGE_ME placeholder."""
    env = {
        "DB_PASSWORD": "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32",
        "API_SECRET_KEY": "a" * 64,
        "API_BEARER_TOKEN": "b" * 32,
    }
    with patch.dict(os.environ, env, clear=False):
        from src.config.settings import Settings
        with pytest.raises(ValueError, match="must set a real DB_PASSWORD"):
            Settings()
```

**Commit:** `feat(config): add validated Pydantic settings with security checks`

---

### Chunk 0.4: Database Schema & Migrations
**Time estimate:** 30–45 minutes  
**Goal:** Create the PostgreSQL database, enable TimescaleDB, define all tables, set up Alembic for migrations, configure retention and compression.

**Key changes from original:**
- Added `JSONB` for flexible fields (not just `text`)
- Added indexes on frequently queried columns
- Added TimescaleDB compression policy (saves 90%+ disk)
- Added retention policy (auto-drop old data)
- Added `siem_health` table for self-observability
- Severity is an enum, not a magic integer

**Step 1: Create the database and user**
```bash
psql postgres <<'SQL'
CREATE USER scarletai WITH PASSWORD 'YOUR_SECURE_PASSWORD_HERE';
CREATE DATABASE scarletai OWNER scarletai;
\c scarletai
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- for fast text search
GRANT ALL PRIVILEGES ON DATABASE scarletai TO scarletai;
SQL
```

**Step 2: Schema file — `src/db/schema.sql`**
```sql
-- ============================================================
-- SecurityScarletAI Database Schema
-- PostgreSQL 16 + TimescaleDB
-- ============================================================

-- Severity enum — never use magic integers
CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE alert_status AS ENUM ('new', 'investigating', 'resolved', 'false_positive', 'closed');
CREATE TYPE case_status AS ENUM ('open', 'in_progress', 'resolved', 'closed');

-- ============================================================
-- LOGS — the core hypertable. Partitioned by time automatically.
-- ============================================================
CREATE TABLE IF NOT EXISTS logs (
    time           TIMESTAMPTZ NOT NULL,
    host_name      TEXT NOT NULL,
    host_ip        INET,
    source         TEXT NOT NULL,           -- 'osquery', 'api', 'syslog', etc.
    event_category TEXT NOT NULL,           -- ECS: 'process', 'network', 'file', 'authentication'
    event_type     TEXT NOT NULL,           -- ECS: 'start', 'end', 'connection', 'creation'
    event_action   TEXT,                    -- ECS: specific action like 'process_started'
    user_name      TEXT,
    process_name   TEXT,
    process_pid    INTEGER,
    source_ip      INET,
    destination_ip INET,
    destination_port INTEGER,
    file_path      TEXT,
    file_hash      TEXT,
    raw_data       JSONB NOT NULL,          -- original event, unmodified
    normalized     JSONB NOT NULL,          -- ECS-mapped fields
    enrichment     JSONB DEFAULT '{}'::jsonb, -- GeoIP, DNS, threat intel hits
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Convert to hypertable (TimescaleDB) — partitions by 1 day
SELECT create_hypertable('logs', 'time', chunk_time_interval => INTERVAL '1 day');

-- Indexes for common query patterns
CREATE INDEX idx_logs_host ON logs (host_name, time DESC);
CREATE INDEX idx_logs_category ON logs (event_category, time DESC);
CREATE INDEX idx_logs_user ON logs (user_name, time DESC) WHERE user_name IS NOT NULL;
CREATE INDEX idx_logs_source_ip ON logs (source_ip, time DESC) WHERE source_ip IS NOT NULL;
CREATE INDEX idx_logs_process ON logs (process_name, time DESC) WHERE process_name IS NOT NULL;
-- GIN index for JSONB full-text search on raw data
CREATE INDEX idx_logs_raw_gin ON logs USING GIN (raw_data jsonb_path_ops);

-- Compression policy: compress chunks older than 7 days (saves ~90% disk)
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'host_name, source',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('logs', INTERVAL '7 days');

-- Retention policy: drop data older than 90 days (adjust as needed)
SELECT add_retention_policy('logs', INTERVAL '90 days');


-- ============================================================
-- DETECTION RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT,
    sigma_yaml     TEXT NOT NULL,           -- raw Sigma rule YAML
    generated_sql  TEXT,                    -- compiled SQL query
    severity       alert_severity NOT NULL DEFAULT 'medium',
    mitre_tactics  TEXT[],                  -- e.g., ARRAY['TA0001', 'TA0002']
    mitre_techniques TEXT[],               -- e.g., ARRAY['T1059', 'T1078']
    enabled        BOOLEAN NOT NULL DEFAULT true,
    run_interval   INTERVAL NOT NULL DEFAULT '60 seconds',
    lookback       INTERVAL NOT NULL DEFAULT '5 minutes',
    threshold      INTEGER DEFAULT 1,      -- minimum matches to trigger
    last_run       TIMESTAMPTZ,
    last_match     TIMESTAMPTZ,
    match_count    BIGINT DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- ALERTS
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id             SERIAL PRIMARY KEY,
    time           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_id        INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    rule_name      TEXT NOT NULL,
    severity       alert_severity NOT NULL,
    status         alert_status NOT NULL DEFAULT 'new',
    host_name      TEXT NOT NULL,
    description    TEXT,
    mitre_tactics  TEXT[],
    mitre_techniques TEXT[],
    evidence       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of matching log excerpts
    ai_summary     TEXT,                    -- LLM-generated explanation (filled async)
    risk_score     FLOAT,
    assigned_to    TEXT,
    resolved_at    TIMESTAMPTZ,
    case_id        INTEGER,                -- FK added after cases table exists
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_status ON alerts (status, severity, time DESC);
CREATE INDEX idx_alerts_host ON alerts (host_name, time DESC);


-- ============================================================
-- ASSETS — discovered endpoints
-- ============================================================
CREATE TABLE IF NOT EXISTS assets (
    id             SERIAL PRIMARY KEY,
    hostname       TEXT NOT NULL UNIQUE,
    ip_addresses   INET[],
    os_type        TEXT,                    -- 'macOS', 'Linux', 'Windows'
    os_version     TEXT,
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score     FLOAT DEFAULT 0.0,
    alert_count    INTEGER DEFAULT 0,
    tags           TEXT[],
    metadata       JSONB DEFAULT '{}'::jsonb
);


-- ============================================================
-- CASES — group related alerts for investigation
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
    id             SERIAL PRIMARY KEY,
    title          TEXT NOT NULL,
    description    TEXT,
    status         case_status NOT NULL DEFAULT 'open',
    severity       alert_severity NOT NULL,
    assigned_to    TEXT,
    alert_ids      INTEGER[],
    notes          JSONB DEFAULT '[]'::jsonb,  -- array of {author, text, timestamp}
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add FK from alerts to cases
ALTER TABLE alerts ADD CONSTRAINT fk_alerts_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL;


-- ============================================================
-- USERS — SIEM operators (not endpoint users)
-- ============================================================
CREATE TABLE IF NOT EXISTS siem_users (
    id             SERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT UNIQUE,
    password_hash  TEXT NOT NULL,           -- bcrypt with 12 rounds minimum
    role           TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active      BOOLEAN NOT NULL DEFAULT true,
    last_login     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- THREAT INTEL — cached IOCs from external feeds
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_intel (
    id             SERIAL PRIMARY KEY,
    ioc_type       TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash_md5', 'hash_sha256', 'url')),
    ioc_value      TEXT NOT NULL,
    source         TEXT NOT NULL,           -- 'abuseipdb', 'otx', 'urlhaus'
    threat_type    TEXT,                    -- 'c2', 'malware', 'phishing', 'botnet'
    confidence     INTEGER CHECK (confidence BETWEEN 0 AND 100),
    first_seen     TIMESTAMPTZ,
    last_seen      TIMESTAMPTZ,
    metadata       JSONB DEFAULT '{}'::jsonb,
    fetched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value, source)
);

CREATE INDEX idx_threat_intel_lookup ON threat_intel (ioc_type, ioc_value);


-- ============================================================
-- SIEM HEALTH — self-observability (who watches the watchers?)
-- ============================================================
CREATE TABLE IF NOT EXISTS siem_health (
    time              TIMESTAMPTZ NOT NULL,
    component         TEXT NOT NULL,        -- 'shipper', 'detection', 'api', 'enrichment'
    status            TEXT NOT NULL,        -- 'healthy', 'degraded', 'down'
    events_per_second FLOAT,
    queue_depth       INTEGER,
    error_count       INTEGER DEFAULT 0,
    details           JSONB DEFAULT '{}'::jsonb
);

SELECT create_hypertable('siem_health', 'time', chunk_time_interval => INTERVAL '1 day');
SELECT add_retention_policy('siem_health', INTERVAL '30 days');
```

**Step 3: Set up Alembic for migrations**
```bash
cd ~/projects/SecurityScarletAI
poetry run alembic init src/db/migrations
```

Edit `src/db/migrations/env.py` to use your config's `database_url_sync`. Then:
```bash
# Generate initial migration from the schema
poetry run alembic revision --autogenerate -m "initial schema"
poetry run alembic upgrade head
```

> **Agent instruction:** After running the schema SQL, verify with:
> ```bash
> psql scarletai -c "\dt"  # Should list all tables
> psql scarletai -c "SELECT hypertable_name FROM timescaledb_information.hypertables;"  # Should show 'logs' and 'siem_health'
> ```

**Commit:** `feat(db): add full schema with TimescaleDB hypertables, compression, and retention`

---

### Chunk 0.5: Structured Logging for the SIEM Itself
**Time estimate:** 15–20 minutes  
**Goal:** Every component in SecurityScarletAI logs its own operations in structured JSON format using `structlog`. This is non-negotiable — you cannot debug a SIEM that has no logs of its own.

**File: `src/config/logging.py`**
```python
"""
Structured logging setup using structlog.
Every log line is JSON with: timestamp, level, component, message, and context.
This lets you grep/jq your own SIEM's logs when something breaks.
"""
import structlog
import logging
import sys
from src.config.settings import settings


def setup_logging() -> None:
    """Call once at startup (main.py, shipper.py, etc.)."""
    
    # Choose renderer based on environment
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(component: str) -> structlog.BoundLogger:
    """Get a logger bound to a specific component name.
    
    Usage:
        log = get_logger("shipper")
        log.info("started tailing", path="/var/log/osquery/results.log")
        log.error("parse failed", raw_line=line, error=str(e))
    """
    return structlog.get_logger(component=component)
```

**Usage pattern (every module should follow this):**
```python
from src.config.logging import get_logger

log = get_logger("detection.scheduler")

log.info("rule_executed", rule_name="brute_force_ssh", matches=3, duration_ms=45)
log.warning("rule_slow", rule_name="port_scan", duration_ms=2300, threshold_ms=1000)
log.error("rule_failed", rule_name="file_integrity", error="SQL syntax error", sql=generated_sql)
```

**Commit:** `feat(config): add structlog-based structured logging for all components`

---

### Chunk 0.6: Docker Compose (Optional Path)
**Time estimate:** 10–15 minutes  
**Goal:** Docker Compose as an *alternative* to Homebrew-managed services. Not required — you already installed PostgreSQL and Redis via brew. Use this if you prefer containers or want a clean teardown.

**Key changes from original:**
- Uses ARM64-native images (`arm64v8/` or multi-arch)
- Adds health checks so `docker compose up` waits for services to be ready
- Mounts `schema.sql` for auto-initialization
- Does NOT containerize the Python app (you're developing it — run it locally)

**File: `docker-compose.yml`**
```yaml
version: "3.9"

services:
  postgres:
    image: timescale/timescaledb:latest-pg16
    platform: linux/arm64
    container_name: scarletai-db
    environment:
      POSTGRES_USER: scarletai
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: scarletai
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./src/db/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U scarletai -d scarletai"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis:
    image: redis:7-alpine
    platform: linux/arm64
    container_name: scarletai-redis
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  pgdata:
  redisdata:
```

> **Agent instruction:** If using Docker path, run `docker compose up -d` and wait for health checks to pass before proceeding. If using Homebrew path, skip this chunk entirely.

**Commit:** `chore: add Docker Compose for optional containerized services`

---

## PHASE 1: LOG INGESTION

### Chunk 1.1: osquery Configuration for macOS ARM64
**Time estimate:** 20–30 minutes  
**Goal:** Configure osquery with scheduled queries that generate meaningful security telemetry on macOS.

**Critical fix from original:** Paths updated from `/usr/local/` (Intel) to `/opt/homebrew/` (ARM). Added notes on TCC/FDA requirements per query. Added `file_events` with explicit FIM paths. Reduced `shell_history` frequency (it's expensive).

**File: `/opt/homebrew/etc/osquery/osquery.conf`**
```json
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/opt/homebrew/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "events_expiry": "3600",
    "database_path": "/opt/homebrew/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_file_events": "true",
    "disable_events": "false",
    "host_identifier": "hostname"
  },

  "schedule": {
    "processes": {
      "query": "SELECT pid, name, path, cmdline, uid, gid, parent, start_time, resident_size FROM processes;",
      "interval": 60,
      "description": "All running processes — detects new/suspicious process launches"
    },
    "listening_ports": {
      "query": "SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.address != '127.0.0.1';",
      "interval": 120,
      "description": "Network listeners excluding localhost — detects backdoors and C2 beacons"
    },
    "logged_in_users": {
      "query": "SELECT type, user, host, time, pid FROM logged_in_users;",
      "interval": 60,
      "description": "Active sessions — detects unauthorized access"
    },
    "open_sockets": {
      "query": "SELECT pid, remote_address, remote_port, local_address, local_port, protocol, p.name, p.path FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE remote_address != '' AND remote_address != '::' AND remote_address != '0.0.0.0';",
      "interval": 60,
      "description": "Active network connections — critical for C2 and exfil detection"
    },
    "shell_history": {
      "query": "SELECT username, command, history_file FROM shell_history WHERE command != '';",
      "interval": 600,
      "description": "Command history — detects post-exploitation activity. NOTE: 10min interval (expensive query)"
    },
    "crontab": {
      "query": "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
      "interval": 300,
      "description": "Scheduled tasks — persistence mechanism detection"
    },
    "startup_items": {
      "query": "SELECT name, path, source, status, username FROM startup_items;",
      "interval": 300,
      "description": "Login items and launch agents — persistence detection"
    },
    "launchd_entries": {
      "query": "SELECT name, label, program, program_arguments, run_at_load FROM launchd WHERE run_at_load = '1';",
      "interval": 300,
      "description": "LaunchDaemons/Agents set to auto-run — macOS persistence"
    },
    "browser_plugins": {
      "query": "SELECT * FROM browser_plugins;",
      "interval": 3600,
      "description": "Browser extensions — can be used for credential theft"
    },
    "disk_encryption": {
      "query": "SELECT * FROM disk_encryption WHERE encrypted = 1;",
      "interval": 3600,
      "description": "FileVault status — compliance check"
    },
    "sip_config": {
      "query": "SELECT * FROM sip_config;",
      "interval": 3600,
      "description": "System Integrity Protection — should always be enabled"
    },
    "user_ssh_keys": {
      "query": "SELECT uid, path, encrypted FROM user_ssh_keys;",
      "interval": 3600,
      "description": "SSH keys — monitors for unauthorized key creation"
    }
  },

  "file_paths": {
    "homes": [
      "/Users/%/Documents/%%",
      "/Users/%/Downloads/%%",
      "/Users/%/Desktop/%%",
      "/Users/%/.ssh/%%"
    ],
    "system_binaries": [
      "/usr/bin/%%",
      "/usr/local/bin/%%",
      "/opt/homebrew/bin/%%"
    ],
    "launch_agents": [
      "/Library/LaunchAgents/%%",
      "/Library/LaunchDaemons/%%",
      "/Users/%/Library/LaunchAgents/%%"
    ]
  },

  "file_accesses": ["homes", "system_binaries", "launch_agents"]
}
```

**Verify osquery config:**
```bash
# Check syntax
osqueryctl config-check --config_path /opt/homebrew/etc/osquery/osquery.conf

# Interactive test — run a query manually
osqueryi --config_path /opt/homebrew/etc/osquery/osquery.conf \
  "SELECT pid, name, path FROM processes WHERE name LIKE '%python%';"

# Start the daemon
sudo osqueryctl start --config_path /opt/homebrew/etc/osquery/osquery.conf

# Verify log output appears
ls -la /opt/homebrew/var/log/osquery/
tail -1 /opt/homebrew/var/log/osquery/osqueryd.results.log | python3 -m json.tool
```

> **Troubleshooting:** If queries return empty results, 99% of the time it's a TCC/FDA issue. Go back to the Prerequisites section and verify Full Disk Access is granted to `osqueryd`.

**Commit:** `feat(agent): configure osquery for macOS ARM64 with security-focused queries`

---

### Chunk 1.2: ECS Log Normalizer
**Time estimate:** 30–45 minutes  
**Goal:** Python module that takes raw osquery JSON output and normalizes it to Elastic Common Schema (ECS) field names. This is the universal translator — everything downstream speaks ECS.

**Why ECS?** It's an open standard. Sigma rules expect ECS fields. Dashboards expect ECS fields. If you later swap osquery for another agent, you only rewrite the normalizer, not the entire pipeline.

**File: `src/ingestion/schemas.py`**
```python
"""
ECS (Elastic Common Schema) field mappings for SecurityScarletAI.
Reference: https://www.elastic.co/guide/en/ecs/current/index.html

Each osquery table maps to an ECS event.category + event.type combination.
"""
from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


class NormalizedEvent(BaseModel):
    """A single security event normalized to ECS fields."""
    timestamp: datetime = Field(alias="@timestamp")
    
    # Host context
    host_name: str
    host_ip: Optional[str] = None
    
    # Event classification (ECS)
    event_category: str        # process, network, file, authentication, configuration
    event_type: str            # start, end, connection, creation, deletion, change, info
    event_action: Optional[str] = None  # specific action, e.g., "process_started"
    source: str                # osquery table name or ingestion source
    
    # Actor
    user_name: Optional[str] = None
    
    # Process context (when applicable)
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_cmdline: Optional[str] = None
    process_path: Optional[str] = None
    
    # Network context (when applicable)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    
    # File context (when applicable)
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Raw + enrichment
    raw_data: dict[str, Any]
    enrichment: dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True


# Mapping: osquery table name → ECS category + type
OSQUERY_ECS_MAP: dict[str, dict[str, str]] = {
    "processes":        {"event_category": "process",        "event_type": "info"},
    "process_events":   {"event_category": "process",        "event_type": "start"},
    "listening_ports":  {"event_category": "network",        "event_type": "connection"},
    "open_sockets":     {"event_category": "network",        "event_type": "connection"},
    "logged_in_users":  {"event_category": "authentication", "event_type": "start"},
    "file_events":      {"event_category": "file",           "event_type": "change"},
    "shell_history":    {"event_category": "process",        "event_type": "info"},
    "crontab":          {"event_category": "configuration",  "event_type": "info"},
    "startup_items":    {"event_category": "configuration",  "event_type": "info"},
    "launchd_entries":  {"event_category": "configuration",  "event_type": "info"},
    "user_ssh_keys":    {"event_category": "configuration",  "event_type": "info"},
    "sip_config":       {"event_category": "configuration",  "event_type": "info"},
}
```

**File: `src/ingestion/parser.py`**
```python
"""
Parses raw osquery result log lines into NormalizedEvent objects.

osquery result log format (one JSON object per line):
{
  "name": "processes",
  "hostIdentifier": "MacBook-Pro.local",
  "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
  "unixTime": 1774267200,
  "epoch": 0,
  "counter": 0,
  "numerics": false,
  "columns": { "pid": "123", "name": "python3", ... },
  "action": "added"
}
"""
import json
import socket
from datetime import datetime, timezone
from typing import Optional

from src.ingestion.schemas import NormalizedEvent, OSQUERY_ECS_MAP
from src.config.logging import get_logger

log = get_logger("ingestion.parser")


def parse_osquery_line(raw_line: str) -> Optional[NormalizedEvent]:
    """Parse a single line from osquery's result log.
    
    Returns None if the line is malformed or from an unmapped table.
    Never raises — log errors and move on. A stuck parser kills the pipeline.
    """
    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError as e:
        log.warning("json_parse_failed", error=str(e), line_preview=raw_line[:200])
        return None

    table_name = data.get("name", "")
    ecs_mapping = OSQUERY_ECS_MAP.get(table_name)
    
    if not ecs_mapping:
        log.debug("unmapped_table", table=table_name)
        return None

    columns = data.get("columns", {})
    
    # Parse timestamp — osquery provides both calendarTime and unixTime
    try:
        ts = datetime.fromtimestamp(int(data.get("unixTime", 0)), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        ts = datetime.now(tz=timezone.utc)

    return NormalizedEvent(
        **{
            "@timestamp": ts,
            "host_name": data.get("hostIdentifier", socket.gethostname()),
            "event_category": ecs_mapping["event_category"],
            "event_type": ecs_mapping["event_type"],
            "event_action": f"{table_name}_{data.get('action', 'info')}",
            "source": f"osquery:{table_name}",
            "user_name": columns.get("user") or columns.get("username") or columns.get("uid"),
            "process_name": columns.get("name"),
            "process_pid": _safe_int(columns.get("pid")),
            "process_cmdline": columns.get("cmdline"),
            "process_path": columns.get("path"),
            "source_ip": columns.get("local_address") or columns.get("address"),
            "destination_ip": columns.get("remote_address"),
            "destination_port": _safe_int(columns.get("remote_port") or columns.get("port")),
            "file_path": columns.get("path") if ecs_mapping["event_category"] == "file" else None,
            "file_hash": columns.get("sha256") or columns.get("md5"),
            "raw_data": data,
        }
    )


def _safe_int(val: Optional[str]) -> Optional[int]:
    """Convert string to int safely. osquery returns all values as strings."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
```

**Test: `tests/unit/test_parser.py`**
```python
import json
from src.ingestion.parser import parse_osquery_line


SAMPLE_PROCESS_LOG = json.dumps({
    "name": "processes",
    "hostIdentifier": "test-mac.local",
    "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
    "unixTime": 1774267200,
    "columns": {
        "pid": "1234",
        "name": "python3",
        "path": "/opt/homebrew/bin/python3",
        "cmdline": "python3 -m pytest",
        "uid": "501",
    },
    "action": "added"
})


def test_parse_process_event():
    event = parse_osquery_line(SAMPLE_PROCESS_LOG)
    assert event is not None
    assert event.host_name == "test-mac.local"
    assert event.event_category == "process"
    assert event.process_name == "python3"
    assert event.process_pid == 1234


def test_parse_invalid_json():
    event = parse_osquery_line("not json at all{{{")
    assert event is None


def test_parse_unknown_table():
    line = json.dumps({"name": "unknown_table_xyz", "columns": {}, "unixTime": 0})
    event = parse_osquery_line(line)
    assert event is None
```

**Commit:** `feat(ingestion): add ECS normalizer with osquery parser and field mappings`

---

### Chunk 1.3: Async Database Writer
**Time estimate:** 30–40 minutes  
**Goal:** High-performance async writer that batches inserts into TimescaleDB using `asyncpg`. Handles backpressure, connection pooling, and retries.

**File: `src/db/connection.py`**
```python
"""
Async PostgreSQL connection pool using asyncpg.
Singleton pool — initialize once at startup, share everywhere.
"""
import asyncpg
from src.config.settings import settings
from src.config.logging import get_logger

log = get_logger("db.connection")

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the connection pool."""
    global _pool
    if _pool is None:
        log.info("creating_pool", host=settings.db_host, db=settings.db_name)
        _pool = await asyncpg.create_pool(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
            min_size=settings.db_pool_min,
            max_size=settings.db_pool_max,
            command_timeout=30,
        )
    return _pool


async def close_pool() -> None:
    """Close the pool on shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        log.info("pool_closed")
```

**File: `src/db/writer.py`**
```python
"""
Batched async log writer for TimescaleDB.

Design decisions:
- Batch inserts (configurable size, default 100) for throughput
- Flush on batch full OR timeout (whichever comes first) to bound latency
- On insert failure: log the error, skip the batch, continue.
  A dead writer is worse than a dropped batch.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional

import asyncpg

from src.db.connection import get_pool
from src.ingestion.schemas import NormalizedEvent
from src.config.logging import get_logger

log = get_logger("db.writer")

BATCH_SIZE = 100
FLUSH_INTERVAL = 5.0  # seconds — flush even if batch isn't full


class LogWriter:
    """Async batched writer for the logs hypertable."""

    def __init__(self, batch_size: int = BATCH_SIZE, flush_interval: float = FLUSH_INTERVAL):
        self._buffer: list[NormalizedEvent] = []
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._total_written = 0
        self._total_errors = 0

    async def start(self) -> None:
        """Start the periodic flush loop."""
        self._flush_task = asyncio.create_task(self._periodic_flush())
        log.info("writer_started", batch_size=self._batch_size, flush_interval=self._flush_interval)

    async def stop(self) -> None:
        """Flush remaining events and stop."""
        if self._flush_task:
            self._flush_task.cancel()
        await self._flush()
        log.info("writer_stopped", total_written=self._total_written, total_errors=self._total_errors)

    async def write(self, event: NormalizedEvent) -> None:
        """Add an event to the buffer. Flushes automatically when full."""
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                await self._flush_unlocked()

    async def _periodic_flush(self) -> None:
        """Flush the buffer every N seconds regardless of size."""
        while True:
            await asyncio.sleep(self._flush_interval)
            async with self._lock:
                if self._buffer:
                    await self._flush_unlocked()

    async def _flush(self) -> None:
        async with self._lock:
            await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        """Actually write the batch to the database. Must be called with lock held."""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()

        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                # Use COPY for maximum insert performance (asyncpg native)
                rows = [
                    (
                        e.timestamp,
                        e.host_name,
                        e.host_ip,
                        e.source,
                        e.event_category,
                        e.event_type,
                        e.event_action,
                        e.user_name,
                        e.process_name,
                        e.process_pid,
                        e.source_ip,
                        e.destination_ip,
                        e.destination_port,
                        e.file_path,
                        e.file_hash,
                        json.dumps(e.raw_data),
                        json.dumps(e.model_dump(exclude={"raw_data", "enrichment"})),
                        json.dumps(e.enrichment),
                        datetime.now(tz=timezone.utc),
                    )
                    for e in batch
                ]
                await conn.copy_records_to_table(
                    "logs",
                    records=rows,
                    columns=[
                        "time", "host_name", "host_ip", "source",
                        "event_category", "event_type", "event_action",
                        "user_name", "process_name", "process_pid",
                        "source_ip", "destination_ip", "destination_port",
                        "file_path", "file_hash", "raw_data", "normalized",
                        "enrichment", "ingested_at",
                    ],
                )
                self._total_written += len(batch)
                log.info("batch_flushed", count=len(batch), total=self._total_written)

        except (asyncpg.PostgresError, OSError) as e:
            self._total_errors += len(batch)
            log.error("batch_insert_failed", count=len(batch), error=str(e))
            # TODO: Dead letter queue — write failed batches to a local file for retry


import json  # needed for json.dumps above
```

**Commit:** `feat(db): add async batched writer with COPY insert and backpressure`

---

### Chunk 1.4: File Tail Shipper
**Time estimate:** 25–35 minutes  
**Goal:** Service that watches osquery's result log file, tails new lines, parses them, and feeds them to the writer. Handles log rotation and checkpointing.

**File: `src/ingestion/shipper.py`**
```python
"""
Log shipper — tails osquery result logs and feeds them to the ingestion pipeline.

Uses watchfiles (Rust-based) for efficient file watching on macOS.
Stores a checkpoint (byte offset) so restarts don't re-ingest old data.
"""
import asyncio
import json
import os
from pathlib import Path

from src.config.settings import settings
from src.config.logging import get_logger
from src.ingestion.parser import parse_osquery_line
from src.db.writer import LogWriter

log = get_logger("ingestion.shipper")

CHECKPOINT_FILE = Path.home() / ".scarletai_shipper_checkpoint"


class FileShipper:
    """Tail a log file and ship events to the database."""

    def __init__(self, log_path: str, writer: LogWriter):
        self.log_path = Path(log_path)
        self.writer = writer
        self._offset = self._load_checkpoint()
        self._running = False
        self._events_shipped = 0

    async def run(self) -> None:
        """Main loop — tail the file forever."""
        self._running = True
        log.info("shipper_started", path=str(self.log_path), offset=self._offset)

        while self._running:
            try:
                if not self.log_path.exists():
                    log.warning("log_file_missing", path=str(self.log_path))
                    await asyncio.sleep(5)
                    continue

                current_size = self.log_path.stat().st_size

                # Detect log rotation (file got smaller)
                if current_size < self._offset:
                    log.info("log_rotation_detected", old_offset=self._offset, new_size=current_size)
                    self._offset = 0

                if current_size > self._offset:
                    await self._read_new_lines()

                await asyncio.sleep(1)  # Poll interval

            except Exception as e:
                log.error("shipper_error", error=str(e))
                await asyncio.sleep(5)

    async def _read_new_lines(self) -> None:
        """Read new lines from the current offset."""
        with open(self.log_path, "r") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parse_osquery_line(line)
                if event:
                    await self.writer.write(event)
                    self._events_shipped += 1
            self._offset = f.tell()
            self._save_checkpoint()

    def _load_checkpoint(self) -> int:
        """Load the byte offset from the checkpoint file."""
        try:
            return int(CHECKPOINT_FILE.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_checkpoint(self) -> None:
        """Persist the current byte offset."""
        CHECKPOINT_FILE.write_text(str(self._offset))

    def stop(self) -> None:
        self._running = False
        log.info("shipper_stopped", events_shipped=self._events_shipped)
```

**Commit:** `feat(ingestion): add file tail shipper with checkpointing and rotation handling`

---

### Chunk 1.5: HTTP Ingestion API
**Time estimate:** 30–40 minutes  
**Goal:** FastAPI endpoint that accepts log events over HTTP. Authenticated with bearer tokens, validates input with Pydantic, rate-limited.

**Critical security addition:** Input sanitization. Log injection attacks are real — an attacker who controls a log field can inject fake events that look like someone else's host. The API must validate and sanitize.

**File: `src/api/main.py`**
```python
"""
FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.config.logging import setup_logging, get_logger
from src.db.connection import get_pool, close_pool
from src.db.writer import LogWriter
from src.api.ingest import router as ingest_router
from src.api.health import router as health_router

log = get_logger("api")

# Shared writer instance
writer = LogWriter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    setup_logging()
    log.info("starting_api", host=settings.api_host, port=settings.api_port)
    await get_pool()
    await writer.start()
    yield
    await writer.stop()
    await close_pool()
    log.info("api_shutdown_complete")


app = FastAPI(
    title="SecurityScarletAI",
    description="AI-Native SIEM — Log Ingestion & Detection API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(ingest_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
```

**File: `src/api/auth.py`**
```python
"""
API authentication — Bearer token for ingestion, JWT for dashboard users.

Security notes:
- Bearer tokens are compared with constant-time comparison (secrets.compare_digest)
  to prevent timing attacks.
- JWT tokens are signed with HS256 using the API_SECRET_KEY.
- Passwords are hashed with bcrypt (12 rounds minimum).
"""
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext

from src.config.settings import settings

bearer_scheme = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 8


def verify_bearer_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> str:
    """Verify the bearer token for API ingestion endpoints."""
    if not secrets.compare_digest(credentials.credentials, settings.api_bearer_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return credentials.credentials


def create_jwt(username: str, role: str) -> str:
    """Create a JWT token for dashboard authentication."""
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(tz=timezone.utc),
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """Verify JWT token and return the payload."""
    try:
        payload = jwt.decode(
            credentials.credentials, settings.api_secret_key, algorithms=[JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

**File: `src/api/ingest.py`**
```python
"""
Log ingestion endpoint — receives events via HTTP POST.

Security:
- Authenticated with bearer token
- Input validated with Pydantic (rejects malformed events)
- Field length limits prevent memory exhaustion attacks
- No raw SQL — everything goes through the writer
"""
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

from src.api.auth import verify_bearer_token
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["ingestion"])


class IngestEvent(BaseModel):
    """Schema for HTTP-ingested events. Stricter than internal events."""
    timestamp: datetime = Field(alias="@timestamp")
    host_name: str = Field(max_length=253)  # max DNS hostname length
    source: str = Field(max_length=100)
    event_category: str = Field(max_length=50)
    event_type: str = Field(max_length=50)
    raw_data: dict = Field(default_factory=dict)
    # Optional fields
    user_name: str | None = Field(None, max_length=256)
    process_name: str | None = Field(None, max_length=256)
    source_ip: str | None = Field(None, max_length=45)  # max IPv6 length

    @field_validator("host_name")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        """Prevent log injection via hostname field."""
        # Strip control characters and newlines
        return "".join(c for c in v if c.isprintable() and c not in "\n\r\t")


class IngestResponse(BaseModel):
    accepted: int
    message: str


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    events: list[IngestEvent],
    _token: Annotated[str, Depends(verify_bearer_token)],
):
    """Ingest one or more security events.
    
    Requires: Bearer token in Authorization header.
    """
    if len(events) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Maximum 1000 events per batch",
        )

    # Import here to avoid circular dependency
    from src.api.main import writer

    count = 0
    for event_data in events:
        event = NormalizedEvent(
            **event_data.model_dump(by_alias=True),
            enrichment={},
        )
        await writer.write(event)
        count += 1

    return IngestResponse(accepted=count, message=f"Accepted {count} events")
```

**File: `src/api/health.py`**
```python
"""
Health check endpoints — self-observability for the SIEM.
"""
from fastapi import APIRouter
from src.db.connection import get_pool
from src.config.logging import get_logger

router = APIRouter(tags=["health"])
log = get_logger("api.health")


@router.get("/health")
async def health_check():
    """Basic liveness check."""
    checks = {"api": "ok", "database": "unknown", "ollama": "unknown"}

    # Database
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)}"
        log.error("health_check_db_failed", error=str(e))

    # Ollama (non-blocking check)
    try:
        import httpx
        from src.config.settings import settings
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            checks["ollama"] = "ok" if resp.status_code == 200 else f"status {resp.status_code}"
    except Exception:
        checks["ollama"] = "unreachable"

    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
```

**Commit:** `feat(api): add authenticated ingestion endpoint with input validation and health checks`

---

### Chunk 1.6: WebSocket Live Streaming
**Time estimate:** 20–25 minutes  
**Goal:** WebSocket endpoint at `/ws/logs` for real-time log streaming to the dashboard. Supports filtering by host, category, and severity.

> **Implementation note:** The original plan's description was fine. Implement as described. Key addition: authenticate WebSocket connections with a token query parameter since WebSocket doesn't support headers in the browser.

**Commit:** `feat(api): add WebSocket endpoint for real-time log streaming`

---

### Chunk 1.7: Log Enrichment Pipeline
**Time estimate:** 30–40 minutes  
**Goal:** Enrich raw events with GeoIP data, DNS reverse lookups, and threat intel IOC matching before writing to the database.

**This was completely missing from the original plan.** Raw logs with bare IP addresses are nearly useless for investigation. Enrichment turns `destination_ip: 185.220.101.1` into `destination_ip: 185.220.101.1, geo.country: DE, dns.reverse: tor-exit-node.example.com, threat_intel.match: true, threat_intel.source: abuseipdb, threat_intel.tags: ["tor_exit"]`.

**File: `src/enrichment/pipeline.py`**
```python
"""
Log enrichment pipeline — adds context to raw events.

Enrichments applied (in order):
1. GeoIP — country, city, ASN for public IPs
2. DNS reverse — PTR record for IPs
3. Threat Intel — match against cached IOC database

Design: Each enricher is a function that takes an event and returns
the enrichment dict to merge. Enrichers must be fast (<50ms each)
and must never raise — return empty dict on failure.
"""
import ipaddress
import socket
from typing import Any

from src.config.logging import get_logger

log = get_logger("enrichment")


def is_public_ip(ip_str: str | None) -> bool:
    """Check if an IP is routable (not private, loopback, or link-local)."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


async def enrich_geoip(ip: str) -> dict[str, Any]:
    """GeoIP lookup using MaxMind GeoLite2 database.
    
    Setup: Download GeoLite2-City.mmdb from maxmind.com (free account required)
    and place in data/GeoLite2-City.mmdb
    """
    if not is_public_ip(ip):
        return {}
    try:
        import geoip2.database
        # Cache the reader — don't open the DB file per-event
        reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")
        response = reader.city(ip)
        return {
            "geo": {
                "country_iso": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
        }
    except Exception:
        return {}


def enrich_dns_reverse(ip: str) -> dict[str, Any]:
    """Reverse DNS lookup. Synchronous but fast with timeout."""
    if not is_public_ip(ip):
        return {}
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"dns": {"reverse": hostname}}
    except (socket.herror, socket.gaierror, OSError):
        return {}


async def enrich_event(event) -> dict[str, Any]:
    """Run all enrichments for an event. Returns merged enrichment dict."""
    enrichment: dict[str, Any] = {}

    # Enrich destination IP (most useful — outbound connections)
    if event.destination_ip and is_public_ip(event.destination_ip):
        geo = await enrich_geoip(event.destination_ip)
        enrichment.update(geo)
        dns = enrich_dns_reverse(event.destination_ip)
        enrichment.update(dns)

    # Enrich source IP (inbound connections)
    if event.source_ip and is_public_ip(event.source_ip):
        src_geo = await enrich_geoip(event.source_ip)
        if src_geo:
            enrichment["source_geo"] = src_geo.get("geo", {})

    return enrichment
```

**Commit:** `feat(enrichment): add GeoIP, DNS reverse, and threat intel enrichment pipeline`

---

### Chunk 1.8: Integration Test — Full Ingestion Pipeline
**Time estimate:** 20–30 minutes  
**Goal:** End-to-end test: synthetic osquery event → parser → enrichment → writer → database → verify.

**File: `tests/integration/test_ingestion.py`**
```python
"""
Integration test for the full ingestion pipeline.

Requires: PostgreSQL running with schema applied.
Run with: poetry run pytest tests/integration/test_ingestion.py -v
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone

from src.ingestion.parser import parse_osquery_line
from src.db.writer import LogWriter
from src.db.connection import get_pool, close_pool


SYNTHETIC_EVENT = json.dumps({
    "name": "processes",
    "hostIdentifier": "integration-test-host",
    "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
    "unixTime": 1774267200,
    "columns": {
        "pid": "9999",
        "name": "suspicious_binary",
        "path": "/tmp/suspicious_binary",
        "cmdline": "/tmp/suspicious_binary --exfil",
        "uid": "0",  # root — suspicious
    },
    "action": "added"
})


@pytest.fixture
async def db_pool():
    pool = await get_pool()
    yield pool
    await close_pool()


@pytest.mark.asyncio
async def test_full_ingestion_pipeline(db_pool):
    """Test: raw osquery line → parsed → written to DB → queryable."""
    # Parse
    event = parse_osquery_line(SYNTHETIC_EVENT)
    assert event is not None
    assert event.process_name == "suspicious_binary"
    assert event.event_category == "process"

    # Write
    writer = LogWriter(batch_size=1, flush_interval=0.1)
    await writer.start()
    await writer.write(event)
    await asyncio.sleep(1)  # Wait for flush
    await writer.stop()

    # Verify in database
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM logs WHERE host_name = $1 AND process_name = $2 ORDER BY time DESC LIMIT 1",
            "integration-test-host",
            "suspicious_binary",
        )
        assert row is not None
        assert row["event_category"] == "process"
        assert row["process_pid"] == 9999

        # Cleanup
        await conn.execute(
            "DELETE FROM logs WHERE host_name = $1", "integration-test-host"
        )
```

**Commit:** `test: add full ingestion pipeline integration test`

---

## PHASE 2: DETECTION ENGINE

### Chunk 2.1: Sigma Rule Parser
**Time estimate:** 45–60 minutes (this is hard — don't underestimate it)  
**Goal:** Parse Sigma YAML rules into a structured Python object. This is the most complex parser in the project.

**Key corrections from original:**
- The original estimated 5 minutes for this. A proper Sigma parser handles nested AND/OR/NOT logic, field modifiers (`|contains`, `|endswith`, `|re`), and aggregation conditions. This is a significant piece of work.
- For the learning project, implement a *subset* of Sigma: basic field matching, AND/OR, and count aggregation. Don't try to implement the full Sigma specification.

**File: `src/detection/sigma.py`** — See Sigma specification at https://sigmahq.io/docs/basics/rules.html

> **Agent instruction:** Implement support for these Sigma features only:
> - `logsource.category`, `logsource.product` — map to ECS event_category
> - `detection.selection` — field: value matching
> - `detection.filter` — field: value exclusion
> - `detection.condition` — `selection`, `selection and not filter`, `selection | count() > N`
> - Field modifiers: `|contains`, `|endswith`, `|startswith`, `|re`
> - Generate a parameterized SQL query (NOT string interpolation — prevent SQL injection)

**Sample Sigma rule to test against — `rules/sigma/brute_force_ssh.yml`:**
```yaml
title: SSH Brute Force Detected
id: scarlet-001
status: experimental
description: Detects multiple failed SSH login attempts from the same source
author: SecurityScarletAI
date: 2026/03/21
logsource:
    category: authentication
    product: osquery
detection:
    selection:
        event_type: "start"
        event_action|contains: "logged_in_users"
    condition: selection | count(source_ip) by host_name > 5
timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1110
```

**Commit:** `feat(detection): add Sigma rule parser with SQL generation`

---

### Chunks 2.2–2.10: Detection Engine (Remaining)

The original plan's structure for chunks 2.2–2.10 is **correct in ordering and scope**. Apply these fixes:

**Chunk 2.2 — SQL Generator:** Use parameterized queries (`$1`, `$2`) not f-strings. asyncpg uses `$N` style parameters, not `%s`.

**Chunk 2.3 — Scheduler:** Replace Celery+Redis with APScheduler:
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()

async def run_rule(rule_id: int):
    """Execute a single detection rule against recent logs."""
    # Load rule, generate SQL, execute, create alerts if matches found
    pass

# Schedule all enabled rules
for rule in enabled_rules:
    scheduler.add_job(
        run_rule,
        trigger="interval",
        seconds=rule.run_interval.total_seconds(),
        args=[rule.id],
        id=f"rule_{rule.id}",
    )
scheduler.start()
```

**Chunk 2.4 — Alert Generation:** As originally specified. Good design.

**Chunk 2.5 — MITRE ATT&CK:** Download the MITRE ATT&CK STIX data from https://github.com/mitre-attack/attack-stix-data (not the raw JSON). Parse tactics and techniques into a lookup dict.

**Chunk 2.6 — Initial Rules:** Write these 5 Sigma rules (corrected for macOS relevance):
1. **Brute force login** — count(failed logins) > 5 in 5 minutes
2. **Suspicious process from /tmp** — process.path starts with `/tmp/` or `/var/tmp/`
3. **Privilege escalation via sudo** — shell_history contains `sudo` + sensitive commands
4. **New launch agent persistence** — file_events in `/Library/LaunchAgents/` or `~/Library/LaunchAgents/`
5. **Outbound connection to rare port** — destination_port NOT IN (80, 443, 53, 22) and destination_ip is public

**Chunk 2.7 — Correlation:** As originally specified. The "3 failed logins then success" pattern is a classic. Implement with a SQL window function:
```sql
-- Detect: failed logins followed by success from same source within 5 minutes
WITH login_sequence AS (
    SELECT host_name, source_ip, event_action, time,
           LAG(event_action, 1) OVER (PARTITION BY host_name, source_ip ORDER BY time) as prev_action,
           COUNT(*) FILTER (WHERE event_action LIKE '%failed%') 
               OVER (PARTITION BY host_name, source_ip ORDER BY time RANGE INTERVAL '5 minutes' PRECEDING) as failed_count
    FROM logs
    WHERE event_category = 'authentication' AND time > NOW() - INTERVAL '10 minutes'
)
SELECT * FROM login_sequence WHERE event_action LIKE '%success%' AND failed_count >= 3;
```

**Chunks 2.8–2.10 — API + Integration Test:** As originally specified.

---

## PHASE 3: DASHBOARD

The original plan's Phase 3 structure is **mostly correct**. Key changes:

**Chunk 3.6 — Threat Hunting:** Replace the raw SQL editor with a **parameterized query builder**. Never give a text box that runs arbitrary SQL against your database.

```python
# WRONG — SQL injection in your own SIEM
query = st.text_area("Enter SQL query")
results = conn.execute(query)  # Attacker enters: DROP TABLE logs; --

# RIGHT — Predefined query templates with parameter substitution
HUNTING_QUERIES = {
    "Processes from /tmp": {
        "sql": "SELECT * FROM logs WHERE process_path LIKE '/tmp/%' AND time > NOW() - $1::interval ORDER BY time DESC LIMIT 100",
        "params": [{"name": "lookback", "type": "interval", "default": "1 hour"}],
    },
    "Outbound to rare ports": {
        "sql": "SELECT * FROM logs WHERE destination_port IS NOT NULL AND destination_port NOT IN (80, 443, 53, 22) AND time > NOW() - $1::interval ORDER BY time DESC LIMIT 100",
        "params": [{"name": "lookback", "type": "interval", "default": "1 hour"}],
    },
}
```

**Chunk 3.8 — Authentication:** The original plan said "simple login with session management." That's fine for a learning project, but implement RBAC (Role-Based Access Control) with three roles:
- **admin** — can manage rules, users, and cases
- **analyst** — can view logs, manage alerts and cases
- **viewer** — read-only access to dashboards

**Commit messages remain as originally specified for Phase 3.**

---

## PHASE 4: AI-NATIVE FEATURES

### What to Keep, What to Cut

**KEEP (high learning value):**
- Chunk 4.1: Ollama integration setup
- Chunk 4.2: Natural Language → SQL (the crown jewel)
- Chunk 4.3: AI alert explanation
- Chunk 4.4: AI hunting assistant
- Chunk 4.5: UEBA behavior baseline (Isolation Forest)
- Chunk 4.6: Risk scoring
- Chunk 4.7: Automated rule generation from threat intel
- Chunk 4.8: Alert triage ML model

**CUT (low learning value, high complexity):**
- ~~Chunk 4.9: Predictive alerting with Prophet~~ → Replace with simple z-score anomaly detection on event volume. Same learning, 1/10th the dependency pain.
- ~~Chunk 4.10: MISP integration~~ → Replace with AbuseIPDB API (free, one HTTP call, no server to run)
- ~~Chunk 4.11: OpenCTI integration~~ → Replace with AlienVault OTX API (free, same)
- ~~Chunk 4.17: Model training pipeline~~ → Premature for this scope
- ~~Chunk 4.18: Feature store~~ → Enterprise MLOps pattern, not needed
- ~~Chunk 4.19: AI model evaluation~~ → Fold basic metrics into training scripts

### Chunk 4.1: Ollama Client with Graceful Degradation
**Time estimate:** 20–25 minutes  
**Goal:** Async Ollama client that handles timeouts, model unavailability, and slow responses without crashing the SIEM.

**File: `src/ai/ollama_client.py`**
```python
"""
Ollama LLM client with graceful degradation.

If Ollama is down or slow, AI features return a fallback message
instead of crashing. The SIEM must work without AI — AI is an enhancement,
not a dependency.
"""
import httpx
from typing import Optional

from src.config.settings import settings
from src.config.logging import get_logger

log = get_logger("ai.ollama")

FALLBACK_MESSAGE = "[AI unavailable — Ollama is not responding. Feature degraded gracefully.]"


async def query_llm(
    prompt: str,
    system_prompt: str = "You are a cybersecurity analyst assistant.",
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> str:
    """Query the local Ollama LLM. Returns fallback string on any failure."""
    try:
        async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
            response = await client.post(
                f"{settings.ollama_base_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "system": system_prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", FALLBACK_MESSAGE)

    except httpx.TimeoutException:
        log.warning("ollama_timeout", timeout=settings.ollama_timeout)
        return FALLBACK_MESSAGE
    except httpx.ConnectError:
        log.warning("ollama_unreachable", url=settings.ollama_base_url)
        return FALLBACK_MESSAGE
    except Exception as e:
        log.error("ollama_error", error=str(e))
        return FALLBACK_MESSAGE


async def is_ollama_available() -> bool:
    """Quick health check — is Ollama responding?"""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False
```

**Commit:** `feat(ai): add Ollama client with timeout handling and graceful degradation`

---

### Chunk 4.2: Natural Language → SQL
**Time estimate:** 45–60 minutes  
**Goal:** Convert natural language security questions into parameterized SQL queries.

**Security note:** The LLM generates SQL. You MUST validate the generated SQL before executing it. At minimum: no DDL (DROP, ALTER, CREATE, TRUNCATE), no DML writes (INSERT, UPDATE, DELETE), and no system catalog access. Whitelist SELECT only.

```python
# SQL validation — never execute raw LLM output
FORBIDDEN_PATTERNS = [
    "DROP", "ALTER", "CREATE", "TRUNCATE", "INSERT", "UPDATE", "DELETE",
    "GRANT", "REVOKE", "COPY", "pg_", "information_schema", ";--",
]

def validate_generated_sql(sql: str) -> bool:
    """Reject any SQL that isn't a pure SELECT query."""
    sql_upper = sql.upper().strip()
    if not sql_upper.startswith("SELECT"):
        return False
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in sql_upper:
            return False
    return True
```

**Commit:** `feat(ai): add NL→SQL with SQL validation guardrails`

---

### Chunk 4.5: UEBA Behavior Baseline
**Time estimate:** 60–90 minutes  
**Goal:** Use Isolation Forest to learn "normal" user behavior and flag anomalies.

**Feature engineering (what to extract from logs):**
```python
UEBA_FEATURES = [
    "login_hour_of_day",           # What hour does this user normally log in?
    "unique_processes_count",       # How many distinct processes does this user run?
    "command_diversity",            # How varied are their commands? (entropy)
    "network_connections_count",    # How many outbound connections?
    "unique_destination_ips",       # How many distinct IPs do they connect to?
    "file_access_count",           # How many file operations?
    "sudo_usage_count",            # How often do they escalate privileges?
    "session_duration_minutes",    # How long are their sessions?
]
```

> **Agent instruction:** Train on 7 days of normal data minimum. Use `contamination=0.05` (expect 5% anomalies). Scores > 0.8 = high anomaly. Retrain weekly.

**Commit:** `feat(ai): add UEBA baseline with Isolation Forest anomaly detection`

---

### Chunk 4.X: Threat Intel — Free API Feeds (Replaces MISP/OpenCTI)
**Time estimate:** 30–40 minutes  
**Goal:** Fetch IOCs from free APIs, cache in the `threat_intel` table, match against log events during enrichment.

**Sources:**
- **AbuseIPDB** — malicious IP reputation (free: 1000 checks/day)
- **AlienVault OTX** — community threat intel (free: unlimited)
- **URLhaus** — malicious URLs (free: unlimited, no API key needed)

```python
# Example: AbuseIPDB check
async def check_abuseipdb(ip: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        )
        data = resp.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
        }
```

**Commit:** `feat(intel): add free threat intel feeds (AbuseIPDB, OTX, URLhaus)`

---

### Chunks 4.12–4.16: SOAR Lite, Slack, Email, Case Management, AI Dashboard

These chunks from the original plan are **correctly specified**. Implement as described. One addition:

**Chunk 4.12 (SOAR) — macOS firewall note:** The original plan mentions `pf/iptables`. macOS uses `pf` (Packet Filter), not `iptables`. Block an IP:
```bash
# Add to /etc/pf.conf (requires sudo)
echo "block drop quick from 185.220.101.1 to any" | sudo pfctl -f -
sudo pfctl -e  # enable pf
```

> **Agent instruction:** The automated firewall blocking should be opt-in and logged. Never auto-block without human approval at this stage — false positive blocks on a learning system will lock you out of your own machine.

---

## PHASE 5: HARDENING & DEPLOYMENT

### Chunk 5.1: Backup Script
**Time estimate:** 15 minutes  
**Goal:** Automated daily PostgreSQL backup.

```bash
#!/bin/bash
# scripts/backup.sh — Run daily via cron or launchd
BACKUP_DIR="$HOME/scarletai-backups"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
pg_dump scarletai | gzip > "$BACKUP_DIR/scarletai_$TIMESTAMP.sql.gz"
# Keep last 7 days
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
echo "Backup complete: scarletai_$TIMESTAMP.sql.gz"
```

### Chunk 5.2: Test Data Generator (Attack Simulation)
**Time estimate:** 30–40 minutes  
**Goal:** Script that generates realistic attack simulation data to test your detection rules. Without this, you're testing a SIEM that has never seen an attack.

**File: `scripts/generate_attack_data.py`**
```python
"""
Generate synthetic attack events for testing detection rules.

Scenarios:
1. SSH brute force (10 failed logins, then success)
2. Reverse shell (bash process with /dev/tcp connection)
3. Data exfiltration (large outbound transfer to rare IP)
4. Persistence (new LaunchAgent created)
5. Privilege escalation (sudo to root)
"""
import json
import time
import random
from datetime import datetime, timezone, timedelta

def generate_brute_force(host: str = "test-mac.local") -> list[dict]:
    """Generate 10 failed SSH logins followed by 1 success."""
    events = []
    attacker_ip = f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    
    for i in range(10):
        events.append({
            "name": "logged_in_users",
            "hostIdentifier": host,
            "unixTime": int((base_time + timedelta(seconds=i*30)).timestamp()),
            "columns": {
                "type": "failed",
                "user": "admin",
                "host": attacker_ip,
            },
            "action": "added",
        })
    
    # Successful login after brute force
    events.append({
        "name": "logged_in_users",
        "hostIdentifier": host,
        "unixTime": int((base_time + timedelta(minutes=5)).timestamp()),
        "columns": {
            "type": "user",
            "user": "admin",
            "host": attacker_ip,
        },
        "action": "added",
    })
    return events

# ... additional scenarios for each attack type
```

### Chunks 5.3–5.6: Docker, Config, Docs, Release

The original plan's Phase 5 is **correctly structured**. Implement as described with this addition to the README:

**Add a "Security Considerations" section:**
```markdown
## Security Considerations

SecurityScarletAI is a learning project. It is NOT production-hardened for enterprise deployment.
Known limitations:
- Single-user JWT (no token rotation or refresh)
- No TLS between components (add nginx/caddy reverse proxy for HTTPS)
- Threat intel API keys stored in .env (use a secrets manager for production)
- Ollama runs unauthenticated on localhost (do not expose to network)
- File-based checkpointing (not crash-consistent)
```

---

## REVISED TIMELINE (Honest Estimates)

| Phase | Chunks | Realistic Time | Notes |
|-------|--------|----------------|-------|
| Prerequisites | — | 1–2 hours | One-time system setup, may need troubleshooting |
| Phase 0: Foundation | 6 | 3–5 hours | Config, schema, logging, Docker |
| Phase 1: Ingestion | 8 | 8–12 hours | Parser, writer, shipper, API, enrichment |
| Phase 2: Detection | 10 | 12–18 hours | Sigma parser is the bottleneck |
| Phase 3: Dashboard | 12 | 10–15 hours | Streamlit is fast to prototype |
| Phase 4: AI-Native | 12 (reduced) | 15–20 hours | ML/LLM integration is iterative |
| Phase 5: Hardening | 6 | 4–6 hours | Docs, backup, testing |
| **TOTAL** | **~54** | **~52–78 hours** | **6–10 weeks at 8–10 hrs/week** |

> The original plan claimed 4.5 hours. That would be true if you were copy-pasting finished code. Since you're building, testing, debugging, and learning — expect 10–15x longer. This is normal and correct for a learning project.

---

## TEST DATA & VALIDATION CHECKLIST

Run these checks at the end of each phase to confirm everything works:

### After Phase 1 (Ingestion)
```bash
# Verify osquery is generating logs
wc -l /opt/homebrew/var/log/osquery/osqueryd.results.log

# Verify events are in the database
psql scarletai -c "SELECT COUNT(*) FROM logs;"
psql scarletai -c "SELECT event_category, COUNT(*) FROM logs GROUP BY event_category;"

# Verify API health
curl http://localhost:8000/api/v1/health | python3 -m json.tool
```

### After Phase 2 (Detection)
```bash
# Run attack simulation
poetry run python scripts/generate_attack_data.py

# Check for alerts
psql scarletai -c "SELECT rule_name, severity, host_name FROM alerts ORDER BY time DESC LIMIT 10;"
```

### After Phase 4 (AI)
```bash
# Test NL→SQL
curl -X POST http://localhost:8000/api/v1/ai/query \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "Show me all processes running from /tmp in the last hour"}'

# Test alert explanation
curl http://localhost:8000/api/v1/alerts/1/explain \
  -H "Authorization: Bearer $TOKEN"
```

---

## SKILLS & DEPENDENCIES (Updated)

| Skill | Level Needed | How You'll Learn It |
|-------|-------------|---------------------|
| Python async/await | Intermediate | Building the writer and shipper |
| PostgreSQL + TimescaleDB | Intermediate | Schema design, hypertable queries |
| FastAPI | Beginner → Intermediate | Building the API layer |
| Streamlit | Beginner | Dashboard prototyping |
| APScheduler | Beginner | Detection rule scheduling |
| scikit-learn | Beginner | UEBA Isolation Forest |
| Ollama / LLM prompting | Beginner | NL→SQL, alert explanation |
| Sigma rule format | Beginner | Writing and parsing rules |
| Pydantic | Beginner → Intermediate | Config, API schemas, validation |
| structlog | Beginner | Structured logging |
| asyncpg | Intermediate | High-performance DB operations |

---

## EXTERNAL DEPENDENCIES (Verified for macOS ARM64)

| Dependency | Version | Install | ARM64 Status |
|-----------|---------|---------|-------------|
| PostgreSQL | 16+ | `brew install postgresql@16` | Native |
| TimescaleDB | 2.x | `brew tap timescale/tap && brew install timescaledb` | Native |
| Redis | 7+ | `brew install redis` | Native |
| osquery | 5.10+ | `brew install osquery` | Native |
| Ollama | latest | `brew install ollama` | Native (Metal GPU) |
| Python | 3.11+ | `brew install python@3.11` | Native |
| GeoLite2 DB | latest | Download from maxmind.com | Platform-independent |

---

## SUCCESS METRICS (Revised)

### MVP Complete (End of Week 3):
- [ ] osquery running and generating logs on your Mac
- [ ] Logs flowing into TimescaleDB via shipper
- [ ] 5 detection rules parsing and executing
- [ ] Alerts generating with MITRE ATT&CK tags
- [ ] Health check endpoint returning "healthy"
- [ ] Attack simulation data triggers at least 3 rules

### v1.0 Complete (End of Week 6):
- [ ] Dashboard showing live logs, alerts, and metrics
- [ ] 10+ detection rules active
- [ ] Alert lifecycle: new → investigating → resolved
- [ ] Case management linking related alerts
- [ ] Authentication with RBAC (admin/analyst/viewer)
- [ ] Log enrichment (GeoIP + DNS + threat intel)

### AI-Native Complete (End of Week 10):
- [ ] "Show me failed logins today" returns correct results via NL→SQL
- [ ] Alert explanations generated by Ollama
- [ ] UEBA risk scores visible per user/asset
- [ ] AI hunting assistant suggests queries
- [ ] Automated rule generation from threat description
- [ ] All AI features degrade gracefully when Ollama is down

---

*Plan revised by Security Engineering Review — v2.0*  
*Original: 80 chunks, 4.5 hours (unrealistic)*  
*Revised: 54 chunks, 6–10 weeks (honest)*  
*Removed: 26 chunks of premature optimization*  
*Added: Security hardening, self-observability, enrichment, test data, honest timelines*
