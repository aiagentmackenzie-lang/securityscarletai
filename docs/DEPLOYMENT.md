# Deployment Guide

SecurityScarletAI runs as a FastAPI service backed by PostgreSQL 17 and Redis 7. Docker Compose is the recommended deployment path — it brings up Postgres, Redis, the API, the entrypoint initializer, and optionally the Streamlit dashboard. The entrypoint is idempotent: re-running on a populated database is a no-op for one-time setup steps.

This document covers: prerequisites, environment variables, Docker Compose deployment, the idempotent entrypoint, schema management, security hardening, JWT rotation, backup/recovery, monitoring, and troubleshooting.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ (tested on 3.14) | Local dev uses Poetry; Docker images use the slim base |
| Docker | 20.10+ | For PostgreSQL, Redis, and the API container |
| Docker Compose | v2 (`docker compose`) | Compose v1 not supported |
| PostgreSQL | 17 | Bundled in `docker-compose.yml` (postgres:17-alpine) |
| Redis | 7 | Bundled in `docker-compose.yml` (redis:7-alpine) |
| Poetry | 1.7+ | Python dependency management for local dev only |
| Ollama | Latest | Local LLM runtime (optional — features degrade gracefully without it) |

---

## Environment Variables

Copy the template and edit:

```bash
cp .env.example .env
```

Generate strong secrets with `openssl rand`:

```bash
# JWT signing key (64 hex chars = 32 bytes)
openssl rand -hex 64

# API bearer token (32 hex chars = 16 bytes minimum, 32+ recommended)
openssl rand -hex 32

# Database password (32+ base64 chars)
openssl rand -base64 32
```

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password (no default) | `openssl rand -base64 32` |
| `API_SECRET_KEY` | JWT signing key (min 32 bytes / 64 hex chars) | `openssl rand -hex 64` |
| `API_BEARER_TOKEN` | API ingestion auth token (min 16 bytes) | `openssl rand -hex 32` |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5433` | PostgreSQL port (5433 avoids Homebrew conflict on macOS) |
| `DB_NAME` | `scarletai` | Database name |
| `DB_USER` | `scarletai` | Database user |
| `DB_POOL_MIN` | `2` | Min asyncpg connection pool size |
| `DB_POOL_MAX` | `10` | Max asyncpg connection pool size |
| `DATABASE_URL` | _(derived)_ | Full `postgresql://` URL — overrides the parts above if set |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL for rate-limit counters and JWT blocklist |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `127.0.0.1` | API bind address |
| `API_PORT` | `8000` | API bind port |
| `API_CORS_ORIGINS` | `http://localhost:8501` | Comma-separated allowed CORS origins |
| `ACCESS_TOKEN_TTL_MINUTES` | `60` | JWT access token lifetime |

### Dashboard Configuration

| Variable | Default | Description |
|----------|---------|---------|
| `DASHBOARD_API_TOKEN` | _(empty)_ | Static bearer token for headless dashboard → API auth. Leave blank to require manual JWT login via the dashboard. When set, the dashboard can call the API without a user login (service-to-service). |

### Ollama (AI Features)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `llama3.2:8b` | Model name |
| `OLLAMA_TIMEOUT` | `30` | Request timeout (seconds) |

AI features degrade gracefully when Ollama is unavailable — template fallbacks and rule-based responses are used instead. The `/health` endpoint's `ollama_status` reports `healthy | degraded | unavailable`.

### osquery (Ingestion)

| Variable | Default | Description |
|----------|---------|-------------|
| `OSQUERY_LOG_PATH` | `/var/log/osquery/osqueryd.results.log` | Path to the osquery result log on the host |
| `OSQUERY_CONFIG_PATH` | `/var/osquery/osquery.conf` | Path to the osquery config file |

### Threat Intel (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key for IP reputation lookups |
| `OTX_API_KEY` | _(empty)_ | AlienVault OTX API key |

If both are empty, threat-intel enrichment silently skips and `configured: false` is returned by `/threat-intel/status`. The pipeline does not error.

### Notifications (Optional)

| Variable | Default | Description |
|----------|---------|---------|
| `SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook for alert notifications |
| `SMTP_HOST` | _(empty)_ | SMTP server for email alerts |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | _(empty)_ | SMTP username |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password |
| `ALERT_EMAIL_TO` | _(empty)_ | Alert recipient email |

If `SLACK_WEBHOOK_URL` is empty, Slack notifications are skipped silently. The same applies to SMTP when the host is empty.

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LOG_FORMAT` | `console` | `console` for dev, `json` for production |

---

## Docker Compose Deployment

The included `docker-compose.yml` defines four services: `postgres`, `redis`, `api`, and (optionally) `dashboard`.

### Bring up the full stack

```bash
# Start infrastructure + API + entrypoint init
docker compose up -d postgres redis api

# Watch the entrypoint initialize
docker compose logs -f api

# Verify the API is up
curl http://localhost:8000/api/v1/health
```

### Port Assignments

| Service | External Port | Internal Port | Notes |
|---------|---------------|---------------|-------|
| PostgreSQL | 5433 | 5432 | External port avoids macOS Homebrew PostgreSQL conflict |
| Redis | 6379 | 6379 | Bind to `127.0.0.1` in production |
| API | 8000 | 8000 | FastAPI / Uvicorn |
| Dashboard | 8501 | 8501 | Streamlit (optional) |

### Idempotent entrypoint (`scripts/entrypoint.sh`)

The API container runs `entrypoint.sh` before starting Uvicorn. The script performs the following in order, and **each step is idempotent** — re-running on a populated database is a no-op for steps 3-6:

1. **Wait for Postgres** to be reachable (retry with exponential backoff)
2. **Apply schema** via `psql -f src/db/schema.sql` (all `CREATE TABLE IF NOT EXISTS`)
3. **Seed demo data** if the `alerts` table is empty (first run only)
4. **Train the triage model** if `models/triage_model.joblib` is missing
5. **Train the UEBA model** if `models/ueba_model.joblib` is missing
6. **Create an admin user** if no users exist; print credentials to stdout **once**
7. **`exec uvicorn`** so it becomes PID 1 and receives signals

Failure policy: `set -e` halts the container on any failed step. This is intentional — better to crash and let Compose restart than to start the API against an uninitialised DB.

### Run only infrastructure (for local dev)

```bash
docker compose up -d postgres redis
# Then in a separate terminal:
poetry install
poetry run uvicorn src.api.main:app --reload
```

### Add the dashboard

The dashboard runs as an optional Streamlit service. Enable it by uncommenting the `dashboard` service in `docker-compose.yml` and setting `DASHBOARD_API_TOKEN` in `.env`:

```bash
docker compose --profile dashboard up -d
# Then open http://localhost:8501
```

---

## Database Migrations

SecurityScarletAI uses a **single canonical schema path**: `src/db/schema.sql`.

### `src/db/schema.sql` (canonical, idempotent)

The raw SQL file is the source of truth. All `CREATE TABLE` statements use `IF NOT EXISTS`. This file is what `scripts/entrypoint.sh` and `docker-entrypoint-initdb.d/10-create-db.sql` apply on first run, and what `scripts/run_osquery_demo.sh` / `scripts/demo.sh` apply for local dev.

When you need to add a new column or table, **append** to this file rather than rewriting existing statements. This keeps the file diff-friendly across merges and safe to re-run on a live database.

```bash
# Apply / refresh the schema against a running Postgres
psql "$DATABASE_URL" -f src/db/schema.sql
```

> **History note:** Alembic migration files were previously bundled but never
> wired (`env.py` had `target_metadata = None` and used a sync engine against
> an asyncpg app, so `alembic upgrade head` could not run). They were removed
> in favor of owning `schema.sql` as the sole path. There is no versioned
> migration tool today — schema evolution is append-only on `schema.sql`.

---

## Security Hardening

### TLS Termination

- **Never expose the API directly in production** — use a reverse proxy (nginx, Caddy, Traefik) with TLS.
- Example nginx config:

```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/scarletai.pem;
    ssl_certificate_key /etc/ssl/private/scarletai.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

For the Streamlit dashboard, run it behind the same reverse proxy on a subpath.

#### Production overlay (Caddy + automatic TLS)

A committed Caddy config and a production compose overlay ship in the repo so the
TLS-terminated path is reproducible rather than left as an exercise:

- `deploy/Caddyfile` — Caddy reverse proxy with automatic Let's Encrypt TLS,
  security headers, and `/api/*` -> API, everything else -> dashboard.
- `docker-compose.prod.yml` — overlay that removes the dev source mount,
  stops the API/dashboard from publishing host ports (only Caddy exposes
  80/443), sets `LOG_FORMAT=json` / `LOG_LEVEL=WARNING`, and adds memory
  limits + a `caddy` service.

Launch it with your real hostname:

```bash
DOMAIN=scarlet.example.com docker compose \
  -f docker-compose.yml -f docker-compose.prod.yml up -d
```

> Requires Docker Compose v2.20+ for the `!reset` volume/port override syntax.
> Set the `email` and `<DOMAIN>` placeholders in `deploy/Caddyfile` before the
> first launch. Secrets still come from `.env` (or a secrets manager — see below).

### JWT Secret Rotation

The project includes JWT hardening (jti blocklist, refresh-token rotation, password-change invalidation). To rotate the `API_SECRET_KEY` safely:

1. Generate a new key: `openssl rand -hex 64`
2. Update the `.env` (or your secrets manager) on **one** API replica at a time
3. The new key signs new tokens. The old key still validates existing tokens until they expire (default 60 min)
4. To force-invalidate all existing tokens, use the `/auth/logout-all` endpoint (admin only) or rotate Redis (`FLUSHDB` on the JWT blocklist DB)
5. Repeat for each replica

**In production:** use a secrets manager (Vault, AWS Secrets Manager, 1Password) and roll keys without restart via the provider's reload hooks.

> **History rewrite deliberately deferred:** Git history rewrite (BFG / `git filter-repo`) to remove the original `scarletai_secure_2026` credential from history is **not** part of this work — see git log for the original decision record (Option B: local-dev-only credentials, cost/benefit of history rewrite not justified for a pre-production SIEM).

### Authentication Hardening

- **JWT `jti` claims** — every access token has a unique ID, enabling single-token revocation
- **Refresh token rotation** — refresh tokens rotate on use; the old token is invalidated
- **Redis-backed blocklist** — revoked tokens are written to Redis with TTL = remaining lifetime
- **`SecretStr` for secrets** — `API_SECRET_KEY` and `API_BEARER_TOKEN` are stored as Pydantic `SecretStr` so they don't leak into logs or tracebacks
- **Account lockout** — `POST /auth/login` rate-limits failed attempts per user and locks the account after threshold
- **Audit log hardening** — all mutating requests are recorded in the DB-backed `audit_logs` table with `REVOKE`d grants for non-admin roles (see `src/db/schema.sql` for the `REVOKE` statements)

### Network Isolation

- PostgreSQL should only be accessible from the API host
- Use Docker networks or firewall rules:

  ```bash
  # Only allow API host to connect to PostgreSQL
  iptables -A INPUT -p tcp --dport 5433 -s 127.0.0.1 -j ACCEPT
  iptables -A INPUT -p tcp --dport 5433 -j DROP
  ```

- Ollama should only listen on `127.0.0.1:11434` (default) — never expose to the network
- Redis should not be accessible externally — bind to `127.0.0.1` or use Docker's internal network

### Rate Limiting

The API includes Redis-backed rate limiting via SlowAPI (`src/api/rate_limit.py`). Per-endpoint limits are configured in `src/api/rate_limit.py`:

| Endpoint | Default Limit |
|----------|---------------|
| `POST /auth/login` | 5/minute per IP |
| `POST /ingest` | 60/minute per API token |
| All other endpoints | 120/minute per user |

For production, also add external rate limiting at the reverse proxy level.

### Input Validation

- All API endpoints use Pydantic models for request validation
- NL→SQL queries undergo 7-layer injection defense (see [docs/AI.md](AI.md))
- Log ingestion validates against ECS-normalized schemas (`src/ingestion/schemas.py`)
- SQL queries use `$1, $2` parameterized placeholders exclusively
- Correlation engine SQL binds `as_of` timestamps as `timestamptz` — no `NOW()` in query strings

### Additional Hardening

- Set `LOG_FORMAT=json` in production for structured logging
- Use `LOG_LEVEL=WARNING` or higher in production to reduce log volume
- Enable SMTP STARTTLS for email notifications
- Restrict CORS origins to your actual dashboard URL
- Run the API as a non-root user (the Docker image creates a `scarletai` user)
- Keep dependencies updated: `poetry update`

---

## Backup & Recovery

### Database Backup

```bash
# Full backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai -F c -f scarletai_backup_$(date +%Y%m%d).dump

# Schema-only backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai --schema-only -f schema_backup.sql

# Data-only backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai --data-only -f data_backup.sql
```

### Recovery

```bash
# Restore from custom format backup
pg_restore -h localhost -p 5433 -U scarletai -d scarletai -c scarletai_backup_20260603.dump

# Restore from SQL dump
psql -h localhost -p 5433 -U scarletai -d scarletai -f data_backup.sql
```

### Automated Backup Script

A reference script is in `scripts/backup.sh`. It uses `~/.pgpass` for credentials (avoids the `PGPASSWORD` process-list exposure):

```bash
# Add to crontab: 0 2 * * * /path/to/backup.sh
BACKUP_DIR="/var/backups/scarletai"
mkdir -p "$BACKUP_DIR"
pg_dump -h localhost -p 5433 -U scarletai -d scarletai \
  -F c -f "$BACKUP_DIR/scarletai_$(date +\%Y\%m\%d_\%H\%M).dump"
# Keep only last 30 days
find "$BACKUP_DIR" -name "*.dump" -mtime +30 -delete
```

### ML Model Files

Model files (`models/*.joblib`, `models/*.sha256`) are gitignored and should be backed up separately:
- They are auto-generated during triage model training
- Can be regenerated from training data in the `alerts` table (slow path)
- Back up the entire `models/` directory if you have trained custom models

---

## Monitoring Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Liveness + readiness (checks DB and Ollama) |
| `/docs` | GET | Swagger UI (auto-generated by FastAPI) |
| `/redoc` | GET | ReDoc documentation (auto-generated) |
| `/api/v1/ai/status` | GET | AI subsystem status: model provenance, cost rollup, prompt versions, calibration metrics |
| `/api/v1/audit/requests` | GET | Query the DB-backed audit log (admin only) |
| `/api/v1/auth/me` | GET | Current user info from JWT |
| `/api/v1/auth/change-password` | POST | Change own password |

### Health Response Shape

```json
{
  "status": "healthy",
  "checks": {
    "api": "ok",
    "database": "ok",
    "ollama": "ok"
  },
  "ollama_status": "healthy",
  "ollama": {
    "ollama_status": "healthy",
    "model": "llama3.2:8b",
    "error": null
  }
}
```

`status` is `healthy` only when every check passes; otherwise `degraded`. The `ollama` block is a rich object (`ollama_status`, `model`, `error`) for monitoring/alerting. The legacy `checks["ollama"]` key is preserved with string values (`"ok" | "error" | "unreachable"`) for backward compat with older monitors.

When Ollama is unreachable, the status becomes `"degraded"` and AI features use template fallbacks.

---

## Troubleshooting

### Database Connection Errors

```bash
# Check PostgreSQL is running
docker compose ps

# Test connection
psql -h localhost -p 5433 -U scarletai -d scarletai -c "SELECT 1"

# Check logs
docker compose logs postgres
```

Common issues:
- **Port 5433 in use**: Stop Homebrew PostgreSQL (`brew services stop postgresql`) or change `DB_PORT`
- **Authentication failed**: Verify `DB_PASSWORD` matches in `.env` and the postgres container's init script
- **Migration errors**: The schema is `src/db/schema.sql`, applied idempotently — re-run `psql "$DATABASE_URL" -f src/db/schema.sql`. There is no Alembic chain.

### Ollama Connection Issues

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Pull the default model
ollama pull llama3.2:8b
```

AI features work without Ollama using template fallbacks. Check the health endpoint:

```bash
curl http://localhost:8000/api/v1/health | jq '.ollama_status'
```

Returns `healthy | degraded | unavailable`.

### API Not Starting

```bash
# Check for port conflicts
lsof -i :8000

# Verify settings
poetry run python -c "from src.config.settings import settings; print(settings.database_url)"

# Check for missing .env
ls -la .env

# View entrypoint logs
docker compose logs api
```

### Login / Authentication Issues

```bash
# Check the admin user was created (printed once on first run)
docker compose logs api | grep -A 2 "admin user created"

# If locked out, reset via psql
psql -h localhost -p 5433 -U scarletai -d scarletai -c \
  "UPDATE siem_users SET failed_attempts = 0, locked_until = NULL WHERE username = 'admin';"

# Force-invalidate all JWTs (rotates the secret)
redis-cli FLUSHDB
```

### Dashboard Issues

```bash
# Start dashboard with verbose logging
poetry run streamlit run dashboard/main.py --server.port 8501 --logger.level debug

# Check API connectivity from dashboard
curl http://localhost:8000/api/v1/health

# If using DASHBOARD_API_TOKEN, verify it matches between .env files
grep DASHBOARD_API_TOKEN .env
```

### High Memory Usage

- Reduce `DB_POOL_MAX` in `.env` (default: 10)
- Set `DB_POOL_MIN=2` for minimal connection pool
- Consider `OLLAMA_TIMEOUT=15` if Ollama requests are slow

### Slow Queries

- Check indexes: `\di` in `psql`
- NL→SQL queries are limited to 5 seconds max and 10,000 row cost
- Add GIN indexes for JSONB columns (already included in `schema.sql` for `enrichment`, `raw_data`)

### Container Won't Start After `docker compose up`

The entrypoint uses `set -e` — any failed init step halts the container. Check:

```bash
docker compose logs api
```

Common entrypoint failures:
- Postgres not yet ready → wait a few seconds, the retry loop handles this
- Permission denied on `models/` → check the volume mount
- Schema already exists with conflicting definitions → drop the DB and re-init (`docker compose down -v` then `up`)
