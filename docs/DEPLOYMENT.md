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
| `API_BEARER_TOKEN` | API ingestion auth token (min 16 bytes) — full admin bearer | `openssl rand -hex 32` |
| `INGEST_BEARER_TOKEN` | Optional (P2.6) scoped ingest token — viewer-class, valid ONLY on `POST /ingest`. Unset = disabled | `openssl rand -hex 32` |

### Database Configuration

The Postgres DSN is **derived** in `src/config/settings.py` from the parts
below (URL-encoded so a rotated `DB_PASSWORD` containing `/`, `@`, `:` etc.
can't break the connection string). There is **no `DATABASE_URL` setting** —
do not add one to `.env`; it is not read and a hand-edited DSN becomes a
stale-DSN footgun after a password rotation.

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5433` | PostgreSQL port (5433 avoids Homebrew conflict on macOS) |
| `DB_NAME` | `scarletai` | Database name |
| `DB_USER` | `scarletai` | Database user |
| `DB_POOL_MIN` | `2` | Min asyncpg connection pool size |
| `DB_POOL_MAX` | `10` | Max asyncpg connection pool size |

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
| `PASSWORD_PEPPER` | _(empty)_ | Optional server-side secret (HMAC-SHA256) mixed into password hashing before the SHA-256 pre-hash + bcrypt. Protects against DB-only leaks (an attacker with the DB but not this secret cannot offline-crack the hashes). Leave unset to keep existing hashes validating; rotating it requires rehashing all passwords. |
| `ACCESS_TOKEN_TTL_MINUTES` | `15` | JWT access token lifetime (minutes) |
| `DOCS_ENABLED` | `true` | When `false`, the Swagger UI (`/api/docs`), ReDoc (`/api/redoc`) and `/openapi.json` are not served. The prod overlay sets this to `false` so the unauthenticated API schema + interactive docs are not exposed. |
| `SEED_ADMIN_ENABLED` | `false` | When `true`, the localhost-only `POST /auth/seed-admin` bootstrap is enabled (creates an admin with the known weak password `admin`, must_change_password=true). Default false so it is not a second weak-password bootstrap path in prod. Production bootstrap is the Docker entrypoint. |

### Dashboard Configuration

| Variable | Default | Description |
|----------|---------|---------|
| `DASHBOARD_API_TOKEN` | _(empty)_ | Static bearer token for headless dashboard → API auth. Leave blank to require manual JWT login via the dashboard. When set, the dashboard can call the API without a user login (service-to-service). |

#### Dashboard exposure — read before exposing the dashboard to a network

`DASHBOARD_API_TOKEN` grants **admin** API access (the API's static bearer
falls back to `role: admin`). When it is set, the dashboard **skips its
login screen** and acts as an admin client. Anyone who can reach the
dashboard URL then has full admin SIEM access — read all alerts, run NL→SQL
queries, manage rules/cases, ingest. **Never expose the dashboard
unauthenticated with `DASHBOARD_API_TOKEN` set.**

Two safe production options:

1. **JWT-only (default, recommended).** Leave `DASHBOARD_API_TOKEN` empty
   (the prod overlay defaults it to `${DASHBOARD_API_TOKEN:-}` = empty). The
   dashboard forces an interactive JWT login. This is the safest default.
2. **Service token behind a gateway (headless/automated use).** Keep the
   token set AND gate the dashboard behind Caddy `basicauth`, an
   identity-aware proxy (OAuth/IAP), or an IP allowlist. A commented
   `basicauth` block is in `deploy/Caddyfile`; generate a hash with
   `caddy hash-password`.

When the token is set, the dashboard prints a startup warning to stderr
(visible in `docker logs scarletai-dashboard`) reminding you to gate it.

### Ollama (AI Features)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `mistral:7b` | Model name (the model installed in the reference deploy; pull it with `ollama pull mistral:7b`). Override per deployment. |
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
| `THREAT_INTEL_ENABLED` | `true` | When `false`, the threat-intel refresh scheduler is not started and no external feed calls are made (URLhaus/AbuseIPDB/OTX). IOC enrichment matches the local `threat_intel` cache only. The air-gapped / no-egress switch — see `docs/AIR-GAPPED.md`. |
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key for IP reputation lookups |
| `OTX_API_KEY` | _(empty)_ | AlienVault OTX API key |

If both feed keys are empty, keyed enrichment silently skips and `configured: false` is returned by `/threat-intel/status`. (URLhaus needs no key and would still call out every 6 h — set `THREAT_INTEL_ENABLED=false` to close that path too.) The pipeline does not error.

For an **air-gapped / no-egress** deployment, set `THREAT_INTEL_ENABLED=false` and leave both keys empty; see [`docs/AIR-GAPPED.md`](AIR-GAPPED.md).

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
3. **Replay the dead-letter queue** (best-effort, non-fatal) — see below
4. **Seed demo data** if the `alerts` table is empty (first run only)
5. **Train the triage model** if `models/triage_model.joblib` is missing
6. **Train the UEBA model** if `models/ueba_model.joblib` is missing
7. **Create an admin user** if no users exist; write the random password to `data/admin_initial_password` (chmod 600, owned by the container user) and print it to stdout **once** on first boot — not left in `docker logs` indefinitely
8. **`exec uvicorn`** so it becomes PID 1 and receives signals

Failure policy: `set -e` halts the container on any failed step. This is intentional — better to crash and let Compose restart than to start the API against an uninitialised DB. The dead-letter replay (step 3) is the one exception: it is wrapped so a failure logs a warning and continues (a stuck replay must not block API startup).

#### Dead-letter queue & replay (P1-E)

When a write batch fails (DB down, transient error), `src/db/writer.py`
persists the events to `data/dead_letter/<date>.jsonl` (one event per line,
true JSON-Lines) so nothing is silently dropped. Two gaps used to make this
half a guarantee: the file lived on a path that could be ephemeral, and
nothing ever read it back. Both are now closed:

- **Persistence:** the dev compose bind-mounts `./data:/app/data` so dead
  letters survive `docker compose down`/`up`. In production, ensure `./data`
  is on persistent storage (or swap the API service's volume to a named
  `scarlet_data` volume) — otherwise dead letters are lost when the deploy
  dir is wiped.
- **Replay:** `scripts/replay_dead_letter.py` reads every `*.jsonl` in
  `data/dead_letter/`, reconstructs each event, and re-ingests it via the
  writer. The entrypoint runs it on boot (best-effort). Replayed files move
  to `data/dead_letter/processed/` so a re-run doesn't double-ingest. Run it
  manually any time: `python -m scripts.replay_dead_letter`.

### Run only infrastructure (for local dev)

```bash
docker compose up -d postgres redis
# Then in a separate terminal:
poetry install
poetry run uvicorn src.api.main:app --reload
```

### Add the dashboard

The dashboard runs as an optional Streamlit service. It is a regular (non-profile) service in `docker-compose.yml`, so it starts with the rest of the stack. Set `DASHBOARD_API_TOKEN` in `.env` for headless/service-to-service auth, or leave it blank to require manual JWT login:

```bash
docker compose up -d dashboard
# Then open http://localhost:8501
```

---

## Database Migrations

SecurityScarletAI uses a **single canonical schema path**: `src/db/schema.sql`.

### `src/db/schema.sql` (canonical, idempotent)

The raw SQL file is the source of truth. All `CREATE TABLE` statements use `IF NOT EXISTS`. This file is what `scripts/entrypoint.sh` applies on first run, and what `scripts/run_osquery_demo.sh` applies for local dev. (The compose `postgres` service also mounts it as `docker-entrypoint-initdb.d/01-schema.sql` for a fresh volume.)

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

## Ports discipline (prod — plan phase 4, F-04)

**Only 80/443 ever publish in production.** The prod overlay revokes the
dev-only host ports on postgres and redis (`ports: !reset []`); before this
overlay the DB (:5433) and Redis (:6379, no password) were LAN-reachable —
Redis unauthenticated means any host could FLUSHALL the JWT blocklist and
rate-limit buckets. In the merged config only Caddy publishes ports:

```bash
REDIS_PASSWORD=<gen> DOMAIN=scarlet.example.com   docker compose -f docker-compose.yml -f docker-compose.prod.yml config | grep published
# expect exactly: 80 and 443
```

## Redis auth (prod — F-04)

The production overlay runs redis with `--requirepass ${REDIS_PASSWORD}`
(required — compose fails fast if unset) and rewrites the API's
`REDIS_URL` to `redis://:$REDIS_PASSWORD@redis:6379/0`. DEV compose keeps
redis password-less (localhost-only). Generate with
`openssl rand -base64 32` and put it in `.env`. Health checks use
`redis-cli ping` — with requirepass, ping still works unauthenticated
(no-op PING allowed), so no healthcheck change is needed.

## Proxy headers (F-07)

The entrypoint starts uvicorn with `--proxy-headers
--forwarded-allow-ips=$UVICORN_FORWARDED_ALLOW_IPS` (default: docker
private ranges). Behind Caddy this is what makes slowapi rate-limit keys
and `audit_logs.ip` carry the REAL client (X-Forwarded-For) instead of the
proxy IP. Without it, one abusive client 429s the whole organization
(one global bucket) and the audit trail's ip column is useless. Only
private ranges are trusted by default; a client that bypasses Caddy
cannot spoof XFF into the key. Override the default with
`UVICORN_FORWARDED_ALLOW_IPS` if your ingress sits elsewhere.

## Container hardening (container hygiene)

api, dashboard and caddy run with `security_opt: no-new-privileges:true`
and `cap_drop: [ALL]`. Postgres keeps the official image's default caps:
the entrypoint legitimately needs chown/setuid to initialize the data
directory — shipping it cap-less requires a custom image and is out of
scope (documented tradeoff).

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
- **Audit log** — all mutating requests are recorded in the DB-backed `audit_logs` table. Append-only **by convention** (the app only INSERTs/SELECTs). DB-enforced immutability via `REVOKE` requires a two-role deploy — see [Audit immutability](#audit-immutability-p1-c) below and `scripts/harden_audit.sql`. The default single-role deploy is convention-only.

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
| `POST /ingest` | 100/minute per IP |
| All other endpoints | 200/minute per IP |

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
- Run the API as a non-root user (the Docker image creates an `appuser` user)
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

## Audit immutability (P1-C)

The audit tables (`audit_logs`, HTTP-level; `audit_log`, action-level) are
append-only **by convention** — the application only INSERTs and SELECTs
them. DB-enforced immutability (so a compromised app cannot rewrite or
delete its own audit trail) requires REVOKEing UPDATE/DELETE/TRUNCATE from
the app role, and that only binds when the app role is **not the table
owner**.

### The default single-role deploy is convention-only

In the default deploy, `DB_USER` applies `schema.sql` and so owns all
tables. Owners bypass GRANT/REVOKE on their own tables, so REVOKE from the
owner is a no-op. The entrypoint prints a notice when
`DATABASE_SUPERUSER_URL` is not set. `scripts/check_audit_grants.py`
reports the real state:

```bash
python -m scripts.check_audit_grants            # informational
python -m scripts.check_audit_grants --strict   # exit 1 if mutable
```

### Enforcing immutability (two-role deploy)

1. Create a dedicated non-owner app role (e.g. `scarletai_app`) and grant
   it the CRUD privileges it needs on the business tables.
2. Apply `schema.sql` as a superuser/owner (so the owner, not the app
   role, owns the tables).
3. Run the hardening script as a superuser:
   ```bash
   psql "$DATABASE_SUPERUSER_URL" -v app_role=scarletai_app \
       -f scripts/harden_audit.sql
   ```
   This REVOKEs UPDATE/DELETE/TRUNCATE on `audit_logs` and `audit_log`
   from the app role (and PUBLIC) and grants INSERT/SELECT.
4. Point the app at the restricted role (`DB_USER=scarletai_app` + its
   password) and set `DATABASE_SUPERUSER_URL` so the entrypoint re-applies
   the hardening on every boot.
5. Verify: `python -m scripts.check_audit_grants --strict` exits 0.

**Retention interaction:** the retention job deletes old `audit_logs` rows.
Once you REVOKE DELETE from the app role, the retention job can no longer
prune `audit_logs` and will log `retention_sweep_failed` for that table
(result sentinel `-2`) — it never crashes. In a hardened deploy, prune
`audit_logs` past `AUDIT_RETENTION_DAYS` with a separate superuser-owned
cron job instead.

## Monitoring Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Liveness + readiness (checks DB and Ollama) |
| `/api/v1/metrics` | GET | Prometheus-format metrics (P3.3): HTTP request/latency by method+path-class, ingest accepted, writer buffer depth + backpressure, DB pool, correlation run duration, retention sweep results. Auth: `METRICS_BEARER_TOKEN` or analyst JWT; unset token → localhost-only unauthenticated scrape. |
| `/docs` | GET | Swagger UI (auto-generated by FastAPI) |
| `/redoc` | GET | ReDoc documentation (auto-generated) |
| `/api/v1/ai/status` | GET | AI subsystem status: model provenance, cost rollup, prompt versions, calibration metrics |
| `/api/v1/audit/requests` | GET | Query the DB-backed audit log (admin only) |
| `/api/v1/auth/me` | GET | Current user info from JWT |
| `/api/v1/auth/change-password` | POST | Change own password |

## Data Retention (P1-D)

Without retention, `logs`, `alerts`, `audit_logs`, `correlation_matches` and
`ai_usage` grow without bound and query performance collapses. The retention
job (`src/services/retention.py`) runs on an APScheduler every
`RETENTION_INTERVAL_HOURS` (default 1) and deletes rows older than the
configured window in **batched parameterized DELETEs** (CTE + LIMIT +
`FOR UPDATE SKIP LOCKED`, `RETENTION_BATCH_SIZE` rows per iteration) so a
large delete never takes a long table lock. A backlog drains across several
runs (capped at 100 batches per table per run).

| Variable | Default | Description |
|----------|---------|-------------|
| `LOGS_RETENTION_DAYS` | 30 | Days to keep raw logs. 0 = keep forever. |
| `ALERTS_RETENTION_DAYS` | 180 | Days to keep alerts. 0 = keep forever. |
| `AUDIT_RETENTION_DAYS` | 365 | Days to keep both `audit_logs` (HTTP) and `audit_log` (action). 0 = keep forever. |
| `CORRELATION_RETENTION_DAYS` | 90 | Days to keep `correlation_matches`. |
| `AI_USAGE_RETENTION_DAYS` | 90 | Days to keep `ai_usage` cost-tracking rows. |
| `RETENTION_INTERVAL_HOURS` | 1 | How often the retention job runs. |
| `RETENTION_BATCH_SIZE` | 5000 | Rows deleted per batch iteration. |

**Audit + append-only hardening interaction:** if you apply the audit
append-only hardening (`scripts/harden_audit.sql` revokes `DELETE` on
`audit_logs` from the app role), the app role can no longer delete old
`audit_logs` rows and the retention job will log `retention_sweep_failed`
for that table (result sentinel `-2`) rather than crash. In that case, run a
separate superuser-owned cron job to prune `audit_logs` past
`AUDIT_RETENTION_DAYS`. The job reports the outcome honestly in its log.

**Scale upgrade:** for very high ingest, switch to TimescaleDB hypertables
(`logs`, `siem_health`) and use a `drop_chunks` retention policy instead of
this job — see the note in `src/db/schema.sql`. TimescaleDB compression then
supersedes the BRIN index too.

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
    "model": "mistral:7b",
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
- **Migration errors**: The schema is `src/db/schema.sql`, applied idempotently — re-run `psql "$(python -c 'from src.config.settings import settings; print(settings.database_url)')" -f src/db/schema.sql` (the DSN is derived from `DB_*` parts; there is no `DATABASE_URL` env var). There is no Alembic chain.

### Ollama Connection Issues

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Pull the default model
ollama pull mistral:7b
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
# The admin password is written to data/admin_initial_password (chmod 600)
# on first boot and echoed to stdout once. It is NOT re-printed later.
cat data/admin_initial_password   # the first-boot copy, if still present

# Preferred reset path — the admin user-management API (Phase 3.1).
# Log in as another admin (or use the API bearer token) and reset:
curl -X POST http://localhost:8000/api/v1/users/1/reset-password \
  -H "Authorization: Bearer $ADMIN_JWT"
# → returns a one-time temporary_password; the user is forced to change it
#   on first login (must_change_password=true). Existing sessions are
#   revoked immediately. Never reset via raw SQL — it bypasses hashing and
#   the revoke marker.

# If the ONLY admin is locked out (not merely forgotten), clear the lockout:
psql -h localhost -p 5433 -U scarletai -d scarletai -c \
  "UPDATE siem_users SET failed_login_attempts = 0, locked_until = NULL WHERE username = 'admin';"

# Force-invalidate all JWTs (rotates the secret)
redis-cli FLUSHDB
```

### seed-admin endpoint

`POST /auth/seed-admin` is a **dev-only** localhost bootstrap that creates an
admin with the known weak password `admin` (must_change_password=true). It is
gated behind `SEED_ADMIN_ENABLED` (default **false**); when disabled the
endpoint returns 404 so it is not a second weak-password bootstrap path in
production. Production bootstrap is the Docker entrypoint above (random
password → `data/admin_initial_password`). Enable `SEED_ADMIN_ENABLED=true`
only for local first-run setup without Docker.

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
