# SecurityScarletAI

**AI-Native SIEM for macOS** — Real-time log ingestion, Sigma-based detection, ML-powered alert triage, and LLM-driven investigation assistance.

> **Status (verified 2026-09-04, local-production release):** CI green on `main` · 1683 unit tests passing (mocked DB) · 5 integration tests (skipped — need live Postgres/Redis/Ollama) · 87% coverage (CI-enforced ≥80%) · 100 Sigma rules · 7 correlation rules · 7 sequence patterns · admin user-management API + Prometheus `/metrics` · OWASP LLM Top-10 red-team regression suite (41 probes — verified by collection) · **runs as a real local-production SIEM**: real osqueryd host telemetry → Sigma → alerts, loopback-only publishing, authenticated Redis, DB-enforced append-only audit trail (two-role deploy), verified backups + restore test, edge-triggered watchdog (see docs/PRODUCTION.md) · CI dependency/image scanning (image scan enforcing-green at zero findings; dependency audit advisory — 2 documented risk-accepts). Counts are hand-verified against the code; no auto-updating badge.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python)]()
[![License](https://img.shields.io/badge/license-MIT-yellow)]()

---

## Architecture

```
 Logs ──▶ Parser ──▶ Enrichment ──▶ Detection ──▶ Alerts ──▶ AI Triage ──▶ Dashboard
               │                            │                              │
          ECS Normalize              100 Sigma Rules                LLM Explanation
          GeoIP + DNS               Correlation Engine              NL→SQL Queries
          Threat Intel              Sequence Detection              Hunt Suggestions
                              │                                        │
                        Threat Intel ◀───────▶ Cases & Lessons Learned
```

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Ingestion** | FastAPI + asyncpg | High-throughput log collection (osquery tail via the FileShipper, HTTP API), fire-and-forget enrichment, rate-limited per IP |
| **Storage** | PostgreSQL 17 + Redis 7 | Time-series logs, alerts, cases, correlation matches, AI usage + cost tracking; Redis for rate-limit state and JWT blocklist |
| **Detection** | Legacy Sigma parser + custom PostgreSQL backend | 100 Sigma rules → parameterized SQL, 7-rule correlation engine with event-driven `as_of` semantics, 7 sequence patterns (exposed via `/correlation/sequences`). The pySigma backend is retained as a unit-tested module but is **off the production path** (P0-04). |
| **Enrichment** | GeoIP2 + DNS + Threat Intel | MaxMind GeoIP (with periodic retry), AbuseIPDB, OTX, URLhaus, severity boost on TI match |
| **AI / ML** | Ollama + sklearn | NL→SQL (7-layer safety), calibrated Random Forest triage with provenance, Isolation Forest UEBA, hunting assistant, versioned prompt templates, per-call cost tracking |
| **Dashboard** | Streamlit + WebSocket | Real-time alerts, cases, hunting, AI chat; JWT or service-to-service bearer auth |
| **Response** | Notifications + Cases | Slack alert notifications (`send_alert_notification`); case management CRUD. Email and macOS pf-firewall response were removed as unwired dead code (P2-21/P2-28). |
| **Audit** | DB-backed middleware | Every state-changing HTTP request written to `audit_logs`; permission-hardened table |

---

## Features

- **100 Sigma Detection Rules** — Authentication, process, network, file, macOS, and cloud categories with MITRE ATT&CK mapping
- **Event-Driven Correlation Engine** — 7 correlation rules (brute force → success, payload → C2, persistence, exfiltration, privilege escalation, credential theft + exfil, defense evasion) with `as_of` time binding (no `NOW()` in queries) and persistent `correlation_matches` table
- **ML Alert Triage** — 11-feature CalibratedClassifierCV with StratifiedKFold cross-validation, full provenance persisted to `triage_model_provenance` (run_id, model_type, source_csv, n_samples, precision/recall/f1, model_path, run_metadata); auto-trains hourly when ≥100 resolved alerts exist (1-hour cooldown)
- **Versioned Prompt Templates** — Jinja2 templates in `src/ai/prompts.py` with explicit `prompt_version` constants, surfaced in `LLMResult.prompt_version`
- **Per-Call AI Cost Tracking** — `src/ai/cost_tracker.py` records tokens, latency, model, prompt_version to `ai_usage` table on every LLM call
- **Natural Language → SQL** — Ask questions in plain English, get safe parameterized SQL with 7-layer injection defense
- **UEBA Behavioral Baselines** — Isolation Forest anomaly detection with per-user behavioral fingerprinting
- **AI Alert Explanation** — LLM-powered explanations with structured `LLMResult` contract and template fallback when Ollama is unavailable
- **Threat Hunting Assistant** — 7 pre-built hunt templates, MITRE gap analysis, and hunt-from-alert
- **Threat Intel Integration** — AbuseIPDB, OTX AlienVault, URLhaus with IOC caching, auto-refresh, and honest feed-status reporting (not just "key configured")
- **Risk Scoring Engine** — Multi-factor scoring: severity, threat intel match, UEBA anomaly (asset criticality was a never-wired placeholder and has been removed — see `src/ai/risk_scoring.py`)
- **Case Management** — Full CRUD with assignments, notes, status tracking, and lessons learned
- **JWT Auth with Hardening** — `jti` (UUID4) per token, refresh token rotation (7-day TTL), Redis-backed logout blocklist, password-change invalidation, `SecretStr` for secrets
- **Redis Rate Limiting** — Per-endpoint overrides (`/auth/login` 5/min, `/ingest` 100/min) with custom 429 handler, `X-RateLimit-*` headers, fail-open to in-memory on Redis outage
- **DB-Backed Audit Logs** — `AuditLogMiddleware` writes one row per state-changing HTTP request to `audit_logs`. Append-only **by convention** in a single-role deploy (the app only INSERTs/SELECTs audit tables); **DB-enforced** (`REVOKE UPDATE,DELETE,TRUNCATE`) via the two-role deploy — the reference local-production deployment runs this enforced posture (owner applies schema, restricted `scarletai_app` role runs the API, hardening re-applied every boot) — see `docs/PRODUCTION.md` §4 and `docs/DEPLOYMENT.md` → Audit immutability.
- **Real-time Dashboard** — Streamlit with WebSocket live updates, auto-refresh, and toast notifications; two auth modes (JWT or `DASHBOARD_API_TOKEN` service bearer)
- **Slack Alert Notifications** — automated Slack notifications on new alerts via `send_alert_notification` (email and macOS pf-firewall response were removed as unwired dead code)
- **Docker Bootstrap** — Idempotent `entrypoint.sh` waits for Postgres, applies schema (owner DSN in the two-role deploy), replays the dead-letter queue, optionally seeds demo data (only with `DEMO_SEED_ENABLED=true`), trains models when missing, creates the admin, execs uvicorn

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI + Uvicorn |
| Database | PostgreSQL 17 (asyncpg) |
| Cache / Rate Limit | Redis 7 |
| Migrations | `src/db/schema.sql` (idempotent, append-only) |
| AI/ML | Ollama (LLM), scikit-learn, joblib, Jinja2 |
| Dashboard | Streamlit + streamlit-autorefresh |
| Detection | Legacy Sigma parser (pySigma backend retained off-path) |
| Networking | httpx, websockets |
| Auth | JWT (python-jose) + bcrypt + Redis blocklist |
| Geolocation | MaxMind GeoIP2 |
| Containerization | Docker Compose |
| Testing | pytest, pytest-asyncio, hypothesis |
| Linting | ruff, mypy |

---

## Quick Start

```bash
# 1. Clone and enter the project
git clone https://github.com/aiagentmackenzie-lang/securityscarletai.git
cd securityscarletai

# 2. Configure environment
cp .env.example .env
# Edit .env — set DB_PASSWORD, API_SECRET_KEY, API_BEARER_TOKEN
# Generate secrets: openssl rand -base64 32  (DB_PASSWORD)
#                   openssl rand -hex 64    (API_SECRET_KEY)
#                   openssl rand -hex 32    (API_BEARER_TOKEN)
# Optional: DASHBOARD_API_TOKEN for headless dashboard access.
# Demo data is opt-in (2026-09-01): add DEMO_SEED_ENABLED=true to .env on demo
# hosts BEFORE the first boot — production boots stay empty (see docs/DEMO.md).

# 3. Start the full stack (Postgres + Redis + API + dashboard)
docker compose up -d
# The idempotent entrypoint.sh will:
#   - wait for Postgres to be ready
#   - apply the canonical schema (src/db/schema.sql)
#   - seed demo data ONLY when DEMO_SEED_ENABLED=true (opt-in)
#   - train the triage/UEBA models when missing
#   - create the admin user (random password written to data/admin_initial_password,
#     chmod 600, printed to stdout once on first boot)
#   - start uvicorn
#
# LOCAL PRODUCTION posture (loopback-only publishing, authenticated Redis,
# DB-enforced audit trail, enforced password pepper):
#   docker compose -f docker-compose.yml -f docker-compose.local-prod.yml up -d
#   — requires REDIS_PASSWORD + PASSWORD_PEPPER in .env (docs/PRODUCTION.md)

# 4. (Dev only) Or run the API outside Docker:
poetry install
# Apply the canonical schema (src/db/schema.sql — Alembic was removed). The DSN
# is DERIVED from DB_* parts; there is NO DATABASE_URL env var (setting one is
# a stale-DSN footgun — see .env.example):
psql "$(poetry run python -c 'from src.config.settings import settings; print(settings.database_url)')" -f src/db/schema.sql
poetry run uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# 5. (Dev only) Start the dashboard outside Docker:
poetry run streamlit run dashboard/main.py --server.port 8501
```

**Running a demo of the project?** Follow [docs/DEMO.md](docs/DEMO.md) — the
full spin-up sequence including the demo-data freshness step (`make
demo-refresh`) that keeps seeded data inside the dashboard's time windows.

Verify it's running:
```bash
curl http://localhost:8000/api/v1/health
# Returns:
# {
#   "status": "healthy",
#   "checks": {"api": "ok", "database": "ok", "ollama": "ok|error|unreachable"},
#   "ollama_status": "healthy|degraded|unavailable",
#   "ollama": {"ollama_status": "healthy|degraded|unavailable", "model": "<name>|null", "error": "<msg>|null"}
# }
```

## Live Telemetry Demo (osquery → detection → alert)

The default deployment seeds synthetic data so the dashboard looks alive. To see
the SIEM ingest a **real log source** and fire detection live, enable the
ingestion shipper — it tails an osquery results log and feeds the detection
scheduler:

```bash
# One-command demo: starts Postgres, applies the schema, starts the API with
# ENABLE_INGESTION_SHIPPER=true, writes osquery events (benign + a reverse-shell
# that matches rules/sigma/process/reverse_shell.yml), and waits for the
# scheduler to tick (~70s, real run_interval) before printing the fired alert.
./scripts/run_osquery_demo.sh

# Or emit events manually into a tailed log:
poetry run python3 scripts/generate_osquery_events.py --path /tmp/osqueryd.results.log
```

What's wired: `osquery log → FileShipper (tail, checkpointed) → parser (ECS) →
LogWriter → Postgres → Sigma detection scheduler → alerts`. The shipper is OFF
by default (`enable_ingestion_shipper=false`) so existing deployments and CI are
unaffected; enable it in `.env` (`ENABLE_INGESTION_SHIPPER=true`) or pass it as
an env var as the demo script does.

> **Local production (real host telemetry, not synthetic):** for the standing
> in-house deployment — a real osqueryd LaunchAgent on this Mac feeding the
> shipper continuously, secrets posture, and the demo↔production mode split —
> see [`docs/PRODUCTION.md`](docs/PRODUCTION.md). Verified live 2026-09-04:
> real osqueryd → shipper → Postgres → critical Sigma alert within one
> scheduler tick.

---

## API Documentation

Interactive API docs are available at (when `DOCS_ENABLED=true` — the default
for dev; **local production and the internet prod overlay set it to `false`,
so these return 404 there by design**):

- **Swagger UI**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **ReDoc**: [http://localhost:8000/api/redoc](http://localhost:8000/api/redoc)

Key endpoints (all under `/api/v1`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (API, DB, rich Ollama status block) |
| `/metrics` | GET | Prometheus metrics (scrape token or analyst role) |
| `/ingest` | POST | Ingest log events (rate-limited 100/min/IP; bearer token required) |
| `/alerts` | GET | List alerts with filtering and pagination |
| `/correlation/rules` | GET | List all 7 correlation rules |
| `/correlation/run` | POST | Run all correlation rules with `as_of` time binding + `persist` flag |
| `/correlation/run/{rule_name}` | POST | Run a single correlation rule |
| `/correlation/matches` | GET | List persisted correlation matches with filters |
| `/correlation/matches/{id}/seen` | POST | Mark a match as seen |
| `/ai/status` | GET | AI health, triage cv_accuracy/calibrated/features, UEBA status |
| `/ai/train` | POST | Train the ML triage model |
| `/ai/triage/{alert_id}` | POST | Get ML triage classification for an alert |
| `/ai/explain/{alert_id}` | POST | Get LLM explanation for an alert |
| `/ai/ueba/{user_name}` | GET | UEBA anomaly score for a user |
| `/query` | POST | Natural language → SQL query |
| `/ai/chat` | POST | AI chat assistant |
| `/hunt/templates` | GET | List pre-built hunt templates |
| `/hunt/{hunt_id}/execute` | POST | Execute a hunt template (analyst) |
| `/hunt/gaps` | GET | MITRE ATT&CK gap analysis |
| `/hunt/from-alert/{alert_id}` | POST | Suggest hunts from an alert (analyst) |
| `/threat-intel/stats` | GET | Threat intel cache + per-feed health (ok/error/no_key/never_refreshed) |
| `/threat-intel/refresh` | POST | Force-refresh threat intel feeds |
| `/threat-intel/lookup/ip/{ip}` | GET | Lookup IP against all feeds |
| `/audit/requests` | GET | Query HTTP request audit log (DB-backed) |
| `/users` | GET | List users (admin; never password_hash) |
| `/users` | POST | Create user (admin; must_change_password=true) |
| `/users/{id}` | PATCH | Role change / activate-deactivate (admin; sets user_revoke marker) |
| `/users/{id}/reset-password` | POST | One-time random password (admin; returned once, never logged) |
| `/auth/login` | POST | Login (rate-limited 5/min/IP) |
| `/auth/me` | GET | Current user info |
| `/auth/change-password` | POST | Change password (invalidates all sessions) |
| `/cases` | GET/POST | Case management CRUD |
| `/rules` | GET | List Sigma detection rules |

---

## Detection Rules

See [docs/RULES.md](docs/RULES.md) for the complete reference of all 100 Sigma rules and 7 correlation rules, organized by category with MITRE ATT&CK mappings.

---

## AI Features

See [docs/AI.md](docs/AI.md) for detailed documentation on:
- `LLMResult` contract — uniform return shape across `query_llm()`, `chat()`, `explain_alert()`
- Versioned Jinja2 prompt templates (`src/ai/prompts.py`)
- Per-call cost tracking (`src/ai/cost_tracker.py` → `ai_usage` table)
- Event-driven correlation with `as_of` time binding (no `NOW()` in queries)
- ML-powered alert triage with CalibratedClassifierCV + provenance
- UEBA behavioral baselines with Isolation Forest
- LLM alert explanation with template fallback
- Threat hunting assistant
- Risk scoring engine
- Validation of Ollama model availability via `validate_ollama_model()`

---

## Event Enrichment

Every ingested event flows through a fire-and-forget enrichment pipeline.
The HTTP `/ingest` endpoint returns 202 Accepted as
soon as the batch is queued in the writer; enrichment runs as a
background `asyncio.create_task` and never blocks ingestion.

Enrichments applied (in order):
1. **GeoIP** — country, city, lat/lon for public IPs (MaxMind GeoLite2-City).
2. **DNS reverse** — PTR record for public IPs.
3. **Threat Intel** — match against the cached IOC database (AbuseIPDB,
   OTX, URLhaus); hits boost the event severity.
4. **Severity boost** — high-confidence threat-intel matches set a
   `severity_boost` recommendation (`critical`/`high`/`medium`) on the event's
   enrichment dict for downstream consumers (it does not rewrite the event's own
   severity).

### GeoIP singleton + lazy retry

The GeoIP reader is a lazy singleton (`_get_geoip_reader`). Init is attempted on
the first enrich call and re-attempted at most once per 60s if it failed, so a
missing `.mmdb` neither permanently disables GeoIP for the process lifetime
nor thrashes the FS on every call. `_geoip_loaded` is only set `True` after a
successful `Reader()` open. The reader handle is closed on shutdown via
`close_geoip_reader()` in the lifespan (P2-12) — there is no background retry
loop.

### Correlation trigger

The ingest path also fires `run_all_correlations(persist=True)`
as a background task, so a single batch of events can produce new
alerts without a separate correlation sweep. The call is fire-and-forget:
correlation errors are logged but never block the HTTP response.

### Honest threat-intel stats

`GET /api/v1/threat-intel/stats` now reports real feed health instead
of "is the key set?":

```json
{
  "feed_status": {
    "abuseipdb": "ok" | "error" | "no_key" | "never_refreshed",
    "otx":       "ok" | "error" | "no_key" | "never_refreshed",
    "urlhaus":   "ok"
  },
  "feed_keys": {
    "abuseipdb": true,
    "otx":       true,
    "urlhaus":   true
  }
}
```

`feed_status` reflects the *last refresh attempt's outcome*. `feed_keys`
is the legacy "do we have a key configured" view, kept for ops who
only care about config presence.

---

## Dashboard

A Streamlit dashboard is included in the repo (`dashboard/`) and
shipped as a `dashboard` service in `docker-compose.yml`.

### Running it

```bash
# With docker-compose (recommended)
docker compose up -d dashboard
open http://localhost:8501

# Or directly (for dev)
poetry run streamlit run dashboard/main.py
```

The dashboard container depends on the `api` service being healthy
(uses its healthcheck), so it won't start until the API is reachable
on `http://api:8000`.

### Auth

The dashboard supports two auth flows:

1. **Interactive JWT login** (default). Visit `http://localhost:8501`,
   enter username/password. In a Docker deploy the entrypoint creates the
   first admin with a random password written to `data/admin_initial_password`
   (chmod 600, printed to stdout once on first boot). Without Docker, the
   dev-only `POST /auth/seed-admin` endpoint (gated by `SEED_ADMIN_ENABLED=true`,
   off by default) creates an admin with the known weak password `admin`
   (must_change_password=true). The JWT is stored in `st.session_state`.

2. **Service-to-service bearer** (headless / docker). Set
   `DASHBOARD_API_TOKEN` in `.env` to a valid API token (typically
   the same value as `API_BEARER_TOKEN`). The dashboard will use
   this as a fallback `Authorization: Bearer ...` header on every
   API call when no user JWT is in the session. Useful for:
   - Headless / automated dashboard access
   - Screenshot capture tools
   - Pre-authenticated demos

The API's unified auth dependency accepts either form, so the
dashboard works with both.

### Dashboard views

| View | File | Purpose |
|------|------|---------|
| Alerts | `dashboard/alerts_view.py` | Triage queue, bulk operations, severity filtering |
| Cases | `dashboard/cases_view.py` | Case management, alert linking, notes |
| Logs | `dashboard/logs_view.py` | Recent events, host/category filtering |
| Hunt | `dashboard/hunt_view.py` | MITRE ATT&CK hunt templates, gap analysis |
| Rules | `dashboard/rules_view.py` | Detection rule CRUD (admin only) |
| AI Chat | `dashboard/ai_chat_view.py` | NL threat-hunting assistant |
| Charts | `dashboard/charts.py` | Time-series visualisations |

All views go through `dashboard/api_client.py` — no direct database
access from the dashboard.

---

## Testing

```bash
# Run the full unit suite (1683 tests, mocked DB, ~30s)
poetry run pytest tests/unit/ -q --no-cov

# With coverage report (gate: 80%; currently 87%)
poetry run pytest tests/unit/ --cov=src --cov-report=term-missing -q

# Integration tests (require a live PostgreSQL with the schema applied)
RUN_INTEGRATION_TESTS=1 poetry run pytest tests/integration/ -v

# Lint
poetry run ruff check src/ dashboard/

# Type check
poetry run mypy src/
```

CI (`.github/workflows/ci.yml`) runs on every push to `main` and on pull
requests:
it builds the Docker image, runs ruff + mypy, applies `schema.sql` to a
provisioned Postgres 17 with `ON_ERROR_STOP=1`, runs the unit suite with the
coverage gate, boots the real entrypoint against a live Postgres (boot gate),
and scans the image with Trivy (HIGH/CRITICAL, zero-findings enforcement
pending the Sep 16 flip).

## Security

- **Auth**: JWT (python-jose) with bcrypt password hashing. Every token carries
  a unique `jti` (UUID4); logout adds it to a Redis blocklist. Password changes
  increment a per-user `user_revoke` marker that invalidates all outstanding
  tokens. Secrets are stored as Pydantic `SecretStr` (never logged).
- **Rate limiting**: slowapi + Redis. `/auth/login` 5/min/IP, `/ingest` 100/min/IP,
  default 200/min/IP. Falls back to in-memory storage if Redis is unreachable
  (with a startup warning). Custom 429 JSON handler emits `Retry-After` and
  `X-RateLimit-*` headers.
- **Audit**: `AuditLogMiddleware` writes one row to `audit_logs` for every
  state-changing HTTP request. The `audit_logs` table is append-only **by
  convention** in a single-role deploy. DB-enforced immutability is
  available via the two-role deploy — a superuser applies
  `scripts/harden_audit.sql` to `REVOKE UPDATE,DELETE,TRUNCATE` from the app
  role, and the app runs as a non-owner role so the REVOKE actually binds:
  ```sql
  REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM scarletai_app;
  GRANT  INSERT, SELECT            ON audit_logs TO   scarletai_app;
  ```
  `scripts/check_audit_grants.py --strict` verifies it. The default
  single-role deploy (app role = table owner) is convention-only; **the
  reference local-production deployment runs the enforced two-role posture**
  (verified: tamper UPDATE/DELETE/TRUNCATE all denied at the DB level,
  `--strict` exit 0) — see `docs/PRODUCTION.md` §4 and
  `docs/DEPLOYMENT.md` → Audit immutability.
- **SQL safety**: All user-supplied values flow through parameterized queries
  (`$1`, `$2`, …) — no string interpolation in SQL. NL→SQL pipeline has
  7 layers of injection defense. `correlation.py` uses `as_of: $1::timestamptz`
  for every time predicate (no `NOW()` in query strings).
- **Dashboard XSS / output escaping**: every value that originates from API
  data — alert fields, host names, case titles/notes/assignments, usernames —
  is treated as **untrusted** in the dashboard. Any such value rendered inside
  `st.markdown(..., unsafe_allow_html=True)` passes through the esc()
  helper at either the interpolation site or the component choke point
  (`charts._colored_metric`, `ui_utils.badge`/`colored_metric`,
  `cases_view._note_card_html`). Host names are ingestion-fed (external
  attacker-writable via `/ingest`), so this is an external-path defense, not
  just insider hygiene. Regression tests: `tests/unit/test_dashboard_esc_sweep.py`.
- **Secret hygiene**: `.env` is gitignored. `.env.example` documents how to
  generate strong secrets with `openssl rand`. Local secret rotation is
  documented in `scripts/entrypoint.sh`; git history rewrite (`filter-repo` /
  BFG) is **deliberately deferred** — see git log for the original
  decision (Option B: local-dev-only credentials, cost/benefit of
  history rewrite not justified).
- **Dashboard auth**: Two modes — interactive JWT login (default) or
  `DASHBOARD_API_TOKEN` service-to-service bearer (set in `.env`). The API's
  unified auth dependency accepts either form. `DASHBOARD_API_TOKEN` grants
  **admin** API access and makes the dashboard skip its login screen, so it
  must NEVER be exposed unauthenticated with the token set — gate it behind
  Caddy `basicauth` / an identity-aware proxy / an IP allowlist, or leave the
  token empty (the prod overlay default) to force JWT login. See
  `docs/DEPLOYMENT.md` → Dashboard exposure.

---



## Limitations (honest)

Deliberate constraints, written down instead of hidden:

- **Single uvicorn worker.** The WS-token store and the connection registry
  are in-memory — scaling to multiple workers requires moving both to Redis
  first (documented scale boundary; do NOT just raise `--workers`).
- **Audit immutability is convention-only in the single-role default.**
  DB-enforced (REVOKE-based) immutability requires the two-role deploy in
  `scripts/harden_audit.sql`; single-role deploys can't bind it. The shipped
  `docker-compose.local-prod.yml` posture runs the enforced two-role deploy
  (see docs/PRODUCTION.md §4) — the limitation is about the bare `docker
  compose up` default, not the reference deployment.
- **JWT library** is `python-jose 3.5.0` (clears known CVEs, but the project
  is unmaintained) — tracked as backlog F-25 (PyJWT migration; the internal
  migration notes are not part of the repo).
- **Dashboard logout is meaningful for 15 minutes.** Access-token TTL is
  short by design (server-side logout blocklists the token); the dashboard
  does not currently auto-rotate via the refresh endpoint, so long sessions
  re-login after ~15 minutes (UX trade-off for tighter blast radius).
- **LLM trust boundary status (verified in code):** untrusted log data is
  data-fenced before prompts (`src/ai/untrusted.py`; LLM01) and `/ai/*` +
  `/query` carry a per-user quota (LLM10, 30/5min default). These are
  soft+structural defenses — an LLM is still a probabilistic component;
  treat AI output as unverified (the UI labels it as such).

## Deployment

See [docs/PRODUCTION.md](docs/PRODUCTION.md) for the **local production** path
(single-host, in-house: real osquery telemetry, loopback-only publishing,
authenticated Redis, two-role audit hardening, backups + watchdog) — this is
the posture the reference deployment runs.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the internet-exposed
production path (Caddy + automatic TLS) including:
- Docker Compose configuration
- Environment variables
- Database migrations
- Security hardening checklist
- Backup & recovery

**Air-gapped / no-egress:** SecurityScarletAI is self-hostable and air-gappable
— local Ollama, no external threat-intel calls, offline Sigma corpus, no
telemetry. See [docs/AIR-GAPPED.md](docs/AIR-GAPPED.md) for the
enterprise / regulated / sovereign scenario (the differentiator vs. SaaS
SIEMs that require constant cloud connectivity).

---

## Project Structure

```
securityscarletai/
├── src/
│   ├── api/                 # FastAPI routers + middleware (17 routers)
│   │   ├── main.py          # App config, CORS, lifespan, middleware stack
│   │   ├── health.py        # /health with rich Ollama status block
│   │   ├── ingest.py        # /ingest (rate-limited, 202 Accepted, fire-and-forget enrichment)
│   │   ├── alerts.py        # Alert CRUD, export, suppressions
│   │   ├── cases.py         # Case management
│   │   ├── ai.py            # /ai/status, /ai/train, /ai/triage, /ai/explain, /ai/ueba
│   │   ├── chat.py          # /ai/chat AI chat endpoint
│   │   ├── hunt.py          # /hunt/templates, /hunt/gaps, /hunt/{id}/execute, /hunt/from-alert
│   │   ├── query.py         # /query NL→SQL
│   │   ├── correlation.py   # /correlation/rules, /run, /matches, /sequences
│   │   ├── threat_intel.py  # /threat-intel/stats|refresh|lookup
│   │   ├── audit.py         # /audit/requests (DB-backed audit log query)
│   │   ├── auth.py          # JWT helpers, RBAC, password hashing, jti, refresh
│   │   ├── auth_login.py    # /auth/login, /auth/me, /auth/change-password
│   │   ├── login_lockout.py # Account lockout on failed logins
│   │   ├── users.py         # /users admin user-management API
│   │   ├── metrics.py       # /metrics Prometheus endpoint (scrape token)
│   │   ├── rules.py         # /rules Sigma rule listing
│   │   ├── logs.py          # /logs raw event query
│   │   ├── websocket.py     # WebSocket live alert feed
│   │   ├── middleware.py    # AuditLogMiddleware, RequestValidationMiddleware
│   │   ├── rate_limit.py    # slowapi Limiter, per-endpoint overrides, 429 handler
│   │   └── redis_client.py  # Lazy-init Redis with fail-open
│   ├── ai/                  # AI/ML module
│   │   ├── nl2sql.py        # Natural language → SQL (7-layer safety)
│   │   ├── alert_triage.py  # CalibratedClassifierCV triage + provenance
│   │   ├── alert_explanation.py  # LLM + template fallback (LLMResult contract)
│   │   ├── hunting_assistant.py  # Hunt templates + MITRE gaps
│   │   ├── risk_scoring.py  # Multi-factor risk scoring
│   │   ├── ueba.py          # Isolation Forest UEBA
│   │   ├── chat.py          # AI chat
│   │   ├── untrusted.py     # LLM01 data-fencing for untrusted log data
│   │   ├── ollama_client.py # Ollama LLM + validate_ollama_model() + LLMResult
│   │   ├── prompts.py       # Versioned Jinja2 prompt templates
│   │   ├── cost_tracker.py  # Per-call cost + latency → ai_usage
│   │   └── utils.py         # Shared helpers
│   ├── detection/           # Detection engine
│   │   ├── sigma.py         # Legacy SigmaParser + parameterized SQL (pySigma backend retained off-path)
│   │   ├── correlation.py   # 7 correlation rules (as_of, persist)
│   │   ├── sequences.py     # 7 event sequence patterns (exposed via /correlation/sequences)
│   │   ├── alerts.py        # Alert lifecycle management
│   │   ├── scheduler.py     # Rule scheduler + hourly auto-train check
│   │   ├── mitre.py         # MITRE ATT&CK STIX cache + gap analysis
│   │   ├── ai_analyzer.py   # Per-alert AI analysis (called by scheduler)
│   │   └── backends/        # pySigma PostgreSQL backend (unit-tested, off production path)
│   ├── enrichment/          # Event enrichment
│   │   └── pipeline.py      # GeoIP (lazy singleton + retry), DNS, Threat Intel
│   ├── intel/               # Threat intelligence
│   │   └── threat_intel.py  # AbuseIPDB, OTX, URLhaus clients
│   ├── ingestion/           # Log ingestion (osquery tail + ECS parsing)
│   │   ├── parser.py        # ECS normalization (OSQUERY_ECS_MAP — only mapped tables ingest)
│   │   ├── shipper.py       # File tailing (polling, checkpointed, persistent data/ checkpoint)
│   │   ├── schemas.py       # Pydantic NormalizedEvent model
│   │   └── runner.py        # maybe_create_shipper() — lifespan wiring
│   ├── response/            # Notifications
│   │   └── notifications.py # Slack alert notifications (send_alert_notification)
│   ├── services/
│   │   ├── writer.py        # Async batched writer + dead-letter queue
│   │   └── retention.py     # Bounded-storage retention job (hourly, batched deletes)
│   ├── config/              # Configuration
│   │   ├── settings.py      # Pydantic Settings (SecretStr for secrets)
│   │   └── logging.py       # Structured logging
│   └── db/                  # Database
│       ├── connection.py    # asyncpg pool (retry + backoff)
│       ├── writer.py        # Async batched writer + dead-letter queue
│       └── schema.sql       # Canonical schema (idempotent, append-only)
├── dashboard/               # Streamlit UI
│   ├── main.py              # Dashboard entry point
│   ├── alerts_view.py       # Alert browser
│   ├── suppressions_view.py # Alert suppressions management
│   ├── cases_view.py        # Case management
│   ├── hunt_view.py         # Hunting interface
│   ├── ai_chat_view.py      # AI chat
│   ├── rules_view.py        # Rule management
│   ├── logs_view.py         # Log viewer
│   ├── charts.py            # Visualization
│   ├── api_client.py        # HTTP client (JWT + DASHBOARD_API_TOKEN support)
│   ├── auth.py              # JWT auth (3 roles: admin/analyst/viewer)
│   └── ui_utils.py          # Shared UI helpers
├── rules/
│   └── sigma/               # 100 Sigma YAML rules (MITRE ATT&CK mapped)
│       ├── authentication/  # 14 rules
│       ├── process/         # 34 rules
│       ├── network/         # 17 rules
│       ├── file/            # 17 rules
│       ├── macOS/           # 12 rules
│       └── cloud/           # 6 rules
├── config/
│   └── osquery.conf         # Host telemetry schedule (verified against osquery 5.23.1)
├── deploy/
│   ├── Caddyfile                        # Internet-path reverse proxy (TLS)
│   ├── osqueryd.launchagent.plist.example # Real-telemetry LaunchAgent
│   ├── backup.launchagent.plist.example   # Nightly verified backup
│   └── watchdog.launchagent.plist.example # 5-min edge-triggered health watchdog
├── scripts/
│   ├── entrypoint.sh             # Idempotent Docker bootstrap (two-role aware)
│   ├── backup_local.sh           # Local backup + verify + rotate + audit prune + restore test
│   ├── health_watchdog.sh        # Edge-triggered health watchdog (Slack optional)
│   ├── check_audit_grants.py     # Audit append-only verification (--strict for gates)
│   ├── harden_audit.sql          # Two-role audit hardening (owner applies)
│   ├── replay_dead_letter.py     # Dead-letter queue replay (also runs at boot)
│   ├── refresh_demo_timestamps.py # make demo-refresh — slide synthetic data to now
│   ├── run_osquery_demo.sh       # Live telemetry demo (osquery -> shipper -> Sigma -> alert)
│   ├── generate_osquery_events.py # Emits osquery result-log lines for the demo
│   ├── generate_attack_data.py   # Synthetic attack fixtures
│   ├── generate_training_data.py # Synthetic alert generator for triage training
│   ├── seed_demo_data.py         # Seed demo alerts (opt-in via DEMO_SEED_ENABLED)
│   ├── seed_realistic_data.py    # Seed a realistic demo dataset
│   ├── migrate_passwords.py      # One-off password migration helper
│   ├── analyze_alerts.py         # Ad-hoc alert analysis helper
│   ├── validate_config.py        # Validate .env / settings
│   └── backup.sh                 # Reference pg_dump backup script (pgpass-based)
├── tests/                   # 1683 unit tests + 5 integration tests (skipped w/o live services)
├── docs/                    # PRODUCTION.md, DEMO.md, RULES.md, AI.md, DEPLOYMENT.md,
│                            # AIR-GAPPED.md, ATTACK-SCENARIOS.md, CHANGELOG.md
└── docker-compose.yml       # Postgres 17 + Redis 7 + API + dashboard
                            #   (+ docker-compose.local-prod.yml loopback overlay
                            #    + docker-compose.prod.yml internet/Caddy overlay)
```

## Screenshots

The dashboard is a Streamlit app (real-time alerts, cases, AI chat, hunting).
To capture screenshots for this section, run the stack locally and snapshot
the views you want to showcase:

```bash
docker compose up -d          # Postgres + Redis + API + dashboard
open http://localhost:8501     # dashboard (JWT login or DASHBOARD_API_TOKEN)
```

> _Replace this block with dashboard screenshots (alerts grid, AI triage
> explanation, MITRE heatmap, case timeline) once captured._

---

## Attack Simulation Walkthroughs

See [docs/ATTACK-SCENARIOS.md](docs/ATTACK-SCENARIOS.md) for 4 detailed walkthroughs:

1. **SSH Brute Force** — Detection → AI explanation → manual IP blocking
2. **Reverse Shell** — Process detection → alert triage → case creation
3. **Data Exfiltration** — Network detection → NL query → hunting
4. **Insider Privilege Escalation** — sudo + log deletion → defense-evasion correlation

---

## License

MIT — See [LICENSE](LICENSE) for details.