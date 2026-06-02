# SecurityScarletAI

**AI-Native SIEM for macOS** — Real-time log ingestion, Sigma-based detection, ML-powered alert triage, and LLM-driven investigation assistance.

[![Tests](https://img.shields.io/badge/tests-1237%20passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-82%25-green)]()
[![Rules](https://img.shields.io/badge/Sigma%20rules-45-blue)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python)]()
[![License](https://img.shields.io/badge/license-MIT-yellow)]()

---

## Architecture

```
 Logs ──▶ Parser ──▶ Enrichment ──▶ Detection ──▶ Alerts ──▶ AI Triage ──▶ Dashboard
               │                            │                              │
          ECS Normalize              45 Sigma Rules                LLM Explanation
          GeoIP + DNS               Correlation Engine              NL→SQL Queries
          Threat Intel              Sequence Detection              Hunt Suggestions
                              │                                        │
                        Threat Intel ◀───────▶ Cases & Lessons Learned
```

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Ingestion** | FastAPI + asyncpg | High-throughput log collection (osquery, syslog, API), fire-and-forget enrichment, rate-limited per IP |
| **Storage** | PostgreSQL 17 + Redis 7 | Time-series logs, alerts, cases, correlation matches, AI usage + cost tracking; Redis for rate-limit state and JWT blocklist |
| **Detection** | pySigma + custom backend | 45 Sigma rules → parameterized SQL, 7-rule correlation engine with event-driven `as_of` semantics, 7 sequence patterns |
| **Enrichment** | GeoIP2 + DNS + Threat Intel | MaxMind GeoIP (with periodic retry), AbuseIPDB, OTX, URLhaus, severity boost on TI match |
| **AI / ML** | Ollama + sklearn | NL→SQL (7-layer safety), calibrated Random Forest triage with provenance, Isolation Forest UEBA, hunting assistant, versioned prompt templates, per-call cost tracking |
| **Dashboard** | Streamlit + WebSocket | Real-time alerts, cases, hunting, AI chat; JWT or service-to-service bearer auth |
| **Response** | SOAR Lite | Slack/email notifications, pf firewall, case management |
| **Audit** | DB-backed middleware | Every state-changing HTTP request written to `audit_logs`; permission-hardened table |

---

## Features

- **45 Sigma Detection Rules** — Authentication, process, network, file, macOS, and cloud categories with MITRE ATT&CK mapping
- **Event-Driven Correlation Engine** — 7 correlation rules (brute force → success, payload → C2, persistence, exfiltration, privilege escalation, credential theft + exfil, defense evasion) with `as_of` time binding (no `NOW()` in queries) and persistent `correlation_matches` table
- **ML Alert Triage** — 11-feature CalibratedClassifierCV with StratifiedKFold cross-validation, full provenance persisted to `triage_model_provenance` (run_id, model_type, source_csv, n_samples, precision/recall/f1, model_path, run_metadata); auto-trains on >20% new labels or >7d stale
- **Versioned Prompt Templates** — Jinja2 templates in `src/ai/prompts.py` with explicit `prompt_version` constants, surfaced in `LLMResult.prompt_version`
- **Per-Call AI Cost Tracking** — `src/ai/cost_tracker.py` records tokens, latency, model, prompt_version to `ai_usage` table on every LLM call
- **Natural Language → SQL** — Ask questions in plain English, get safe parameterized SQL with 7-layer injection defense
- **UEBA Behavioral Baselines** — Isolation Forest anomaly detection with per-user behavioral fingerprinting
- **AI Alert Explanation** — LLM-powered explanations with structured `LLMResult` contract and template fallback when Ollama is unavailable
- **Threat Hunting Assistant** — 7 pre-built hunt templates, MITRE gap analysis, and hunt-from-alert
- **Threat Intel Integration** — AbuseIPDB, OTX AlienVault, URLhaus with IOC caching, auto-refresh, and honest feed-status reporting (not just "key configured")
- **Risk Scoring Engine** — Multi-factor scoring: severity, threat intel match, asset criticality, UEBA anomaly
- **Case Management** — Full CRUD with assignments, notes, status tracking, and lessons learned
- **JWT Auth with Hardening** — `jti` (UUID4) per token, refresh token rotation (7-day TTL), Redis-backed logout blocklist, password-change invalidation, `SecretStr` for secrets
- **Redis Rate Limiting** — Per-endpoint overrides (`/auth/login` 5/min, `/ingest` 100/min) with custom 429 handler, `X-RateLimit-*` headers, fail-open to in-memory on Redis outage
- **DB-Backed Audit Logs** — `AuditLogMiddleware` writes one row per state-changing HTTP request to `audit_logs` (append-only, with `REVOKE UPDATE,DELETE,TRUNCATE` hardening documented)
- **Real-time Dashboard** — Streamlit with WebSocket live updates, auto-refresh, and toast notifications; two auth modes (JWT or `DASHBOARD_API_TOKEN` service bearer)
- **SOAR Lite** — Automated Slack/email alerts and macOS pf firewall blocking
- **Docker Bootstrap** — Idempotent `entrypoint.sh` waits for Postgres, applies schema, seeds demo data, trains models, creates admin, execs uvicorn

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI + Uvicorn |
| Database | PostgreSQL 17 (asyncpg) |
| Cache / Rate Limit | Redis 7 |
| Migrations | Alembic |
| AI/ML | Ollama (LLM), scikit-learn, joblib, Jinja2 |
| Dashboard | Streamlit + streamlit-autorefresh |
| Detection | pySigma |
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

# 3. Start the full stack (Postgres + Redis + API + dashboard)
docker compose up -d
# The idempotent entrypoint.sh will:
#   - wait for Postgres to be ready
#   - apply alembic migrations and the canonical schema
#   - seed demo data and train the triage model
#   - create the admin user (password surfaced in `docker logs`)
#   - start uvicorn

# 4. (Dev only) Or run the API outside Docker:
poetry install
poetry run alembic upgrade head
poetry run uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# 5. (Dev only) Start the dashboard outside Docker:
poetry run streamlit run dashboard/main.py --server.port 8501
```

Verify it's running:
```bash
curl http://localhost:8000/api/v1/health
# Returns:
# {
#   "status": "healthy",
#   "checks": {"api": "ok", "database": "ok", "ollama": "ok|error|unreachable"},
#   "ollama": {"ollama_status": "healthy|degraded|unavailable", "model": "<name>|null", "error": "<msg>|null"}
# }
```

---

## API Documentation

Interactive API docs are available at:

- **Swagger UI**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **ReDoc**: [http://localhost:8000/api/redoc](http://localhost:8000/api/redoc)

Key endpoints (all under `/api/v1`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (API, DB, rich Ollama status block) |
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
| `/chat` | POST | AI chat assistant |
| `/hunt/suggestions` | GET | Get hunting suggestions |
| `/threat-intel/stats` | GET | Threat intel cache + per-feed health (ok/error/no_key/never_refreshed) |
| `/threat-intel/refresh` | POST | Force-refresh threat intel feeds |
| `/threat-intel/lookup/ip/{ip}` | GET | Lookup IP against all feeds |
| `/audit/requests` | GET | Query HTTP request audit log (DB-backed) |
| `/auth/login` | POST | Login (rate-limited 5/min/IP) |
| `/auth/me` | GET | Current user info |
| `/auth/change-password` | POST | Change password (invalidates all sessions) |
| `/cases` | GET/POST | Case management CRUD |
| `/rules` | GET | List Sigma detection rules |

---

## Detection Rules

See [docs/RULES.md](docs/RULES.md) for the complete reference of all 45 Sigma rules and 7 correlation rules, organized by category with MITRE ATT&CK mappings.

---

## AI Features

See [docs/AI.md](docs/AI.md) and [docs/V2_PRODUCTION_ROADMAP.md](docs/V2_PRODUCTION_ROADMAP.md) for detailed documentation on:
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

Every ingested event flows through a fire-and-forget enrichment pipeline
(added in Epic 9). The HTTP `/ingest` endpoint returns 202 Accepted as
soon as the batch is queued in the writer; enrichment runs as a
background `asyncio.create_task` and never blocks ingestion.

Enrichments applied (in order):
1. **GeoIP** — country, city, lat/lon for public IPs (MaxMind GeoLite2-City).
2. **DNS reverse** — PTR record for public IPs.
3. **Threat Intel** — match against the cached IOC database (AbuseIPDB,
   OTX, URLhaus); hits boost the event severity.
4. **Severity boost** — high-confidence threat-intel matches upgrade the
   event to `high` or `critical` automatically.

### GeoIP singleton retry (Epic 9 fix)

The pre-Epic-9 GeoIP reader set its "loaded" flag *before* the
init try/except, so a single missing `.mmdb` (or any init failure)
would permanently disable GeoIP for the rest of the process lifetime.
The fix:

- `_geoip_loaded` is only set to `True` after a successful `Reader()` open.
- Init attempts are throttled to once per 60s, so a missing file doesn't
  thrash the FS.
- Optional `_geoip_retry_loop()` coroutine can be scheduled from
  `main.py` to periodically re-attempt — useful when an operator drops
  the `.mmdb` in after the API has already started.

### Correlation trigger

The ingest path also fires `run_all_correlations(persist_alerts=True)`
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
shipped as a `dashboard` service in `docker-compose.yml` (Epic 10).

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
   enter username/password (the API's `seed-admin` endpoint creates
   the first admin). The JWT is stored in `st.session_state`.

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
# Run the full unit suite (1237 tests, 3 warnings, ~30s)
poetry run pytest tests/unit/ -q --no-cov

# With coverage report
poetry run pytest tests/unit/ --cov=src --cov-report=term-missing -q

# Lint
poetry run ruff check src/ dashboard/ --select S,E,F,W

# Type check
poetry run mypy src/
```

CI runs the unit suite on every push; integration tests in `tests/integration/`
require a live Postgres + Redis and are run on a separate job.

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
  state-changing HTTP request. The `audit_logs` table is append-only by
  design — documented hardening:
  ```sql
  REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM scarletai;
  GRANT  INSERT, SELECT            ON audit_logs TO   scarletai;
  ```
- **SQL safety**: All user-supplied values flow through parameterized queries
  (`$1`, `$2`, …) — no string interpolation in SQL. NL→SQL pipeline has
  7 layers of injection defense. `correlation.py` uses `as_of: $1::timestamptz`
  for every time predicate (no `NOW()` in query strings).
- **Secret hygiene**: `.env` is gitignored. `.env.example` documents how to
  generate strong secrets with `openssl rand`. Local secret rotation is
  documented in `scripts/entrypoint.sh`; git history rewrite (`filter-repo` /
  BFG) is **deliberately deferred** — see `SESSION_HANDOFF.md` for the
  decision record (Option B: local-dev-only credentials, cost/benefit of
  history rewrite not justified).
- **Dashboard auth**: Two modes — interactive JWT login (default) or
  `DASHBOARD_API_TOKEN` service-to-service bearer (set in `.env`). The API's
  unified auth dependency accepts either form.

---

## Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment instructions including:
- Docker Compose configuration
- Environment variables
- Database migrations
- Security hardening checklist
- Backup & recovery

---

## Project Structure

```
securityscarletai/
├── src/
│   ├── api/                 # FastAPI routers + middleware (15 routers)
│   │   ├── main.py          # App config, CORS, lifespan, middleware stack
│   │   ├── health.py        # /health with rich Ollama status block
│   │   ├── ingest.py        # /ingest (rate-limited, 202 Accepted, fire-and-forget enrichment)
│   │   ├── alerts.py        # Alert CRUD, export, suppressions
│   │   ├── cases.py         # Case management
│   │   ├── ai.py            # /ai/status, /ai/train, /ai/triage, /ai/explain, /ai/ueba
│   │   ├── chat.py          # /chat AI chat endpoint
│   │   ├── hunt.py          # /hunt/suggestions
│   │   ├── query.py         # /query NL→SQL
│   │   ├── correlation.py   # /correlation/rules, /run, /matches
│   │   ├── threat_intel.py  # /threat-intel/stats|refresh|lookup
│   │   ├── audit.py         # /audit/requests (DB-backed audit log query)
│   │   ├── auth.py          # JWT helpers, RBAC, password hashing, jti, refresh
│   │   ├── auth_login.py    # /auth/login, /auth/me, /auth/change-password
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
│   │   ├── ollama_client.py # Ollama LLM + validate_ollama_model()
│   │   ├── prompts.py       # Versioned Jinja2 prompt templates
│   │   ├── cost_tracker.py  # Per-call cost + latency → ai_usage
│   │   └── utils.py         # Shared helpers
│   ├── detection/           # Detection engine
│   │   ├── sigma.py         # pySigma parser + PostgreSQL backend
│   │   ├── correlation.py   # 7 correlation rules (as_of, persist)
│   │   ├── sequences.py     # 7 event sequence patterns
│   │   ├── alerts.py        # Alert lifecycle management
│   │   └── scheduler.py     # Rule scheduler
│   ├── enrichment/          # Event enrichment
│   │   └── pipeline.py      # GeoIP (with retry), DNS, Threat Intel
│   ├── intel/               # Threat intelligence
│   │   └── threat_intel.py  # AbuseIPDB, OTX, URLhaus clients
│   ├── ingestion/           # Log ingestion
│   │   ├── parser.py        # ECS normalization
│   │   ├── shipper.py       # File tailing (osquery)
│   │   ├── schemas.py       # Pydantic models
│   │   └── ingest.py        # Ingestion path with async enrichment + correlation trigger
│   ├── response/            # SOAR Lite
│   │   ├── soar.py          # Slack, email, pf
│   │   └── notifications.py # Notification dispatch
│   ├── services/
│   │   └── writer.py        # Batched log writer
│   ├── config/              # Configuration
│   │   ├── settings.py      # Pydantic Settings (SecretStr for secrets)
│   │   └── logging.py       # Structured logging
│   └── db/                  # Database
│       ├── connection.py    # asyncpg pool (retry + backoff)
│       ├── writer.py        # Async batched writer
│       └── schema.sql       # Canonical schema (ai_usage, correlation_matches, audit_logs, triage_model_provenance, alert_labels)
├── dashboard/               # Streamlit UI
│   ├── main.py              # Dashboard entry point
│   ├── alerts_view.py       # Alert browser
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
│   └── sigma/               # 45 Sigma YAML rules
│       ├── authentication/  # 9 rules
│       ├── process/         # 8 rules
│       ├── network/         # 7 rules
│       ├── file/            # 6 rules
│       ├── macOS/           # 10 rules
│       └── cloud/           # 5 rules
├── alembic/                 # Database migrations (5 revisions)
├── scripts/
│   ├── entrypoint.sh        # Idempotent Docker bootstrap
│   ├── generate_training_data.py  # Synthetic alert generator (Epic 3)
│   └── setup_db.sh          # Local DB setup
├── tests/                   # 1237 unit tests + 2 integration suites
├── docs/                    # AI.md, RULES.md, DEPLOYMENT.md, ATTACK-SCENARIOS.md, V2_PRODUCTION_ROADMAP.md
└── docker-compose.yml       # Postgres 17 + Redis 7 + API + dashboard
```

<!-- TODO: Screenshots -->

---

## Attack Simulation Walkthroughs

See [docs/ATTACK-SCENARIOS.md](docs/ATTACK-SCENARIOS.md) for 3 detailed walkthroughs:

1. **SSH Brute Force** — Detection → AI explanation → SOAR IP blocking
2. **Reverse Shell** — Process detection → alert triage → case creation
3. **Data Exfiltration** — Network detection → NL query → hunting

---

## License

MIT — See [LICENSE](LICENSE) for details.