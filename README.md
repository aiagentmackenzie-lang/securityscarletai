# SecurityScarletAI

**AI-Native SIEM for macOS** — Real-time log ingestion, Sigma-based detection, ML-powered alert triage, and LLM-driven investigation assistance.

[![Tests](https://img.shields.io/badge/tests-1022%20passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-green)]()
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
| **Ingestion** | FastAPI + asyncpg | High-throughput log collection (osquery, syslog, API) |
| **Storage** | PostgreSQL 17 | Time-series logs, alerts, cases with indexed JSONB |
| **Detection** | pySigma + custom backend | 45 Sigma rules → parameterized SQL, correlation engine |
| **Enrichment** | GeoIP2 + DNS + Threat Intel | MaxMind GeoIP, AbuseIPDB, OTX, URLhaus enrichment |
| **AI / ML** | Ollama + sklearn | NL→SQL, Random Forest triage, Isolation Forest UEBA, hunting |
| **Dashboard** | Streamlit + WebSocket | Real-time alerts, cases, hunting, AI chat |
| **Response** | SOAR Lite | Slack/email notifications, pf firewall, case management |

---

## Features

- **45 Sigma Detection Rules** — Authentication, process, network, file, macOS, and cloud categories with MITRE ATT&CK mapping
- **Correlation Engine** — 5 SQL-based and 7 sequence-based correlation rules detecting multi-step attack chains
- **ML Alert Triage** — Random Forest classifier with 11 features, auto-trains at 100+ resolved alerts
- **Natural Language → SQL** — Ask questions in plain English, get safe parameterized SQL with 7-layer injection defense
- **UEBA Behavioral Baselines** — Isolation Forest anomaly detection with per-user behavioral fingerprinting
- **AI Alert Explanation** — LLM-powered explanations with 6 template fallbacks when Ollama is unavailable
- **Threat Hunting Assistant** — 7 pre-built hunt templates, MITRE gap analysis, and hunt-from-alert
- **Threat Intel Integration** — AbuseIPDB, OTX AlienVault, URLhaus with IOC caching and auto-refresh
- **Risk Scoring Engine** — Multi-factor scoring: severity, threat intel match, asset criticality, UEBA anomaly
- **Case Management** — Full CRUD with assignments, notes, status tracking, and lessons learned
- **RBAC Authentication** — JWT-based auth with role-based access control (viewer, analyst, admin)
- **Real-time Dashboard** — Streamlit with WebSocket live updates, auto-refresh, and toast notifications
- **SOAR Lite** — Automated Slack/email alerts and macOS pf firewall blocking

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI + Uvicorn |
| Database | PostgreSQL 17 (asyncpg) |
| Migrations | Alembic |
| AI/ML | Ollama (LLM), scikit-learn, joblib |
| Dashboard | Streamlit |
| Detection | pySigma |
| Networking | httpx, websockets |
| Auth | JWT (python-jose) + bcrypt |
| Geolocation | MaxMind GeoIP2 |
| Containerization | Docker Compose |
| Testing | pytest, pytest-asyncio, hypothesis |
| Linting | ruff, mypy |

---

## Quick Start

```bash
# 1. Clone and enter the project
git clone https://github.com/your-org/SecurityScarletAI.git
cd SecurityScarletAI

# 2. Start PostgreSQL with Docker
docker-compose up -d

# 3. Install dependencies
poetry install

# 4. Configure environment
cp .env.example .env
# Edit .env — set DB_PASSWORD, API_SECRET_KEY, API_BEARER_TOKEN

# 5. Run database migrations
poetry run alembic upgrade head

# 6. Start the API
poetry run uvicorn src.api.main:app --port 8000

# 7. Start the dashboard (separate terminal)
poetry run streamlit run dashboard/main.py --server.port 8501
```

Verify it's running:
```bash
curl http://localhost:8000/api/v1/health
# → {"status":"healthy","checks":{"api":"ok","database":"ok"}}
```

---

## API Documentation

Interactive API docs are available at:

- **Swagger UI**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **ReDoc**: [http://localhost:8000/api/redoc](http://localhost:8000/api/redoc)

Key endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check (API, DB, Ollama status) |
| `/api/v1/ingest` | POST | Ingest log events (bearer token required) |
| `/api/v1/alerts` | GET | List alerts with filtering and pagination |
| `/api/v1/query` | POST | Natural language → SQL query |
| `/api/v1/cases` | GET/POST | Case management CRUD |
| `/api/v1/rules` | GET | List Sigma detection rules |
| `/api/v1/threat-intel/stats` | GET | Threat intel cache statistics |
| `/api/v1/correlation/run` | POST | Run all correlation rules |
| `/api/v1/ai/triage/train` | POST | Train the ML triage model |
| `/api/v1/ai/explain` | POST | Get AI explanation for an alert |
| `/api/v1/hunt/suggestions` | GET | Get hunting suggestions |
| `/api/v1/chat` | POST | AI chat assistant |

---

## Detection Rules

See [docs/RULES.md](docs/RULES.md) for the complete reference of all 45 Sigma rules and 12 correlation rules, organized by category with MITRE ATT&CK mappings.

---

## AI Features

See [docs/AI.md](docs/AI.md) for detailed documentation on:
- Natural Language → SQL query conversion
- ML-powered alert triage with Random Forest
- UEBA behavioral baselines with Isolation Forest
- LLM alert explanation with template fallback
- Threat hunting assistant
- Risk scoring engine

---

## Testing

```bash
# Run all unit tests (1022 tests)
poetry run pytest tests/unit/ -v

# Run with coverage report
poetry run pytest tests/ --cov=src --cov-report=term-missing -q

# Lint check
poetry run ruff check src/ dashboard/ --select S,E,F,W

# Type check
poetry run mypy src/
```

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
SecurityScarletAI/
├── src/
│   ├── api/                 # FastAPI endpoints (14 routers)
│   │   ├── main.py          # App config, CORS, lifespan
│   │   ├── alerts.py        # Alert CRUD, export, suppressions
│   │   ├── cases.py         # Case management
│   │   ├── ai.py            # AI triage, explanation, NL→SQL
│   │   ├── chat.py          # AI chat endpoint
│   │   ├── hunt.py          # Hunting assistant
│   │   ├── query.py         # NL→SQL query endpoint
│   │   └── ...
│   ├── ai/                  # AI/ML module
│   │   ├── nl2sql.py        # Natural language → SQL (7-layer safety)
│   │   ├── alert_triage.py  # Random Forest triage model
│   │   ├── alert_explanation.py  # LLM + template fallback
│   │   ├── hunting_assistant.py  # Hunt templates + MITRE gaps
│   │   ├── risk_scoring.py  # Multi-factor risk scoring
│   │   ├── ueba.py          # Isolation Forest UEBA
│   │   ├── chat.py          # AI chat
│   │   └── ollama_client.py # Ollama LLM integration
│   ├── detection/           # Detection engine
│   │   ├── sigma.py         # pySigma parser + PostgreSQL backend
│   │   ├── correlation.py   # 5 SQL correlation rules
│   │   ├── sequences.py     # 7 event sequence patterns
│   │   ├── alerts.py        # Alert lifecycle management
│   │   └── scheduler.py     # Rule scheduler
│   ├── enrichment/          # Event enrichment
│   │   └── pipeline.py     # GeoIP, DNS, Threat Intel enrichment
│   ├── intel/               # Threat intelligence
│   │   └── threat_intel.py  # AbuseIPDB, OTX, URLhaus clients
│   ├── ingestion/           # Log ingestion
│   │   ├── parser.py        # ECS normalization
│   │   ├── shipper.py       # File tailing (osquery)
│   │   └── schemas.py      # Pydantic models
│   ├── case/                # Case management
│   ├── response/            # SOAR Lite
│   │   ├── soar.py          # Slack, email, pf
│   │   └── notifications.py # Notification dispatch
│   ├── config/              # Configuration
│   │   ├── settings.py      # Pydantic Settings
│   │   └── logging.py      # Structured logging
│   └── db/                  # Database
│       ├── connection.py    # asyncpg pool
│       └── writer.py        # Batched log writer
├── dashboard/               # Streamlit UI
│   ├── main.py              # Dashboard entry point
│   ├── alerts_view.py       # Alert browser
│   ├── cases_view.py        # Case management
│   ├── hunt_view.py         # Hunting interface
│   ├── ai_chat_view.py      # AI chat
│   ├── rules_view.py        # Rule management
│   ├── logs_view.py         # Log viewer
│   ├── charts.py            # Visualization
│   ├── api_client.py        # HTTP client
│   └── auth.py              # JWT auth
├── rules/
│   └── sigma/               # 45 Sigma YAML rules
│       ├── authentication/  # 9 rules
│       ├── process/         # 8 rules
│       ├── network/         # 7 rules
│       ├── file/            # 6 rules
│       ├── macOS/           # 10 rules
│       └── cloud/           # 5 rules
├── alembic/                 # Database migrations
├── tests/                   # 1022 unit tests
├── scripts/                 # Utilities
├── docs/                    # Documentation
└── docker-compose.yml       # PostgreSQL + Redis
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