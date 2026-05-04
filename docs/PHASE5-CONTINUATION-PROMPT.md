# SecurityScarletAI — Phase 5 Continuation Prompt (Chunk 5.2 → 5.3)

You are the lead security engineer on SecurityScarletAI, an AI-native SIEM portfolio
project. Phases 0–4 are COMPLETE. Phase 5 Chunk 5.1 is COMPLETE — we've gone from
352 tests/39% coverage to **1022 tests/85% coverage**. Both targets exceeded.

```
   Repo: /Users/main/Security Apps/SecurityScarletAI
   Branch: feature/phase4-dashboard-ux
   Last commit: 6be5e18 feat: Phase 5 Chunk 5.1 — Comprehensive Test Suite (1022 tests, 85% coverage)
```

Current Metrics: 1022 tests pass · 85% coverage · ruff check clean · S608 suppressed
(false positive)

Read first: docs/HANDOVER.md (full state)

### What to do: Phase 5 Chunks 5.2 and 5.3

Chunk 5.1 (Testing) is DONE. Now proceed to documentation and portfolio polish.

---

## Chunk 5.2: Documentation & README

### 5.2.1 README.md — Complete Rewrite

Create a professional, portfolio-quality README.md that makes someone want to clone and
run this project. Must include:

**Structure:**
```markdown
# SecurityScarletAI 🔐
> AI-Native SIEM with Natural Language Querying, Real-Time Detection, and Automated Response

## Architecture Overview
(ASCII art diagram showing: Ingestion → Detection → AI Layer → Dashboard)

## Features
- 45+ Sigma Detection Rules with MITRE ATT&CK mapping
- Natural Language → SQL query engine (NL→SQL)
- AI-powered alert triage (Random Forest classifier, auto-train)
- Threat intelligence enrichment (AbuseIPDB, OTX, URLhaus)
- UEBA behavioral analytics
- Real-time WebSocket log streaming
- Case management with lessons learned
- RBAC with JWT authentication
- 47+ API endpoints with OpenAPI documentation
- Dark-themed Streamlit dashboard

## Tech Stack
- Backend: Python, FastAPI, asyncpg, APScheduler
- AI: Ollama (local LLM), sklearn, SHAP
- Detection: pySigma, custom correlation engine
- Database: PostgreSQL with Alembic migrations
- Dashboard: Streamlit with JWT auth
- Testing: pytest (1022 tests, 85% coverage), hypothesis, ruff

## Quick Start
```bash
docker-compose up -d          # PostgreSQL on port 5433
poetry install                # Install dependencies
poetry run alembic upgrade head  # Run migrations
poetry run uvicorn src.api.main:app --reload --port 8000  # API
poetry run streamlit run dashboard/main.py --server.port 8501  # Dashboard
```

## API Documentation
Open http://localhost:8000/api/docs for Swagger UI

## Detection Rules
See docs/RULES.md for the complete list of 45+ Sigma rules mapped to MITRE ATT&CK.

## Testing
```bash
poetry run pytest tests/unit/ -v    # 1022 unit tests
poetry run ruff check src/          # Lint check
poetry run pytest tests/ --cov=src  # 85% coverage
```

## Project Structure
```
src/
├── api/              # FastAPI endpoints (47+)
├── ai/               # NL→SQL, triage, hunting, risk scoring, UEBA
├── detection/        # Sigma engine, correlation, scheduler, MITRE
├── enrichment/       # GeoIP, DNS, threat intel enrichment
├── intel/            # Threat intel feeds (AbuseIPDB, OTX, URLhaus)
├── ingestion/        # Log parser, schemas, shipper
├── response/         # SOAR playbooks, notifications
├── config/           # Settings, logging
├── db/               # Connection pool, writer, migrations
├── case/             # Case management
dashboard/            # Streamlit dashboard (7 pages)
rules/sigma/          # 45+ Sigma detection rules
tests/unit/           # 1022 unit tests (85% coverage)
```

## Screenshots
(add screenshots/GIFs here during Chunk 5.3)

## License
MIT
```

### 5.2.2 DEPLOYMENT.md

Create `docs/DEPLOYMENT.md` with:
- Prerequisites (Python 3.11+, Docker, PostgreSQL 15+, Ollama)
- Environment variables (.env file template)
- Docker Compose setup
- Database migration instructions
- Security hardening checklist (TLS, secrets rotation, network isolation)
- Backup & recovery procedures
- Monitoring (health endpoints, log aggregation)

### 5.2.3 RULES.md

Create `docs/RULES.md` with:
- Complete list of all 45 Sigma rules with MITRE ATT&CK technique IDs
- How to write custom Sigma rules
- Rule testing workflow
- Correlation rule format

### 5.2.4 AI.md

Create `docs/AI.md` with:
- NL→SQL: how it works, template system, safety measures
- Alert Triage: sklearn Random Forest, feature engineering, auto-train
- UEBA: behavioral baselines, anomaly scoring
- Alert Explanation: LLM + template fallback
- Hunting Assistant: pre-built templates, MITRE gap analysis
- Risk Scoring: factor weights, asset/user risk

---

## Chunk 5.3: Portfolio Polish

### 5.3.1 Demo Script

Create `scripts/demo.sh`:
```bash
#!/bin/bash
# One command to start the full stack and seed data
docker-compose up -d
poetry run alembic upgrade head
poetry run python scripts/seed_demo_data.py
poetry run uvicorn src.api.main:app --port 8000 &
poetry run streamlit run dashboard/main.py --server.port 8501 &
```

Create `scripts/seed_demo_data.py`:
- Insert 50-100 sample alerts with realistic data
- Create 3 sample cases
- Add case notes and lessons learned
- Seed threat intel data
- Create sample hunt results

### 5.3.2 Attack Simulation Scenarios

Create `docs/ATTACK-SCENARIOS.md`:
- Scenario 1: SSH Brute Force → detection → AI explanation → SOAR response
- Scenario 2: Reverse Shell → detection → alert triage → case creation
- Scenario 3: Data Exfiltration → detection → NL query → hunt → block

### 5.3.3 GitHub Actions CI

Create `.github/workflows/ci.yml`:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install poetry
      - run: poetry install
      - run: poetry run ruff check src/ dashboard/
      - run: poetry run pytest tests/unit/ -q
      - run: poetry run pytest tests/ --cov=src --cov-fail-under=80
```

### 5.3.4 Clean Git History

Squash or rebase commits for clean history before final push. Each phase should be
a clean commit with a descriptive message.

### 5.3.5 Final Security Audit

Run a final pass:
- [ ] Verify no hardcoded secrets (grep for api_key, password, secret in src/)
- [ ] Verify all SQL uses parameterized queries ($1, $2)
- [ ] Verify JWT auth on all sensitive endpoints
- [ ] Verify CORS is restrictive
- [ ] Verify rate limiting is configured

---

## Quality Gates

```bash
cd "/Users/main/Security Apps/SecurityScarletAI"
poetry run pytest tests/unit/ -v                    # 1022+ must pass
poetry run ruff check src/ dashboard/ --select S,E,F,W  # Must be clean
poetry run pytest tests/ --cov=src --cov-report=term-missing --tb=no -q  # 80%+ (currently 85%)
```

## Key Gotchas

- S608 in pyproject.toml — `ignore = ["S608"]` suppresses false-positive bandit warnings
  for asyncpg. All SQL uses `$1, $2` parameterized placeholders. Do NOT remove.
- `require_role()` creates closures — Can't be easily overridden via FastAPI
  dependency_overrides. Test endpoint functions directly with mocked DB pools.
- Integration tests (3 in test_detection.py) fail without DB — excluded from unit count.
- hypothesis was added as dev dependency for property-based tests.
- Best test patterns are in test_risk_scoring.py (async DB mocking) and
  test_cases_api.py (API endpoint testing).