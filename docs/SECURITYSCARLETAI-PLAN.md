# SecurityScarletAI — Production-Ready Portfolio SIEM Plan

**Created:** May 3, 2026
**Goal:** Transform from learning project → credible portfolio piece that demonstrates security engineering + AI capabilities
**Timeline:** ~4 weeks (20 working days)
**Philosophy:** Deep, not wide. Ship what works. Kill what doesn't.

---

## Guiding Principles

1. **Security first** — A SIEM with SQL injection is not a SIEM. Fix before feature.
2. **Real detections, real data** — 50+ rules that actually fire, not 6 stubs.
3. **AI that adds value** — Not "AI for AI's sake." NL→SQL that works, triage that learns.
4. **Portfolio-ready** — Every feature must be demonstrable in a 5-minute walkthrough.
5. **Test coverage ≥ 80%** — Untested code is unfinished code.

---

## Phase 0: Critical Bug Fixes (Day 1-2) ✅ COMPLETE
### 🚨 Stop the bleeding. No new features until these are fixed.

### Chunk 0.1: SQL Injection Elimination (Day 1) ✅ COMPLETE
**Files:** `src/detection/sigma.py`, `src/ai/risk_scoring.py`, `src/ai/ueba.py`, `src/detection/correlation.py`, `dashboard/main.py`

**What:**
- [ ] Replace all f-string SQL in `sigma.py` with parameterized queries
  - `group_by` and `count_field` must be whitelisted against known column names
  - `lookback` must be validated as a proper timedelta, not string-interpolated
- [ ] Fix asyncpg interval parameterization in `risk_scoring.py`
  - Use `timedelta` objects with `asyncpg` or use `NOW() - $1::interval` cast
- [ ] Fix same pattern in `ueba.py` (`INTERVAL '$2 days'`)
- [ ] Fix `correlation.py` — parameterize `time_window` and `failed_threshold`
- [ ] **KILL** the `subprocess.run(psql, ...)` in `dashboard/main.py` Live Logs page
  - Replace with API call (every other page already uses the API)

**Test:** Add specific SQL injection test cases to `test_sigma.py`:
```python
def test_sigma_prevents_sql_injection():
    malicious = """
    title: Evil Rule
    detection:
        selection:
            host_name: "'; DROP TABLE logs; --"
        condition: selection
    """
    sql, params = sigma_to_sql(malicious)
    # Verify the injection attempt is parameterized, not raw
    assert "DROP TABLE" not in sql
```

**Deliverable:** Zero SQL injection vectors. `ruff check --select S608` passes clean.

---

### Chunk 0.2: Remove Hardcoded Secrets (Day 1) ✅ COMPLETE
**Files:** `dashboard/main.py`, `scripts/seed_realistic_data.py`, `scripts/analyze_alerts.py`

**What:**
- [ ] Remove hardcoded `TOKEN` from `dashboard/main.py` — read from env or `.env`
- [ ] Remove hardcoded `TOKEN` from `scripts/seed_realistic_data.py`
- [ ] Remove hardcoded path `sys.path.insert(0, "/Users/main/Security Apps/...")` from `scripts/analyze_alerts.py`
- [ ] Verify `.env` is NOT in git history: `git log --all --full-history -- .env`
- [ ] If it is, rotate ALL secrets and use `git filter-branch` or BFG Repo Cleaner

**Deliverable:** Zero hardcoded secrets in source. All scripts read from env.

---

### Chunk 0.3: Fix Runtime Crashes (Day 2) ✅ COMPLETE
**Files:** `src/detection/scheduler.py`, `src/detection/ai_analyzer.py`, `src/response/notifications.py`

**What:**
- [ ] Fix double `UPDATE rules SET last_match` in `scheduler.py` (lines 60-69 duplicate)
- [ ] Fix hardcoded `MODEL = "mistral:7b"` in `ai_analyzer.py` → use `settings.ollama_model`
- [ ] Add `aiosmtplib` to `pyproject.toml` dependencies (or remove the import and make email a TODO)
- [ ] Fix MITRE tag parsing in `main.py` and `sigma.py`:
  - Tactic IDs: `TA0001` format → match `attack.ta` prefix
  - Technique IDs: `T1110` format → match `attack.t` prefix (not tactic)
  - Current logic `len(t) == 8` is wrong
- [ ] Fix `process_cmdline` and `process_path` — add columns to `logs` table schema or ensure they're queryable via `normalized` JSONB with GIN index

**Deliverable:** All unit tests pass. No runtime crashes on standard operations.

---

### Chunk 0.4: Replace Pickle with Safe Serialization (Day 2) ✅ COMPLETE
**Files:** `src/ai/ueba.py`, `src/ai/alert_triage.py`

**What:**
- [ ] Replace `pickle.load()` / `pickle.dump()` with `joblib.load()` / `joblib.dump()` (already in deps)
  - joblib is safer (no arbitrary code execution) and is the sklearn standard
- [ ] Add model file integrity check (SHA256 hash stored separately)
- [ ] Move model files from `~/` to project directory `models/` (gitignored)

**Deliverable:** `ruff check --select S301` passes clean on these files.

---

## Phase 1: Foundation Hardening (Day 3-7) ✅ COMPLETE
### 🔧 Make it actually work correctly and professionally.

### Chunk 1.1: Replace Custom Sigma Parser with pySigma (Day 3-4) ✅ COMPLETE
**The single highest-impact improvement.**

**What:**
- [ ] Add `pysigma` and `pysigma-backend-postgresql` to dependencies
- [ ] Replace `src/detection/sigma.py` with thin wrapper around pySigma
  - `parse_sigma_rule()` → `pySigma.parse()`
  - `sigma_to_sql()` → `pySigma PostgreSQL backend.generate()`
- [ ] This gives us: proper Sigma spec compliance, all modifiers, AND/OR logic, aggregation, field mapping
- [ ] Port all 6 existing rules to pySigma-compatible format
- [ ] Add 10+ new rules from SigmaHQ community rules (macOS-focused)

**Why this matters:** The custom parser covers ~20% of the Sigma spec. pySigma covers 100%. This is not NIH — this is using the standard library.

**Deliverable:** pySigma-powered detection engine. All existing rules still work. 15+ total rules.

---

### Chunk 1.2: Database Migrations with Alembic (Day 4)
**Files:** New `alembic/` directory

**What:**
- [ ] Initialize Alembic: `poetry run alembic init alembic`
- [ ] Configure `alembic.ini` to read from `settings.database_url_sync`
- [ ] Create initial migration from existing `schema.sql`
- [ ] Add migration for missing columns: `process_cmdline TEXT`, `process_path TEXT` in `logs`
- [ ] Add `audit_log` table migration:
  ```sql
  CREATE TABLE audit_log (
      id SERIAL PRIMARY KEY,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,        -- 'rule.create', 'alert.update', 'case.create'
      target_type TEXT NOT NULL,    -- 'rule', 'alert', 'case'
      target_id INTEGER,
      old_values JSONB,
      new_values JSONB,
      ip_address TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  ```
- [ ] Update startup to run `alembic upgrade head` before pool creation

**Deliverable:** `alembic upgrade head` creates the full schema from scratch.

---

### Chunk 1.3: Audit Logging & RBAC Enforcement (Day 5)
**Files:** `src/api/auth.py`, new `src/api/audit.py`, all API endpoints

**What:**
- [ ] Create `audit.py` with `log_audit_action()` helper
- [ ] Wire to all mutation endpoints:
  - Rule CRUD → audit rule.create/update/delete
  - Alert status change → audit alert.update
  - Case CRUD → audit case.create/update
- [ ] Add `GET /api/v1/audit` endpoint for querying audit log
- [ ] Add role-based access to endpoints:
  - `admin`: all operations
  - `analyst`: alert/case management, read rules
  - `viewer`: read-only everything
- [ ] Fix `verify_bearer_token` vs `verify_jwt` inconsistency — bearer for ingestion, JWT for dashboard

**Deliverable:** Every state change is auditable. RBAC enforced on all endpoints.

---

### Chunk 1.4: Ingestion Hardening (Day 6)
**Files:** `src/api/ingest.py`, `src/db/writer.py`, new `src/api/middleware.py`

**What:**
- [ ] Add rate limiting with `slowapi`:
  - `/ingest`: 100 requests/min per token
  - `/alerts`, `/rules`: 60 requests/min
- [ ] Add request size validation (max body size 1MB)
- [ ] Implement dead letter queue in `writer.py`:
  - Failed batches → write to `data/dead_letter/YYYY-MM-DD.jsonl`
  - Log error, don't silently drop
  - Add `POST /api/v1/ingest/retry` endpoint for manual retry
- [ ] Add batch ingestion validation — reject entire batch if any event is malformed
- [ ] Add `Content-Type: application/json` enforcement

**Deliverable:** Ingestion is resilient, rate-limited, and never silently drops data.

---

### Chunk 1.5: Config & Environment Cleanup (Day 7)
**Files:** `src/config/settings.py`, `.env.example`, `Dockerfile`, `docker-compose.yml`

**What:**
- [ ] Add settings validation at startup (fail fast on missing required values)
- [ ] Fix `docker-compose.yml` — PostgreSQL port 5432 conflicts with Homebrew PostgreSQL (same issue as AI Agent Security Monitor). Change to 5433.
- [ ] Update `Dockerfile` — copy `alembic/` and `rules/` directories
- [ ] Add `docker-compose.yml` healthcheck wait (API waits for DB to be ready)
- [ ] Add `LOG_LEVEL` override for individual modules
- [ ] Remove Redis from docker-compose if we're not using it (or add caching)

**Deliverable:** Clean `docker-compose up -d` → working stack. No port conflicts.

---

## Phase 2: Detection Engine (Day 8-13)
### 🎯 Make it detect real threats. This is the core value proposition.

### Chunk 2.1: Expand Sigma Rule Library (Day 8-9) ✅ COMPLETE

**Files:** `rules/sigma/` (6 subdirectories with 45 YAML rules)

**What:**
Import and adapt rules from SigmaHQ community repository, focused on:
- [x] **macOS-specific** (10 rules):
  - LaunchAgent/LaunchDaemon creation ✅
  - TCC database modification ✅
  - Gatekeeper bypass ✅
  - XProtect removal ✅
  - Safari extension installation ✅
  - Keychain access ✅
  - System Integrity Protection modification ✅
  - Disk utility mount (removed, covered by SIP)
  - Authorization database modification ✅
  - Hidden file creation in user directories ✅

- [x] **Authentication** (9 rules):
  - SSH brute force (upgraded from basic) ✅
  - Failed login spike ✅
  - Login from unusual geography ✅
  - Service account authentication anomaly ✅
  - Multiple account lockouts ✅
  - Root login from non-console ✅
  - Credential dumping attempts ✅
  - Sudo privilege escalation ✅
  - SSH success after failures ✅

- [x] **Process** (8 rules):
  - Suspicious /tmp execution (upgraded) ✅
  - Reverse shell patterns ✅
  - Living-off-the-land binaries (LOLBins) ✅
  - Encoded command execution ✅
  - Unusual parent-child process chains ✅
  - PowerShell/curl download patterns ✅
  - Script interpreter from unexpected location ✅
  - Process injection indicators ✅

- [x] **Network** (7 rules):
  - C2 beaconing patterns ✅
  - DNS tunneling indicators ✅
  - Rare port outbound (upgraded) ✅
  - Data exfiltration volume ✅
  - Tor exit node connections ✅
  - Internal lateral movement ✅
  - Suspicious HTTPS outbound ✅
  - Suspicious DNS (upgraded) ✅

- [x] **File** (6 rules):
  - Sensitive file access ✅
  - Ransomware file encryption patterns ✅
  - Scheduled task/cron modification ✅
  - Binary replacement (DLL side-loading) ✅
  - Webshell creation ✅
  - Log file deletion ✅

- [x] **Cloud/SaaS** (5 rules):
  - Impossible travel ✅
  - API key usage from new IP ✅
  - Bulk data download ✅
  - Permission escalation in SaaS ✅
  - New admin account creation ✅

**Total:** 45 rules (from 6)

**Additional changes:**
- Added `process_cmdline` and `process_path` to ALLOWED_COLUMNS whitelist
- Updated field mappings in both legacy and pySigma backends
- Changed `load_rules_from_directory()` to use `rglob("*.yml")` for recursive loading
- Added 26 unit tests for rule library validation

**Deliverable:** 45+ working Sigma rules with MITRE ATT&CK tags. Each tested against sample data.

---

### Chunk 2.2: Correlation Engine v2 (Day 10) ✅ COMPLETE

**Files:** `src/detection/correlation.py` (rewritten), new `src/detection/sequences.py`

**What:**
- [x] Rewrite correlation rules as parameterized, safe SQL ✅
- [x] Add sequence-based detection (Event A followed by Event B): ✅
  - Failed login → Successful login (brute force succeeded) ✅
  - Process from /tmp → Network connection (dropped payload calling home) ✅
  - File creation in LaunchAgents → launchctl load (persistence activated) ✅
  - Large file read → Large network transfer (data exfiltration) ✅
  - Privilege escalation → New process as root (compromise chain) ✅
- [x] Add time-window sessionization (group events by host+user into sessions) ✅
- [x] Add confidence scoring (more signals = higher confidence, capped at 100) ✅
- [x] Add 7 EventSequence definitions in sequences.py ✅
- [x] Add correlation API endpoints (/correlation/rules, /run, /run/{name}) ✅

**Deliverable:** 5+ correlation rules that detect attack chains, not just single events. + sessionization + confidence scoring + API.

---

### Chunk 2.3: Alert Management v2 (Day 11) ✅ COMPLETE

**Files:** `src/detection/alerts.py` (rewritten), `src/api/alerts.py` (rewritten)

**What:**
- [x] Fix deduplication — configurable window (default 15 min, not 5) ✅
- [x] Add alert suppression rules (whitelist known false positives) ✅
- [x] Add alert severity escalation (3x in 1hr → bump severity) ✅
- [x] Add bulk alert operations (acknowledge all, assign to me, mark as FP) ✅
- [x] Add alert notes/timeline (analyst comments tracked) ✅
- [x] Wire `send_alert_notification()` into alert creation ✅
- [x] Add alert export (CSV, STIX 2.1) ✅
- [x] Add alert_suppressions table (Alembic migration) ✅
- [x] Add notes column to alerts (Alembic migration) ✅

**Deliverable:** Alert lifecycle is complete: detect → deduplicate → notify → triage → resolve.

---

### Chunk 2.4: Threat Intelligence v2 (Day 12-13) ✅ COMPLETE

**Files:** `src/intel/threat_intel.py` (rewritten), new `src/enrichment/pipeline.py` (rewritten), `src/api/threat_intel.py` (new)

**What:**
- [x] Add scheduled threat intel refresh (every 6 hours via APScheduler) ✅
- [x] Add AbuseIPDB IP reputation enrichment on ingest ✅
- [x] Add OTX pulse subscription and auto-ingestion ✅
- [x] Add URLhaus URL checking during log enrichment ✅
- [x] Create enrichment pipeline v2 ✅
  ```
  Log ingested → check source_ip against threat_intel
                → check destination_ip against threat_intel
                → GeoIP + DNS reverse lookup
                → add enrichment data to event
                → if match, boost severity
  ```
- [x] Wire enrichment into ingestion pipeline (enrich_event function callable) ✅
- [x] Add `GET /api/v1/threat-intel/stats` endpoint ✅
- [x] Add `POST /api/v1/threat-intel/refresh` endpoint ✅
- [x] Add `GET /api/v1/threat-intel/lookup/ip/{ip}` endpoint ✅
- [x] Add `GET /api/v1/threat-intel/lookup/url` endpoint ✅
- [x] Add `GET /api/v1/threat-intel/lookup/hash/{hash}` endpoint ✅

**Deliverable:** Every ingested event can be automatically enriched with threat intel data.

---

## Phase 3: AI Layer (Day 14-17)
### 🧠 Make AI the differentiator. This is what makes this project stand out.

### Chunk 3.1: NL→SQL v2 — Safe and Functional (Day 14)
**Files:** `src/ai/nl2sql.py`

**What:**
- [ ] Add prompt injection defense:
  - Sanitize user input before sending to LLM
  - Add query result size limits (max 1000 rows)
  - Add query cost estimation (reject full table scans)
  - Add execution timeout (5 seconds max)
- [ ] Improve SQL validation:
  - Parse with `sqlparse` to verify structure
  - Add EXPLAIN check before execution (reject queries scanning >10K rows)
  - Add schema context to prompt (already exists, but improve it)
- [ ] Add query templates for common questions:
  - "Show me failed logins" → pre-built query
  - "What's talking to rare ports?" → pre-built query
  - "Any process from /tmp?" → pre-built query
- [ ] Add conversation context (follow-up queries with "and from that IP?")
- [ ] Add `POST /api/v1/query` endpoint for NL→SQL with results

**Deliverable:** Analysts can ask questions in English and get real answers. Safe.

---

### Chunk 3.2: Alert AI Triage — Actually Works (Day 15)
**Files:** `src/ai/alert_triage.py`, `src/ai/alert_explanation.py`

**What:**
- [ ] Replace pickle serialization with joblib + integrity hash
- [ ] Fix UEBA feature engineering — replace all placeholders:
  - `command_diversity`: calculate Shannon entropy from process names
  - `session_duration_minutes`: derive from first/last event timestamps
  - `login_hour_of_day`: use actual login time distribution
- [ ] Add model training endpoint: `POST /api/v1/ai/train`
- [ ] Add model status endpoint: `GET /api/v1/ai/status`
- [ ] Add auto-training trigger when 100+ resolved alerts exist
- [ ] Wire alert explanation into alert creation flow (not separate script)
- [ ] Add fallback when Ollama is down (template explanations, which already exist)

**Deliverable:** AI triage makes real predictions. Alert explanations auto-generated.

---

### Chunk 3.3: AI Hunting Assistant v2 (Day 16)
**Files:** `src/ai/hunting_assistant.py`

**What:**
- [ ] Add pre-built hunt templates with real SQL (fix the existing ones)
- [ ] Add hunt execution endpoint: `POST /api/v1/hunt/{template_id}/execute`
- [ ] Add hunt results analysis (LLM summarizes findings)
- [ ] Add "hunt from alert" — given an alert, suggest related hunts
- [ ] Add MITRE ATT&CK gap analysis:
  - Which techniques have rules?
  - Which are uncovered?
  - Suggest hunts for gaps
- [ ] Add hunt history (save and compare over time)

**Deliverable:** Analysts can run guided threat hunts and discover unknown threats.

---

### Chunk 3.4: AI Dashboard Chat (Day 17)
**Files:** New `src/ai/chat.py`, new `dashboard/chat_view.py`

**What:**
- [ ] Add conversational AI endpoint: `POST /api/v1/ai/chat`
- [ ] Context-aware: feed current dashboard state + recent alerts to LLM
- [ ] Example interactions:
  - "What should I investigate first?" → prioritize alerts by risk
  - "Explain the brute force alert" → detailed breakdown
  - "Are there any signs of lateral movement?" → run correlation queries
  - "Summarize today's security posture" → executive summary
- [ ] Add to dashboard as sidebar chat panel
- [ ] Add prompt injection guard (same as NeuralGuard approach)

**Deliverable:** Security analyst can chat with their SIEM. This is the wow factor.

---

## Phase 4: Dashboard & UX (Day 18-20)
### 🎨 Make it look professional and actually usable.

### Chunk 4.1: Dashboard Rebuild — API-First (Day 18) ✅ COMPLETE
**Files:** `dashboard/main.py`, all dashboard views, new: `dashboard/api_client.py`, `dashboard/ai_chat_view.py`, `dashboard/hunt_view.py`, `src/api/auth_login.py`

**What:**
- [x] Kill ALL `subprocess.run(psql, ...)` calls
- [x] Kill ALL direct database access from dashboard
- [x] Every data fetch goes through `httpx` API calls (`dashboard/api_client.py`)
- [x] Fix `asyncio.run()` in Streamlit → use synchronous `ApiClient` method calls
- [x] Add proper error handling (API down = user-friendly `ApiError`, not traceback)
- [x] Add Cases page to navigation
- [x] Add Chat page to navigation
- [x] Add Hunting page to navigation
- [x] Add JWT authentication (`/auth/login`, `/auth/seed-admin`, `/auth/me`, `/auth/change-password`)
- [x] Add dark theme CSS
- [x] Add MITRE ATT&CK heatmap
- [x] Add alert severity sparklines
- [x] Add risk score gauges per host
- [x] Add keyboard shortcuts
- [x] Add alert detail with AI explain, triage, hunt-from-alert
- [x] Add bulk alert operations
- [x] Fix passlib/bcrypt 5.x incompatibility
- [x] Add 55 new tests (14 auth + 41 dashboard API)

**Deliverable:** Dashboard is 100% API-driven. No direct DB access.

---

### Chunk 4.2: Dashboard Visual Polish (Day 19) ✅ COMPLETE
**Files:** `dashboard/main.py`, `dashboard/charts.py`, all dashboard views, `pyproject.toml`

**What:**
- [x] Proper login page (JWT auth against API with seed-admin flow)
- [x] MITRE ATT&CK heatmap (which techniques are detected vs. gaps)
- [x] Alert severity sparklines over time
- [x] Risk score gauges per host
- [x] Event volume timeline (proper Altair chart with dark theme)
- [x] Dark theme (security tools should look the part)
- [x] Proper loading states (st.spinner on ALL data fetches, st.status for AI ops)
- [x] Auto-refresh (streamlit-autorefresh with per-page configurable intervals)
- [x] Toast notifications (st.toast on all successful actions)
- [x] CSS polish (fadeIn animations, button transitions, metric animations)
- [x] Keyboard shortcuts (1-7 for navigation)
- [x] Added 28 new tests for polish features

**Deliverable:** Dashboard looks like a security product, not a Streamlit tutorial.

---

### Chunk 4.3: Dashboard Alert Investigation Flow (Day 20) — COMPLETE
**Files:** `dashboard/alerts_view.py`, `dashboard/cases_view.py`, `src/api/cases.py`, `dashboard/api_client.py`

**What:**
- [x] Alert detail page with:
  - Full evidence display
  - AI explanation (one-click generate)
  - AI triage (one-click predict)
  - Hunt from Alert (one-click suggest)
  - Alert notes with timestamps
  - Status update + assign
- [x] Case investigation page with:
  - Linked alerts with severity
  - AI triage per case
  - Hunt suggestions per case
  - Alert notes/timeline
- [x] Bulk actions (select multiple → acknowledge, resolve, mark FP, assign)
- [x] Alert export (CSV download)
- [x] Full cases CRUD API (independent case management)
- [x] Lessons learned field on case resolution

**Deliverable:** Full investigation workflow from alert to resolution.

---

## Phase 5: Testing, Docs & Portfolio (Day 21-25)
### ✅ Prove it works. Document it. Show it off.

### Chunk 5.1: Comprehensive Test Suite (Day 21-22)

**Target: 80%+ coverage, 200+ tests**

- [ ] **Unit tests** (150+):
  - Sigma parser: edge cases, injection attempts, all modifiers
  - Ingestion: validation, sanitization, batch logic
  - Auth: token verification, JWT expiry, RBAC
  - AI modules: mock Ollama responses, test fallbacks
  - Risk scoring: known inputs → expected scores
  - NL→SQL: injection defense, validation, templates

- [ ] **Integration tests** (30+):
  - Full ingestion pipeline (parse → write → query)
  - Detection pipeline (rule → execute → alert → AI analyze)
  - Alert lifecycle (create → deduplicate → update → resolve)
  - API CRUD for rules, alerts, cases
  - WebSocket connection and filtering

- [ ] **End-to-end tests** (10+):
  - Attack scenario → detection → alert → AI analysis → case
  - Each of the 6 original attack scenarios
  - NL→SQL query → results
  - Dashboard auth → view → action flow

- [ ] **Security tests**:
  - SQL injection attempts on every endpoint
  - Auth bypass attempts
  - Rate limit verification
  - Input fuzzing on ingest

**Deliverable:** `pytest --cov=src` shows 80%+. CI green.

---

### Chunk 5.2: Documentation & README (Day 23)

- [ ] **README.md** — Complete rewrite:
  - Architecture diagram (ASCII art, updated)
  - Quick start guide (docker-compose up → working in 5 minutes)
  - Feature showcase with screenshots
  - API reference (link to Swagger)
  - Rule writing guide
  - AI features guide
  - Contributing guide

- [ ] **DEPLOYMENT.md** — How to run in production:
  - Environment setup
  - Security hardening checklist
  - Backup & recovery
  - Monitoring the SIEM

- [ ] **RULES.md** — Detection rule reference:
  - Complete list of rules with MITRE mapping
  - How to write custom rules
  - Rule testing workflow

- [ ] **AI.md** — AI features deep dive:
  - How NL→SQL works
  - Alert triage model training
  - UEBA behavior baselines
  - Prompt injection defenses

**Deliverable:** Someone can clone the repo and have it running in 15 minutes.

---

### Chunk 5.3: Demo & Walkthrough (Day 24)

- [ ] Create `scripts/demo.sh` — one command to:
  - Start Docker stack
  - Run database migrations
  - Seed realistic attack data
  - Start API
  - Start dashboard

- [ ] Create attack simulation scenarios:
  - Scenario 1: SSH brute force → detection → AI explanation → block IP
  - Scenario 2: Reverse shell → detection → process kill → case
  - Scenario 3: Data exfiltration → detection → NL query "who's sending the most data?" → hunt

- [ ] Record a 5-minute walkthrough video (or animated GIFs for README)

**Deliverable:** `./scripts/demo.sh` → working SIEM with realistic data in 2 minutes.

---

### Chunk 5.4: Portfolio Integration (Day 25)

- [ ] Push to GitHub with clean history
- [ ] Update `raphael-v4` portfolio site:
  - Project 006: SecurityScarletAI
  - Badge: "AI-Native SIEM · 45+ Detection Rules · NL→SQL · MITRE ATT&CK"
  - Link to GitHub repo
- [ ] Add to LinkedIn "Projects" section
- [ ] Write a blog post / LinkedIn article:
  - "I Built an AI-Native SIEM from Scratch — Here's What I Learned"
  - Architecture decisions, AI trade-offs, security lessons
- [ ] Pin on GitHub profile (consider swapping with one of the existing pins)

**Deliverable:** SecurityScarletAI is a visible, demonstrable portfolio piece.

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Detection Rules | 45 ✅ | 45+ ✅ |
| Test Coverage | ~60% (108 tests) → 297 tests | 80%+ (297 tests) |
| SQL Injection Vulns | 0 ✅ | 0 ✅ |
| Hardcoded Secrets | 0 ✅ | 0 ✅ |
| Lint Errors | ~20 (line length) → clean except 1 intentional | 0 (justified noqa) |
| Ruff Security Errors | 1 intentional S608 noqa | 1 intentional S608 noqa |
| AI Features Working | 7 of 7 ✅ | 7 of 7 ✅ |
| Dashboard Pages | 4 of 7 → 7 of 7 ✅ | 7 of 7 ✅ |
| MITRE ATT&CK Coverage | 40+ techniques ✅ | 40+ techniques ✅ |
| API Endpoints | ~38+ ✅ | 38+ ✅ |
| Dashboard DB Access | 3 files direct SQL → 0 | 0 (100% API) ✅ |
| Dashboard Auth | Hardcoded token → JWT with RBAC | JWT with RBAC ✅ |
| Dashboard Loading States | 0 → All views with spinners/status | All views ✅ |
| Dashboard Auto-Refresh | Broken time.time() hack → streamlit-autorefresh | Configurable ✅ |
| Dashboard Notifications | None → st.toast on all actions | All actions ✅ |
| Dashboard CSS Polish | None → Full dark theme + animations | Dark theme + animations ✅ |
| passlib/bcrypt compat | Broken → Fixed | Fixed (bcrypt direct) ✅ |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| pySigma integration breaks existing rules | Medium | High | Test all 6 existing rules against pySigma before migrating |
| Ollama model unavailable during demo | High | Medium | Template fallbacks for all AI features |
| Scope creep — too many features, ship nothing | High | Critical | Stick to chunk plan. Ship per chunk. |
| PostgreSQL version conflicts | Medium | Low | Use Docker, avoid Homebrew dependency |
| Dashboard Streamlit limitations | Medium | Medium | Accept Streamlit's constraints. Polish, don't rebuild. |

---

## What We're NOT Doing (Scope Boundaries)

- ❌ Replacing Streamlit with React (too much work, not portfolio value)
- ❌ Multi-tenant / multi-org support
- ❌ Cloud deployment (AWS/GCP) — local only
- ❌ SIEM feed integrations beyond free tiers
- ❌ Custom ML model training from scratch (use sklearn)
- ❌ Mobile app / native clients
- ❌ Compliance reporting (SOC 2, PCI) — mention but don't build
- ❌ Full Sigma spec compliance — use pySigma for that

---

## Daily Check-in Format

After each chunk, update this file with:
- [x] Completed items
- Bugs found during implementation
- Decisions made
- Blockers

Let's build this. 🔨