# SecurityScarletAI — Bug Catalog

**Created:** 2026-05-04  
**Branch:** `debug/code-quality-audit`  
**Auditor:** Lead Engineer / AI SIEM Specialist  
**Method:** Full codebase sweep — 120+ files, 8 parallel sub-agents, ~15K lines  

---

## Status Key

| Icon | Status |
|------|--------|
| 🔴 | Open — not started |
| 🟡 | In progress |
| 🟢 | Fixed |
| ⚪ | Won't fix (with reason) |

---

## Summary

| Severity | Count | Open | Fixed | Won't Fix |
|----------|-------|------|-------|-----------|
| 🔴 Critical | 18 | 18 | 0 | 0 |
| 🟠 High | 24 | 24 | 0 | 0 |
| 🟡 Medium | 22 | 22 | 0 | 0 |
| 🟢 Low | 12 | 12 | 0 | 0 |
| 🔵 Test Quality | 10 | 10 | 0 | 0 |
| **Total** | **86** | **86** | **0** | **0** |

---

## 🔴 CRITICAL (18)

| ID | Status | File(s) | Description | Fix Notes |
|----|--------|---------|-------------|-----------|
| C-01 | 🔴 | `src/api/auth_login.py:181-205`, `dashboard/auth.py:87-95` | Unauthenticated seed admin endpoint. Anyone hits POST `/auth/seed-admin` when siem_users empty → admin/admin created. Race condition: two requests both see count=0. | Add auth requirement OR rate limit OR remove endpoint. Add advisory lock for race condition. |
| C-02 | 🔴 | `src/detection/alerts.py:47-58` | Alert dedup race condition (TOCTOU). SELECT then INSERT not atomic. Concurrent requests bypass dedup window. | Use `INSERT ... ON CONFLICT DO NOTHING` with unique constraint on (rule_id, host_name, time_bucket). |
| C-03 | 🔴 | `src/detection/alerts.py:60-63` | Severity escalation race condition. COUNT read before current alert inserted. Concurrent alerts can both escalate or neither. Off-by-one in threshold. | Move escalation check after INSERT, or use serializable transaction. |
| C-04 | 🔴 | `src/detection/alerts.py:138` | Broken notification import. `from src.response.notifications import send_notification` — function doesn't exist. Every alert notification triggers ImportError, silently swallowed. | Replace with `from src.response.notifications import send_alert_notification`. |
| C-05 | 🔴 | `src/detection/alerts.py:490-491` | STIX indicator ID format invalid. `indicator--{d['id']:012d}` produces non-UUID. STIX pattern `[host_name = 'xxx']` is invalid syntax. All STIX consumers reject it. | Use `indicator--{uuid4()}`. Map host_name to valid STIX objects (network-traffic, process). |
| C-06 | 🔴 | `src/detection/correlation.py:41-47` | Invalid SQL in window function. `RANGE BETWEEN INTERVAL '1 minute' * $2 PRECEDING` — PostgreSQL doesn't support parameterized interval multiplication in window frames. Runtime crash. | Use `RANGE BETWEEN '$2 minutes'::interval PRECEDING` or restructure query. |
| C-07 | 🔴 | `rules/sigma/process/download_execute.yml`, `rules/sigma/process/encoded_command_execution.yml` | YAML duplicate keys. Two `process_cmdline|contains` keys → second overwrites first. 4 detection branches dead. download_execute only checks `sh` (not `curl`), encoded_command only checks `-d` (not `base64`). | Use list value: `process_cmdline|contains: [curl, sh]`. |
| C-08 | 🔴 | `rules/sigma/authentication/failed_login_spike.yml`, `rules/sigma/cloud/bulk_data_download.yml` | `count()` empty parens breaks aggregation regex. Pattern `([^)]+)` requires ≥1 char. Falls through to simple SELECT, no GROUP BY/HAVING. Spike detection dead. | Change rules to `count(*)`. Update regex to `count\(([^)]*)\)`. |
| C-09 | 🔴 | `src/detection/backends/postgresql.py:175-185` | `generate_query` crashes. `condition.detection_item` attribute doesn't exist on `SigmaDetectionCondition`. AttributeError at runtime. pySigma path falls back to legacy parser. | Fix attribute reference to match pySigma API (check `cond_parsed`, `post_conditions`, etc.). |
| C-10 | 🔴 | `ssh_success_after_failures.yml`, `impossible_travel.yml`, `login_unusual_geography.yml`, `data_exfiltration_volume.yml` | 4 Sigma rules trivially broad. Detection is just `event_type: start` or `event_category: network`. Matches everything. CRITICAL-labeled rules flood analysts with FPs. | Add specific detection logic: failed-then-success correlation, geo-distance check, volume thresholds. |
| C-11 | 🔴 | `rules/sigma/file/sensitive_file_access.yml` | Dead detection branch. `selection_hosts` defined but not referenced in condition. `/etc/hosts` modifications never detected. | Add `selection_hosts` to condition: `selection_shadow or selection_ssh or ... or selection_hosts`. |
| C-12 | 🔴 | `src/db/connection.py:14-28` | DB connection pool race condition. `get_pool()` checks `_pool is None` without lock. Two coroutines at startup create two pools, one orphaned. | Add `asyncio.Lock()` around pool creation. |
| C-13 | 🔴 | `src/api/websocket.py:22-23` | WebSocket token in query parameter. Logged by proxies, CDNs, browser history. Same JWT with 8-hour expiry. | Generate short-lived single-use WS tokens (5 min TTL) from dedicated endpoint. |
| C-14 | 🔴 | `dashboard/api_client.py:317,331,336` | Path traversal in API client. `f"/threat-intel/lookup/ip/{ip}"` — no sanitization. Input like `127.0.0.1/../../auth/seed-admin` creates path traversal URL. | URL-encode user inputs before interpolation. Validate IP/hash format before building URL. |
| C-15 | 🔴 | `src/ai/risk_scoring.py:210-220` | Cartesian product JOIN. `alerts a JOIN logs l ON l.user_name = $1` — no relationship between tables. 100 alerts × 5000 logs = 500K count. All user risk scores meaningless. | Separate queries: count alerts where host_name IN (SELECT DISTINCT host_name FROM logs WHERE user_name = $1). |
| C-16 | 🔴 | `src/ai/risk_scoring.py:50-60,130-145` | 35% of risk weight is dead. `anomaly_score` (25%) and `exposure_score` (10%) initialized to 0.0, never populated. Max achievable ~65/100. Critical risk (≥80) unreachable. | Wire UEBA anomaly and exposure scores into `calculate_asset_risk()`. |
| C-17 | 🔴 | `alembic.ini:70` | Hardcoded DB credentials in VCS. `postgresql://scarletai:password@localhost:5433/scarletai`. | Use env var: `sqlalchemy.url = %(DATABASE_URL)s`. Add `alembic.ini` to `.gitignore` or use `alembic.ini.example`. |
| C-18 | 🔴 | `src/intel/threat_intel.py` | IOC type mapping bug. `_map_ioc_type("domain") == "ip"` and `_map_ioc_type("email") == "ip"`. Domain/email IOCs looked up as IPs → false negatives. | Fix mapping: domain→"domain", email→"email". Add corresponding lookup paths. |

---

## 🟠 HIGH (24)

| ID | Status | File(s) | Description | Fix Notes |
|----|--------|---------|-------------|-----------|
| H-01 | 🔴 | `src/detection/correlation.py:197` | Missing `172.16.0.0/12` RFC1918 range in exfiltration correlation. Internal 172.16.x.x flagged as exfil. | Add `"172.16.0.0/12"` to RFC1918 filter list. Update $N params. |
| H-02 | 🔴 | `src/ai/nl2sql.py`, `QUERY_TEMPLATES["cron_scheduled"]` | SQL operator precedence bug. Missing parens around OR → matches ALL events with LaunchDaemons/cron paths. | Add parens: `WHERE event_category = 'file' AND (path ILIKE ... OR ...)`. |
| H-03 | 🔴 | `src/ai/nl2sql.py`, `QUERY_TEMPLATES["lateral_movement"]` | GROUP BY includes `time` (microsecond). Each group ~1 row. HAVING COUNT(*) > 10 never matches. Always empty. | Remove `time` from GROUP BY. Add MIN(time) to SELECT. |
| H-04 | 🔴 | `src/enrichment/pipeline.py:34-48` | GeoIP reader never closed. New Reader() per lookup. File handle leak under sustained ingestion. | Singleton reader initialized once at module level or startup. |
| H-05 | 🔴 | `src/detection/sigma.py:240-255` | `_map_field` allows unvalidated column names. Unknown fields pass through with only warning. | Raise ValueError instead of warning when field not in ALLOWED_COLUMNS. |
| H-06 | 🔴 | `src/detection/scheduler.py:45-70` | Scheduler double-update. `last_run` updated twice on match. Wasteful DB round-trip. | Move unconditional `last_run` update to else branch. |
| H-07 | 🔴 | `src/api/middleware.py:33` | Body size bypass via chunked transfer encoding. content-length check only fires when header exists. | Check `transfer-encoding: chunked` or use Starlette body size limiting. |
| H-08 | 🔴 | `src/api/websocket.py:82-104` | WebSocket broadcast race condition. `_connected_clients` modified during iteration → RuntimeError. | Use `asyncio.Lock` or copy list before iteration. |
| H-09 | 🔴 | `src/response/soar.py:88-92` | SOAR `_block_ip` shell command injection. IP interpolated into shell command unsanitized. | Validate IP format with `ipaddress.ip_address()` before interpolation. |
| H-10 | 🔴 | `src/response/soar.py:138-155` | SOAR playbook hardcoded "unknown" values. Ignores alert evidence. Block-IP tries to block "unknown". | Extract attacker_ip and target_user from `alert.get("evidence", {})`. |
| H-11 | 🔴 | `src/detection/alerts.py:326-349` | Suppression rule can globally suppress all alerts. Both rule_name and host_name can be None → matches everything. | Add constraint: at least one of rule_name or host_name must be non-None. |
| H-12 | 🔴 | `src/ai/hunting_assistant.py:120` | Hunt execution has no timeout. `HUNT_TIMEOUT_SECONDS = 10` defined but never used. Slow queries block pool. | Wrap `pool.fetch(sql)` with `asyncio.wait_for(timeout=HUNT_TIMEOUT_SECONDS)`. |
| H-13 | 🔴 | `src/ai/hunting_assistant.py:250-280` | Hunt history never actually saved. `save_hunt_history()` only logs, never inserts to audit_log. `get_hunt_history()` always empty. | Add INSERT to audit_log in `save_hunt_history()`. |
| H-14 | 🔴 | `src/db/writer.py:127-147` | Dead letter queue: unbounded disk growth. No size limit, rotation, cleanup, or replay. Extended DB outage fills disk. | Add max size per file, rotate daily, add cleanup job for files >30 days. |
| H-15 | 🔴 | `src/ingestion/shipper.py:56-60` | Log rotation detection flaw. Only checks `size < offset`. Misses same-size rotation, truncation. | Use file inode/device ID for rotation detection. |
| H-16 | 🔴 | `src/api/health.py:25` | Health check leaks internal error messages. `f"error: {str(e)}"` exposes DB connection details. | Return generic "database_error" without details. Log full error server-side. |
| H-17 | 🔴 | `scripts/backup.sh:25` | PGPASSWORD in process list. `PGPASSWORD="..." pg_dump` visible in /proc/*/environ. | Use `~/.pgpass` file. |
| H-18 | 🔴 | `scripts/backup.sh:52` | Syntax error. `$(date}` — `$(` opens command substitution but `}` closes variable. Runtime shell error. | Fix to `$(date)`. |
| H-19 | 🔴 | `scripts/backup.sh:39` | Failed backup never detected. After if/elif/else, $? is always 0. pg_dump exit code consumed. | Capture exit code before if statement. |
| H-20 | 🔴 | `docker-compose.yml:39-46` | curl healthcheck on slim image. `python:3.11-slim` doesn't include curl. Healthcheck always fails. | Use `wget` or Python-based health check. |
| H-21 | 🔴 | `alembic/versions/c54a2335ab60_phase2...py:6` | Alembic disconnected from base schema. `down_revision = None` skips base tables on fresh DB. | Create initial migration from schema.sql. |
| H-22 | 🔴 | `.github/workflows/ci.yml:14-17` | CI secrets hardcoded in plaintext. DB_PASSWORD, API_SECRET_KEY, API_BEARER_TOKEN as env vars. | Use `${{ secrets.* }}` GitHub Secrets. |
| H-23 | 🔴 | `scripts/seed_demo_data.py:220` | JSON serialization bug. `str(evidence).replace("'", '"')` corrupts values with apostrophes. | Use `json.dumps()`. |
| H-24 | 🔴 | `dashboard/auth.py:127-140` | Stale dashboard RBAC after server-side role change. Token verified once, cached forever. | Re-verify token periodically or on sensitive actions. |

---

## 🟡 MEDIUM (22)

| ID | Status | File(s) | Description | Fix Notes |
|----|--------|---------|-------------|-----------|
| M-01 | 🔴 | `src/ai/ueba.py:310` | Anomaly score can go negative or exceed 1.0. `1 - (raw_score + 0.5)` assumes range [-0.5, 0.5]. | Clamp: `max(0.0, min(1.0, 1 - (raw_score + 0.5)))`. |
| M-02 | 🔴 | `src/ai/ueba.py:170-190` | Session duration feature meaningless. MAX-MIN over lookback window = span, not session length. | Use session boundaries (login/logout pairs) or remove feature. |
| M-03 | 🔴 | `src/ai/ueba.py:210-240` | UEBA model trained on near-zero samples. 1 feature vector per user. With min_users=3, trains on 3 rows. | Aggregate per-session features, increase min_users, or document limitation. |
| M-04 | 🔴 | `src/ai/alert_triage.py:240-250` | Training accuracy measured on training set. Overfitting mask. | Use cross-validation or held-out test split. |
| M-05 | 🔴 | `src/ai/alert_triage.py`, `check_auto_train()` | Auto-train has no cooldown. Every call that passes threshold triggers retrain. | Add cooldown (e.g., don't retrain within 1 hour). |
| M-06 | 🔴 | `src/ai/nl2sql.py:300` | EXPLAIN query has no timeout. Complex queries make EXPLAIN itself expensive. | Add `asyncio.wait_for` with 5s timeout. |
| M-07 | 🔴 | `src/ai/nl2sql.py`, `ConversationContext` | NL→SQL context leaks raw SQL to LLM. Previous queries in prompt enable injection via column aliases. | Sanitize previous SQL before including in prompt. |
| M-08 | 🔴 | `src/ai/nl2sql.py`, `add_safety_limits()` | `add_safety_limits` breaks CTEs. Appends LIMIT after semicolons. | Detect CTEs and insert LIMIT before final SELECT. |
| M-09 | 🔴 | `src/ai/chat.py:150` | Chat prompt has stray double quotes. LLM receives `" "Be specific...`. | Fix f-string formatting in prompt construction. |
| M-10 | 🔴 | `src/api/auth.py`, `hash_password()` | Password truncation at 72 bytes is silent. No validation or user feedback. | SHA-256 pre-hash before bcrypt, or reject passwords >72 bytes. |
| M-11 | 🔴 | `src/detection/alerts.py:47-58` | Dedup returns wrong alert ID on suppression. Old ID → re-analyzes existing alert. | Return sentinel (e.g., -1) or None to indicate suppression. |
| M-12 | 🔴 | `src/detection/alerts.py:78-89` | Suppression ignores severity. Suppress-by-host suppresses even critical alerts. | Add severity column to suppression_rules, filter on it. |
| M-13 | 🔴 | `src/ai/risk_scoring.py`, `get_top_risk_assets()` | N+1 query. 50 hosts × 4 queries = 200 per dashboard load. | Batch into single query or use materialized view. |
| M-14 | 🔴 | `src/detection/mitre.py` | MITRE cache in home directory. Lost on Docker restart, no version in filename. | Move to `data/mitre_attack_cache.json` with version. |
| M-15 | 🔴 | `src/enrichment/pipeline.py:82-103` | Enrichment overwrites source/destination keys when source has no data. | Always nest destination enrichment under `enrichment["destination"]`. |
| M-16 | 🔴 | `scripts/seed_realistic_data.py:75` | Wrong variable name. Uses `API` (undefined) instead of `API_BASE`. Runtime NameError. | Fix to `API_BASE`. |
| M-17 | 🔴 | `docker-compose.yml:39-46` | Redis service defined but never used. No code references it. | Remove Redis from docker-compose or wire it in for rate limiting/sessions. |
| M-18 | 🔴 | `docker-compose.yml:28` | API service has no restart policy. Crashes → stays down. | Add `restart: unless-stopped`. |
| M-19 | 🔴 | `.github/workflows/ci.yml:14` vs `docker-compose.yml:5` | PG15 (CI) vs PG17 (Docker) version mismatch. | Align to same version. |
| M-20 | 🔴 | `src/ingestion/shipper.py:90-92` | Shipper checkpoint not atomic. Crash mid-write corrupts checkpoint. | Use `os.replace()` with temp file pattern. |
| M-21 | 🔴 | `src/api/auth_login.py:96-100` | Login re-acquires pool connection separately. User fetch and last_login update in two transactions. | Combine into single connection/transaction. |
| M-22 | 🔴 | `src/api/audit.py:46-48` | Audit log failure silently returns None. State-changing actions go unrecorded. | Raise exception or return error to caller. Log alert. |

---

## 🟢 LOW (12)

| ID | Status | File(s) | Description | Fix Notes |
|----|--------|---------|-------------|-----------|
| L-01 | 🔴 | `src/ai/alert_triage.py`, `src/ai/ueba.py` | Duplicate `_shannon_entropy` function. | Extract to `src/ai/utils.py`. |
| L-02 | 🔴 | `src/response/soar.py` | SOAR ISOLATE_HOST, DISABLE_USER, KILL_PROCESS not implemented. | Add stub implementations or remove action types. |
| L-03 | 🔴 | `src/response/notifications.py` | `email.mime.text` import inside function body. | Move to module level. |
| L-04 | 🔴 | `dashboard/cases_view.py:60` | Status filter string mapping bug. "In Progress".lower() → "in progress" (needs underscore). | Add `.replace(" ", "_")`. |
| L-05 | 🔴 | `dashboard/logs_view.py:25` | Time range filter does nothing. Assigned but never passed to API call. | Wire `time_range` into `api.get_logs()`. |
| L-06 | 🔴 | `dashboard/alerts_view.py:58-90` | No confirmation for destructive bulk actions. "Acknowledge All New" fires immediately. | Add confirmation dialog. |
| L-07 | 🔴 | `dashboard/ai_chat_view.py:80` | Chat history grows unbounded. Long sessions consume memory. | Cap history at last N messages (e.g., 50). |
| L-08 | 🔴 | `dashboard/rules_view.py:69-76` | Rule template `str.format()` breaks on user input with braces. | Use `str.format_map()` with dict or escape braces. |
| L-09 | 🔴 | `dashboard/api_client.py:120-122` | `logout()` doesn't clear all session state. Stale state on re-login. | Clear all auth-related session state keys. |
| L-10 | 🔴 | `scripts/analyze_alerts.py:26` | Bare `except:` clause. Catches KeyboardInterrupt, SystemExit. | Use `except (json.JSONDecodeError, ValueError):`. |
| L-11 | 🔴 | `dashboard/auth.py:127-140` | Dead code: `require_auth()` never called. Token never re-validated. | Call `require_auth()` on sensitive actions or remove dead code. |
| L-12 | 🔴 | `dashboard/main.py:381` | Dead code: unused import `render_alert_list`. | Remove import. |

---

## 🔵 TEST QUALITY (10)

| ID | Status | File(s) | Description | Fix Notes |
|----|--------|---------|-------------|-----------|
| T-01 | 🔴 | `test_alerts_full.py:285` | `link_to_case` test swallows all exceptions with `pass`. Test can never fail. | Remove blanket except. Test specific expected exceptions. |
| T-02 | 🔴 | `test_api_endpoints.py` | `test_password_truncation` asserts security vulnerability as correct. | Change test to warn about truncation or test pre-hashing. |
| T-03 | 🔴 | `test_auth_login.py:10-11` | Hardcoded fake bcrypt hash. `TEST_ADMIN_HASH` with repeating `b0b0b0` is fabricated. | Generate proper test hash with `bcrypt.hashpw()`. |
| T-04 | 🔴 | `test_enrichment_extra.py`, `test_soar.py`, `test_hunting.py` | Tautological assertions. `result is None or result is not None` always True. | Replace with meaningful assertions. |
| T-05 | 🔴 | `test_enrichment_pipeline.py:TestEnrichEvent` | Enrichment test never calls `enrich_event()`. Sets `result = event`. | Actually call the function being tested. |
| T-06 | 🔴 | `tests/integration/test_detection.py`, `tests/integration/test_ingestion.py` | Integration tests hit real DB without guards. Crash in CI. | Add `@pytest.mark.integration`, skipif for missing DB. |
| T-07 | 🔴 | `test_api_query.py` | Zero adversarial tests for NL→SQL injection. Most security-critical endpoint untested. | Add injection test cases: DROP TABLE, UNION SELECT, etc. |
| T-08 | 🔴 | All alert test files | No tests for concurrent alert creation. TOCTOU race in dedup untested. | Add concurrent creation test with asyncio.gather. |
| T-09 | 🔴 | `test_websocket_full.py` | Shared mutable global state. Manual save/restore of `_connected_clients`. | Use proper fixture/teardown pattern. |
| T-10 | 🔴 | `test_ai_triage.py` | Weak `or` assertion. `assert mock_model.train.called or result is True`. | Assert both conditions independently. |

---

## Architectural Concerns (Discussion Items)

| ID | Area | Description | Recommendation |
|----|------|-------------|----------------|
| A-01 | Schema | No proper migration system. Alembic configured but `target_metadata = None`. Schema changes undocumented. | Wire SQLAlchemy models into Alembic or create initial migration from schema.sql. |
| A-02 | Infra | Redis defined but unused in docker-compose. Wasted resources and attack surface. | Remove or wire in for rate limiting/sessions. |
| A-03 | API | In-memory rate limiting (slowapi). Resets on restart, no multi-instance sharing. | Use Redis-backed rate limiter. |
| A-04 | API | No pagination on most alert/log list endpoints. Dashboard fetches 1000 rows max. | Add cursor/offset pagination. |
| A-05 | Dashboard | 5× redundant API calls on overview. Each chart function fetches `api.get_alerts(limit=1000)` independently. | Fetch once, pass data to chart functions. |
| A-06 | CI | Integration tests not run in CI. Only `tests/unit/` executed. | Add integration test step with DB service. |
| A-07 | Auth | Static bearer token with no rotation or expiry. Full ingestion API access. | Add token rotation mechanism or short-lived tokens. |
| A-08 | Auth | JWT with no key rotation or token revocation. No `jti` claim. | Add `jti` for revocation. Document key rotation procedure. |

---

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-05-04 | Mackenzie 🔍 | Initial full codebase audit — 86 items catalogued |

---

_To update status: Change 🔴 → 🟡 (in progress) → 🟢 (fixed) or ⚪ (won't fix). Add comment in Fix Notes column._