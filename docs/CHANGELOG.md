# Changelog

Fixes shipped on SecurityScarletAI, newest last. This is the **public** record
of what was fixed — it lists resolved issues, not open ones. The full
finding-by-finding catalog (the audit that produced these fixes) is kept
locally, out of the public repo.

Severity key: **P0** = exploitable / ship-blocker · **P1** = control-bypass or
data-integrity gap · **P2** = quality / slop / doc drift.

## 2026-09-02 — Phase 2 (hard boundaries)

Merged to `main`. Each fix shipped on its own branch via `--no-ff` merge;
tests went 1473 → 1525 passed (unit, `--no-cov`).

- **P2.1** `fix/redis-degradation` (`98189b4`) — the documented "fails back
  to in-memory" rate-limit fallback never existed (Redis storage connects
  lazily, so the construction-time try/except was dead code; a dead Redis
  500'd every rate-limited request). Now `in_memory_fallback_enabled=True`:
  storage failures are caught at REQUEST time, checks serve from a
  memory-backed strategy, and the backend is re-probed with exponential
  backoff to recover without a restart. Redis client converted to
  `redis.asyncio` (P2-32): revocation checks, blocklist, and lockout ops no
  longer block the event loop (F-08 bounded-retry + cooldown preserved,
  awaited backoff). Fail-open semantics unchanged.
- **P2.2** `fix/stream-cap-request-body` (`8cf54ca`) — chunked request
  bodies were buffered ENTIRELY in RAM before the 1 MB check (memory-DoS:
  any chunked uploader pinned unbounded RAM per request). The stream is now
  consumed in chunks and aborted with 413 the moment the cap is exceeded.
  Hardening bonus: garbage/negative/conflicting Content-Length headers
  return 400 instead of raising ValueError → 500 (also kills a request-
  smuggling primitive).
- **P2.3** `fix/pagination-bounds` (`36e974f`) — `/alerts` (≤1000), `/cases`
  (≤500), and `/correlation/matches` (≤1000) now bound their pagination via
  Annotated Query constraints (`?limit=10000000` used to pull the whole
  table into memory; logs/audit were already bounded, these weren't).
- **P2.4** `fix/ws-backpressure` (`9d3397f`) — WebSocket broadcast moved off
  the ingest hot path into the per-batch background task (one slow
  dashboard socket used to stall event ingestion), and every send is
  capped with a 1 s `asyncio.wait_for` — slow clients get EVICTED, not
  waited on. F-16 filter semantics unchanged.
- **P2.5** `fix/ti-negative-cache` (`bcbb9ce`) — every IOC-cache miss fired
  a LIVE AbuseIPDB check (attacker-sprayed fresh IPs burned the daily
  quota, leaving enrichment blind). Clean results are now negative-cached
  in Redis for 1 h, live calls are capped by an hourly budget (default
  500, env `ABUSEIPDB_HOURLY_BUDGET`), API errors are never cached as
  clean, and Redis-down = documented fail-open.
- **P2.6** `fix/scoped-ingest-token` (`122483b`) — a leaked static bearer
  was FULL ADMIN everywhere. New optional `INGEST_BEARER_TOKEN` is
  viewer-class and honored ONLY on the ingest router: `get_current_user`
  rejects it on every other endpoint, `get_ingest_client` (new, wired to
  `/ingest`) accepts admin bearer + dashboard JWTs + the scoped token.
  Unset → byte-for-byte pre-P2.6 behavior.
- **P2.7** `fix/ml-off-event-loop` (`51497d6`) — `/ai/train` (and the
  hourly auto-train) froze the whole API for the fit duration: RF fit,
  CV score, the v2 per-fold CalibratedClassifierCV loop, the final
  calibration fit, and UEBA's IsolationForest all ran synchronously inside
  async methods. All CPU-bound blocks now run via `asyncio.to_thread`;
  thread-identity tests pin the behavior.
- **P2.8** `fix/sigma-limits-rules-validation` (`8145c5d`) — simple
  detection queries carry a parameterized LIMIT (`MAX_DETECTION_ROWS`
  = 1000); rules API bounds create + patch: `run_interval` ≥30 s, lookback
  ≤24 h, threshold ≥1, severity restricted to the known enum (off-enum
  values 500'd on the DB enum — now a clean 422).

## 2026-09-01 — Phase 1 (trust & truth)

Merged to `main`. Each fix shipped on its own branch via `--no-ff` merge;
tests went 1450 → 1473 passed (unit, `--no-cov`).

- **P1.1** `fix/dashboard-esc-huntview` (`7af9554`) — alerts-view stored XSS
  fixed at the `_note_card_html` / `_expander_title` choke points (esc()
  everywhere, MITRE tags escaped; esc-sweep tests extended) and three dead
  API-shape paths in hunt_view repaired (`_summarize_gaps`, `_group_templates`,
  `_hunts_for_alert`). New `tests/unit/test_hunt_view_shapes.py`.
- **P1.2** `fix/demo-seed-gate` (`9c61293`) — demo seeding (synthetic alerts
  AND the publicly documented `demo_analyst` credential) previously ran
  unconditionally from the Docker entrypoint on any first boot. Now opt-in via
  `DEMO_SEED_ENABLED=true` — gated in `settings`, `seed_demo_data.py`, the
  entrypoint, and compose passthrough; docs + troubleshooting updated.
- **P1.3** `fix/llm-fence-risk-score` (`b3f41c1`) — the two unfenced LLM
  paths re-fenced (LLM01 regression): `build_prompt` fences ingest-fed
  `host_name` + evidence; `_suggest_hunts_for_alert` fences `host_name`.
  LLM risk_score validated before returning — non-numeric/bool → 50,
  out-of-range clamped to [0, 100] (a string verdict previously crashed
  `enrich_alert` and aborted the rule's alert loop).
- **P1.4** `fix/hunt-from-alert-quota` (`2196144`) — `/hunt/from-alert` now
  carries the 30-per-5-min LLM limit keyed by `user_or_ip_key` (the quota
  hole let a user bypass the LLM budget); dashboard client passes the
  60 s AI timeout on that path.
- **P1.5** `fix/secret-placeholder-gate` (`e2c19d6`) — fail-closed: startup
  rejects `CHANGE_ME` placeholders on `API_SECRET_KEY` and `API_BEARER_TOKEN`
  (joining `DB_PASSWORD`), with the `openssl rand` command in the error.
- **P1.6** `fix/f10-dedup-payload` (`49bf287`) — correlation dedup now
  actually dedups: the dupe comparison excludes the per-match uuid4
  `correlation_id` (the full payload never matched, so rows piled up
  unboundedly).
- **P1.7** `fix/truth-pass-docs-csv` (`cb14869`) — truth pass:
  `docs/RULES.md` regenerated from the real 100 rule files (was "45");
  CSV export guards formula injection (`=`, `+`, `-`, `@` cells quoted,
  hostile-host test); `docs/AI.md` training-label description matches the
  code (`resolved`/`closed` = 1, `false_positive` = 0); README Status line
  states the real test count and date; dead internal link removed.

## 2026-08-26 — Phase 1 + Phase 2 (production-hardening)

Merged to `main` (final `793186a`). Each fix shipped on its own branch via
`--no-ff` merge; tests went 1218 → 1258 passed.

- **P0-A** `fix/nl2sql-table-allowlist` (`a20e79f`) — NL→SQL now enforces a
  `{logs, alerts}` table allowlist (sqlparse FROM/JOIN extraction, recursive
  for subqueries/CTEs) in `validate_sql_structure` before execution. A crafted
  question targeting `siem_users.password_hash` is rejected, never executed.
  README's "parameterized SQL" claim corrected (the AI path is regex-filtered
  raw execution, not parameterized; the Sigma path IS parameterized). +9 tests.
- **P1-A** `fix/jwt-type-claim-enforcement` (`be4d249`) — `verify_jwt` /
  `get_current_user` reject `type != "access"`. A refresh token (7d) no longer
  works as an access token on every endpoint. Drive-by: switched `auth.py` to
  structlog `get_logger` (the stdlib `logging` call was a latent `TypeError`). +6 tests.
- **P1-B / P2-12** `fix/force-password-change-token-scope` (`c8e41fa`) — new
  `verify_force_change_token` dependency (the ONLY path accepting a force
  token). `verify_jwt`/`get_current_user` reject `force_password_change: True`,
  so the must_change_password control is no longer bypassable for the 15-min
  TTL. `/force-change-password` sets a `user_revoke_marker` so the force token
  dies on success. +6 tests.
- **P0-B** `fix/prod-dashboard-jwt-only` (`b5e69fe`) — `DASHBOARD_API_TOKEN` =
  admin; the dashboard skips login when set. Added a loud startup warning
  (warnings.warn + stderr), a commented Caddy `basicauth` block + note, a
  DEPLOYMENT "Dashboard exposure" section, and a README correction. Prod
  overlay already defaults the token to empty (JWT-only); now explicit.
- **P1-D** `fix/retention-and-brin-index` (`64a82d0`) — new
  `src/services/retention.py`: APScheduler job (hourly) deletes rows older
  than env-configurable windows (LOGS=30d, ALERTS=180d, AUDIT=365d,
  CORRELATION=90d, AI_USAGE=90d) in batched parameterized DELETEs
  (CTE + LIMIT + FOR UPDATE SKIP LOCKED; capped loops). 0 = keep forever.
  BRIN index on `logs(time)` + TimescaleDB upgrade note. +7 tests.
- **P1-E** `fix/writer-backpressure-and-dead-letter-replay` (`c2c808f`) —
  `LogWriter` buffer capped at `MAX_BUFFER` (10× batch); when full, `write()`
  flushes first (backpressure, not OOM). New `scripts/replay_dead_letter.py`
  reads `data/dead_letter/*.jsonl`, re-ingests via the writer, moves replayed
  files to `processed/`. Entrypoint runs it on boot (best-effort, non-fatal). +5 tests.
- **P1-C** `fix/audit-append-only-hardening` (`793186a`) — README's "append-only
  with REVOKE hardening" was false (the REVOKE was a schema COMMENT, never
  applied, and can't bind in the default single-role deploy — the app role owns
  the tables; owners bypass REVOKE). New `scripts/harden_audit.sql` (superuser,
  two-role deploy), `scripts/check_audit_grants.py` (reports real grant state;
  `--strict` for gates). Entrypoint applies it when `DATABASE_SUPERUSER_URL`
  is set, else prints a convention-only notice. README/DEPLOYMENT corrected. +7 tests.

## 2026-08-22 → 2026-08-25 — production-readiness fix pass

The fix pass that closed the original 59-finding audit. One line per fix;
commits are the `sha` prefixes. Grouped by the pass that shipped them.

### Pass 1 — schema / boot / Sigma path (`0edaa14`)
- **P0-02** — `logs.id` BIGINT PK; `correlation_matches.trigger_event_id` INT→BIGINT.
- **P0-03** — `logs.severity` TEXT column + writer inserts it.
- **P0-05** — entrypoint applies schema via `psql -v ON_ERROR_STOP=1` (statement-by-statement, no all-or-nothing rollback).
- **P0-06** — Dockerfile: deleted stale `COPY alembic/ alembic.ini`.
- CREATE TYPE idempotency (`DO $$ EXCEPTION duplicate_object`).

### Pass 2 — Sigma parser / execution (`359a339`)
- **P0-01** — `sigma_to_sql` routes through the legacy `SigmaParser` only; all 45 rules execute against real Postgres.
- **P0-04** — deleted the dead pySigma parse path (`_parse_with_pysigma`).
- **P2-42** — `SigmaParser._parse_condition` plain `and` support (webshell_creation).
- **P1-04** — `reverse_shell.yml` + `ssh_success_after_failures.yml` duplicate-key YAML fixed.
- **P2-10** — `to_sql` parses the condition once (was double-parse leaving untyped unreferenced placeholders).
- INET LIKE `host(col)::text` + Sigma `'*'` → `IS NOT NULL` (unflagged INET runtime bugs surfaced by the execution test).

### Pass 3 — ingest / correlation enrichment (`8d357de`, `7890108`)
- **P0-03** (completion) — `severity` verified in the `detect_defense_evasion_cleanup` query.
- **P1-07** — ingest writes enrichment back to `logs.enrichment` JSONB; `LogWriter.flush()` added.
- **P1-16** — `IngestEvent` adds `process_cmdline`/`process_path`/`host_ip`; seed sets `process_cmdline`.
- **P1-06** — `run_all_correlations(persist=True)` calls `create_alert(rule_id=None)` per match; dedup by `rule_name+host_name`.
- **P1-13** — ingest loop broadcasts each event to `/ws/logs` via `broadcast_event` (best-effort).
- **P2-28** (partial) — deleted the dead `run_all_correlations_legacy` wrapper.

### Pass 4 — provenance / risk / auto-train (`6338cf0`)
- **P1-08** — `_write_provenance` uses `json.dumps` for JSONB; provides `model_hash`/`training_samples`/`cv_accuracy` (NOT NULL).
- **P1-09** — `calculate_asset_risk` exposure query moved inside the async-with block.
- **P1-10** — `get_top_risk_assets` rewritten (joined outbound-conns subquery).
- **P2-25** — `schedule_rules` schedules `auto_train_check` hourly.

### Pass 5 — auth hardening (`52ed123`)
- **P1-11** — `get_current_user` enforces jti blocklist + user_revoke via shared `_check_revocation`.
- **P1-12** — rule mutations require admin role; viewer gets 403.
- **P1-14 / P2-41** — `seed-admin` localhost-only + `must_change_password=TRUE`; dashboard button + admin/admin text removed.
- **P2-23** — `log_audit_action` no longer raises (logs + returns None); audit added to rule/alert mutations.
- **P2-24** — `alerts.py` uses `user.get("sub")` not `str(user)` for author/created_by/updated_by/assigned_to.
- **P2-40** — dashboard logout POSTs `/auth/logout` (server-side blocklist) before clearing the session.

### Pass 6 — dashboard field-shape fixes (`d9f447a`)
- **P1-15** — `RuleResponse` exposes `mitre_tactics`/`techniques`/`sigma_yaml`/`run_interval`/`lookback`/`threshold`; `from_row` serializes intervals.
- **P2-43** — `PATCH /rules/{id}` partial update; dashboard `update_rule` uses PATCH; dashboard field-shape fixes (prediction string, matching_hunts+llm_suggestions, is_trained/training_samples/training_accuracy/ollama_available, templates description+id).
- **P2-39** — sidebar AI Triage uses `is_trained`.
- **P2-20** — `PUT update_rule` re-parses `sigma_yaml` + refreshes MITRE.
- interval params use `timedelta` (asyncpg str→interval bug); `scheduler.start()` idempotent.

### Pass 7 — prod proxy / threat intel / osquery / health (`3a4897a`)
- **P1-17** — Caddyfile `handle_path` → `handle /api/*` (preserve the `/api` prefix the FastAPI app requires).
- **P2-17** — threat-intel initial refresh runs as a background task (non-blocking startup).
- **P2-37** — `osquery.conf` `logger_path` aligned; unmapped tables documented as intentional.
- **P2-31** — docker-compose `OLLAMA_MODEL` default aligned. *(Note: later re-corrected to `mistral:7b` — the verified running model — in the 2026-08-26 docs-honesty pass.)*
- **P2-34** — `/health` caches the Ollama probe (60s TTL).
- **P2-16** — startup `validate_ollama_model` warns on result (was discarded).
- **P2-35** — cases link/unlink/note + alerts `link_to_case` use atomic SQL (`array_append`/`remove`, `notes || jsonb`).

### Pass 8 — dead code / cleanup (`53cedb0`)
- **P2-07** — `FileShipper` docstring corrected (polling, not watchfiles).
- **P2-13 / P2-28** — dead code deleted (`get_sequence`, `suggest_hunting_queries`, `get_hunt_history`, `summarize_multiple_alerts`, `suggest_investigation_steps`, `calculate_severity_boost`, `send_email_notification`, `send_daily_summary`).
- **P2-14** — unused `JWT_EXPIRY_HOURS` removed.
- **P2-15** — `AuditLogMiddleware` best-effort decodes JWT to attribute actors/role.
- **P2-18** — MITRE STIX master-vs-v14 drift documented (accept).
- **P2-19** — nl2sql `add_safety_limits` whitespace-tolerant `)\s+SELECT`; comment-check + EXPLAIN-failure limits documented.
- **P2-27** — `GET /hunt/history` removed from the hunt.py docstring (function already deleted).
- **P2-29** — stale/broken `scripts/demo.sh` deleted (port conflict, unreferenced).
- **P2-30** — `make migrate` uses `psql -v ON_ERROR_STOP=1`.
- **P2-32** — sync redis in async auth paths documented as follow-up (socket_timeout bounds; switch to redis.asyncio at scale).
- **P2-33** — correlation `_unwrap`/`_parse_as_of` left as-is (acceptable test-coupling).
- **P2-36** — `execute_hunt` forwards actor; `save_hunt_history` records the analyst, not `hunting_assistant`.
- **P2-44** — `generate_attack_data` brute-force fixture adds `local_address` so the parser extracts `source_ip`.
- **P2-11** — moot (pySigma parse path deleted in P0-04).
- **P2-21** — `send_email_notification`/`send_daily_summary` deleted as dead code (send_alert_notification is the only wired path).

### Pass 9 — rules reconcile / writer / correlation docs / geoip (`fa9c6fd`)
- **P1-05** — `load_sigma_rules` reconciles every boot (upsert by name, preserve operator state, log db-only orphans).
- **P2-08** — dead-letter writes one event per line (true JSON-Lines).
- **P2-09** — correlation `as_of` docstrings corrected to `datetime.now(timezone.utc)`.
- **P2-12** — lifespan calls `close_geoip_reader()` on shutdown.
- **P2-22** — `FileShipper` checkpoint path per-instance (defaults to legacy global).

### Pass 10 — chat / CI (`39155e9`, `4e1b210`)
- **P2-26** — chat forwards the authenticated user to cost tracking; `session_id` threaded as correlation key (multi-turn memory documented as not implemented).
- **P2-38** — CI builds the Docker image + applies schema (`ON_ERROR_STOP=1`) + runs integration tests (were skipping); fixed two wrong integration test contracts (`get_alert_stats` int, dedup returns -1).
## 2026-08-28 — Post-audit remediation (8 branches, dashboard + AI + auth + deploy + resilience + hygiene)

Phase 1–6 of the 08-28 double-sweep remediation plan (findings F-01…F-26).
Each phase shipped on its own branch, gated (ruff src+dashboard · mypy src ·
pytest) and merged `--no-ff`. Tests 1343 → 1438.

- **`fix/dashboard-esc-sweep`** — every data-derived value rendered inside
  `unsafe_allow_html=True` is escaped (case titles/notes/assignments, metric
  labels incl. ingestion-fed host names, badge labels, sidebar username);
  logout() now posts to the client's own base_url (F-01/F-02/F-19).
- **`fix/llm-content-fencing`** — NEW `src/ai/untrusted.py`: untrusted log
  data enters prompts only inside explicit data fences with
  neutralized escape sequences (OWASP LLM01:2026); `ai_generated` labeling
  end-to-end (F-06).
- **`fix/llm-rate-quota`** — per-user LLM quota (30/5min default,
  `LLM_RATE_LIMIT`) on /ai/chat, /ai/explain, /query, /hunt execute, keyed
  by authenticated sub (OWASP LLM10) (F-14).
- **`fix/lockout-and-revocation-robustness`** — composite login lockout
  (per-(user,ip) counters, exponential 15m→1h→6h, distributed-noise no-lock)
  replaces the flat renewing lockout DoS; Redis client bounded-retry +
  cooldown; user_revoke fixed-key (O(1) read); /auth/refresh honors
  must_change_password; disabled/locked login branches burn bcrypt
  (F-05/F-08/F-09/F-11/F-15).
- **`fix/prod-deploy-hardening`** — prod overlay revokes DB/redis host
  ports (only Caddy publishes 80/443), redis requirepass enforced, uvicorn
  trusts XFF from private ranges, static-bearer audit rows attributed,
  platform pins removed, containers capped (F-04/F-07/F-21/F-26).
- **`fix/ingest-pipeline-backpressure`** — reverse-DNS off the event loop
  (bounded pool); correlation capped/coalesced/deduped; WS filters honored
  + registry capped; fire-and-forget tasks GC-referenced; enrichment
  write-back IP-keyed; sigma missing selection parses FALSE (F-03/F-10/
  F-16/F-17/F-18/F-20).
- **`fix/hygiene-deps-ci`** — dead deps dropped (passlib, sqlalchemy, black);
  redis pinned >=6,<9; CI gains a scripts/+tests/ lint gate (was a 195-error
  blind spot); README gains an honest Limitations section; PyJWT migration
  filed as backlog (F-25).

## 2026-09-02 — Phase 3 (product & proof) + v0.2.0

Merged to `main`; tagged `v0.2.0` (Phase 1–3 remediation complete). Each item
shipped on its own branch via `--no-ff` merge; tests went 1525 → 1640 passed
(unit, `--no-cov`), coverage 86% → 87% (CI-enforced ≥80%).

- **P3.1** `feat/user-management-api` (`e0794ca`) — admin-only user
  management API: `GET /users` (never exposes password_hash — excluded from
  the response model AND the SQL), `POST /users` (hashed password, role
  enum, `must_change_password=true`, duplicate → 409), `PATCH /users/{id}`
  (role change + is_active toggle; deactivation AND role change set the
  Redis user_revoke marker — the JWT carries the role claim, so pre-change
  tokens must not survive a demotion; self-guard prevents an admin from
  deactivating themselves or changing their own role), and
  `POST /users/{id}/reset-password` (one-time `secrets.token_urlsafe(16)`
  password returned once in the response, never logged, never in the audit
  entry; lockout state cleared; older tokens revoked). Every mutation
  audit-logged with actor + IP. DEPLOYMENT.md's raw-SQL password reset
  replaced with the API path.
- **P3.2** `fix/wire-request-body-hash` (`d962e79`) —
  `audit_logs.request_body_hash` was plumbed end-to-end but never written
  (always NULL). Now: RequestValidationMiddleware sha256-hashes size-bounded
  POST/PUT/PATCH bodies ≤ 64KB onto `request.state` (Starlette caches +
  replays the body downstream — bytes reach the endpoint intact,
  regression-tested at app level); AuditLogMiddleware passes the hash to
  the audit row. Bodies > 64KB stay NULL by policy ("not hashed", distinct
  from an empty body). 8 tests incl. chunked bodies and a full
  middleware-chain passthrough.
- **P3.3** `feat/prometheus-metrics` (`9d98426`) — `GET /api/v1/metrics` in
  Prometheus text format via a tiny in-process registry (zero new
  dependencies): HTTP request count + latency histogram by method +
  path-class (IDs/UUIDs/usernames normalized — cardinality control), ingest
  accepted, writer buffer depth + backpressure, DB pool in-use/size,
  correlation run duration, retention rows-deleted/errors. Access
  fail-closed: optional `METRICS_BEARER_TOKEN` or analyst JWT; token unset
  → localhost-only unauthenticated scrape; an invalid bearer is always 401
  even from localhost; malformed JWTs caught (no 500). Verified live:
  199 samples, path-class normalization and live gauges rendering.
- **P3.4** `chore/ops-honesty-sweep` (`001882e`) — Slack alert links use
  `DASHBOARD_PUBLIC_URL` (new setting) instead of a hardcoded localhost:8501;
  `/ai/status` uses the CACHED Ollama probe (the /health P2-34 cache) instead
  of a fresh 5s probe per call; `scripts/migrate_passwords.py` derives its
  DSN from settings (+asyncpg stripped) instead of the stale-DATABASE_URL
  footgun; PersistFlags-era `/correlation/run-legacy` removed after a
  verified zero-caller check (dashboard client, docs, tests).
- **P3.5** `chore/ci-dependency-image-scanning` (`3a0efaa`) — CI gains
  `pip-audit` (over the same locked dependency set the test job installs)
  and a Trivy HIGH/CRITICAL image scan. Both NON-BLOCKING for two weeks
  (continue-on-error, policy in the YAML); `.trivyignore` ships with zero
  CVE accepts — entries require CVE/GHSA ID + rationale + date, enforced by
  a unit test. Build/test jobs stay hard-failing.
- **P3.6** `test/llm-redteam-matrix` (`4d1b5be`) — OWASP LLM Top 10 (2025)
  matrix as a permanent 41-probe regression suite at the prompt boundary
  (no live Ollama): LLM01 direct+indirect injection against FOUR prompt
  surfaces (build_prompt, hunt suggestions, NL→SQL conversation context,
  chat security context) with fence-balance + outside-fence assertions;
  LLM02 synthetic-SQL validator bypasses (siem_users.password_hash via
  direct/UNION/JOIN, dblink, pg_read_file, pg_catalog, stacking, pt-BR
  comment obfuscation) — all rejected; LLM09 fallback labeling (no silent
  fabrication); LLM10 quota marking on all five LLM-costing endpoints.
  Findings: none new — Phase 1 fencing + M-07 redaction hold.
- **P3.7** full-stack local verification (colima vz VM) + two shipped
  findings: `fix/cors-env-parsing` (`954cf05`) — a P0 boot-blocker where
  docker-compose's bare-string `API_CORS_ORIGINS` default crashed every
  container boot at settings load (pydantic-settings demands JSON for list
  fields at the source level, before validators run); now NoDecode +
  tolerant validator (bare string, comma list, JSON — malformed JSON still
  fails loudly). And `fix/ai-status-test-seam` (`f55ceaa`) — a test left
  patching the pre-P3.4 probe seam passed only while another test primed
  the shared cache; now deterministic. DEMO.md §4 page-by-page verified
  against the live stack (see README Status): stats 35/12c/12h/9m/2l,
  35 alert rows, 20 logs, 3 cases, 15 TI, 100 rules, suppressions 200 `[]`
  (route-shadowing fix holding). Phase 1 XSS fix verified in rendered
  reality: a live-stored `<img src=x onerror=alert(1)>` note renders as
  escaped inert text in the dashboard's note card. Findings logged: host
  Ollama on this machine lacks `mistral:7b` (demo run used the documented
  `OLLAMA_MODEL` override); a fresh demo volume seeds only `demo_analyst`
  (DEMO.md §5's "admin exists" claim is stale — entrypoint bootstrap wrote
  no admin on this volume).

## 2026-09-03 → 2026-09-04 — Local production (real telemetry, hard boundaries, ops)

Raphael's mandate: "not a demo, not an online stack — a local program, safe,
in-house, AI connected." Executed as phased branches, each merged `--no-ff`
with CI green; tests went 1640 → 1683 passed, coverage holds 87%.

- **fix/slim-image-boot-deps + fix/test-redis-hermetic + fix/ci-provenance-db-seam
  + fix/trivy-action-pin (Sep 3)** — demo spin-up surfaced three real bugs
  (missing runtime deps in the slim image, test-isolation leak into the live
  Redis, CI postgres-dependent test, never-running trivy action).
- **vuln triage + fast-wins + Project A + Project C (Sep 3)** — 126 pip-audit
  findings triaged reachability-first → 9 → 2 risk-accepts; KEV
  CVE-2026-48710 killed via fastapi/starlette upgrade; trivy image scan at
  ZERO HIGH/CRITICAL; runtime image 1.83GB → 1.11GB (poetry evicted,
  multi-stage).
- **feat/local-telemetry-pipe (Sep 4)** — REAL host telemetry: zero-sudo
  osqueryd LaunchAgent (inside-.app-bundle execution, root-only path redirects,
  CLI-only flags), config/osquery.conf rewritten against live 5.23.1 schema
  checks (shell_history uid, sip_config columns, browser_plugins dropped), a
  read-only bind mount into the API, shipper enabled. Verified end-to-end:
  reverse-shell-pattern event → critical alert within one scheduler tick.
  Fixed live: shipper checkpoint at Path.home() (nonexistent in-container →
  duplicate re-ingest) → persistent data/ checkpoint; pydantic extra=forbid
  vs undeclared .env deployment keys; metrics tests pinning ambient env.
- **feat/local-prod-overlay (Sep 4)** — production cutover: loopback-only
  publishing (redis unpublished, closes the LAN-exposed unauthenticated Redis),
  requirepass enforced, DOCS_ENABLED=false, PASSWORD_PEPPER enforced
  (fail-fast), no-new-privileges + cap_drop, memory limits, dashboard
  live-reload mount removed, JWT-login default. Fresh volume; demo archived to
  data/backups/.
- **feat/local-prod-ops (Sep 4)** — DB-ENFORCED audit immutability: two-role
  deploy (owner applies schema via DATABASE_SUPERUSER_URL; restricted
  scarletai_app runs the API with INSERT/SELECT-only audit privileges;
  harden_audit.sql re-applied every boot; tamper UPDATE/DELETE/TRUNCATE all
  denied). scripts/backup_local.sh (verify-gated dumps, rotation, owner audit
  prune, RESTORE TEST against a throwaway postgres) + launchd nightly;
  scripts/health_watchdog.sh edge-triggered watchdog + launchd; enforcing-flip
  plan documented for Sep 16.
- **docs/readme-honesty-audit (Sep 4)** — full README/docs honesty pass:
  killed the vapor "syslog" ingest claim, fixed stale rule-category counts
  (9/8/7/6/10/5 → 14/34/17/17/12/6 = 100), test counts (1473/1656 → 1683),
  CI branch triggers, structure block (17 routers, missing modules), stale
  PHASE_PLAN.md deleted; PRODUCTION.md added to the docs set.
