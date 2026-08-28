# Changelog

Fixes shipped on SecurityScarletAI, newest last. This is the **public** record
of what was fixed — it lists resolved issues, not open ones. The full
finding-by-finding catalog (the audit that produced these fixes) is kept
locally, out of the public repo.

Severity key: **P0** = exploitable / ship-blocker · **P1** = control-bypass or
data-integrity gap · **P2** = quality / slop / doc drift.

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
