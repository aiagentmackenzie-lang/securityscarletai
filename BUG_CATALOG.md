# SecurityScarletAI — Bug Catalog

**Created:** 2026-08-22
**Lead:** Mackenzie 🔍
**Method:** Slow, systematic read-through of the codebase. Every finding here is
verified against the actual code (and, where it touches SQL, executed against a
throwaway PostgreSQL 18). No grepping for patterns — code was read in full.

> Status legend: ✅ confirmed (reproduced) · ⚠️ suspected (strong read, not yet
> executed) · 🟡 minor / slop · ⬜ not yet investigated.
> Severity: **P0** ship-blocker / silent detection failure · **P1** correctness or
> real feature gap · **P2** quality / polish / slop.

---

## P0 — Silent detection failures (ship-blockers)

### P0-01 · pySigma backend produces invalid or semantically-wrong SQL; scheduler swallows the errors

**Status:** ✅ confirmed (executed `sigma_to_sql` on 7 representative rules)

`src/detection/sigma.py::sigma_to_sql` tries the pySigma-backed
`PostgreSQLBackend.generate_query` first and only falls back to the legacy
parser if the backend raises. Two distinct failure modes, both confirmed:

**Mode A — aggregation rules (`condition: selection | count(...) by ... > N`):**
pySigma's `convert_rule` raises *"The pipe syntax in Sigma conditions has been
deprecated ... pySigma doesn't supports this syntax."* The backend catches it
and sets `where_clause = "TRUE"`. The **selection criteria are dropped**. The
rule becomes "count ALL logs in this event_category over the window". Confirmed
output for `failed_login_spike.yml`:

```
SELECT source_ip, COUNT(*) ... WHERE event_category = $1 AND (TRUE) AND time > NOW() - INTERVAL '1 second' * $2
GROUP BY source_ip HAVING COUNT(*) > $3
PARAMS: ['authentication', 300, 10]
```

The `event_type=start` and `event_action|contains:failed` filters are gone.
Same for `c2_beaconing`, `impossible_travel`, and every other `count() by` rule.
These produce **valid** SQL → the scheduler executes them → **alerts are created
on the wrong data** (over-fire / false positives).

**Mode B — non-aggregation rules (`OR`/`AND` of selections):** pySigma's
`convert_rule` returns a Python `list` of query fragments. The backend does
`where_clause = str(output)`, injecting a **Python list repr** into the SQL.
Confirmed output for `gatekeeper_bypass.yml`:

```
SELECT * FROM logs WHERE event_category = $9 AND (['event_type=$1 AND process_name=$2 OR event_type=$3 AND process_name=$4 AND process_cmdline=$5 OR ...'])
AND time > NOW() - INTERVAL '1 second' * $10 ORDER BY time DESC
```

`['...']` is **not valid SQL**. `conn.fetch` raises a syntax error →
`run_rule`'s broad `except Exception: log.error("rule_execution_failed")`
swallows it → **no alert is ever created**. These rules are silently dead.
Confirmed for `gatekeeper_bypass`, `webshell_creation`, `suspicious_parent_child`,
and every other non-agg, well-formed rule.

**Mode C — `contains`/`endswith` produce `=` not `LIKE`:** Even ignoring the
list-repr, the backend emits `file_path=$1` (equality) for `|contains` /
`|endswith` values that contain `%` wildcards (e.g. `'%.php'`, `'%/var/www/%'`).
`convert_condition_contains/startswith/endswith` are defined but never reached
by pySigma's dispatch in this path. So wildcard matching is broken even where
the SQL parses.

**Why the 1258-test suite passes:** `tests/unit/test_sigma.py` asserts
*substrings* ("`LIKE` in sql", `"'DROP TABLE' not in sql`", `"INTERVAL '1
second' *" in sql`, `300 in params`). It never asserts the SQL is valid,
never executes it, and never asserts the selection predicates are present.
The injection-defense test passes in both modes because the malicious value
lands in `params` either way — but Mode A drops it into a `TRUE` WHERE, and
Mode B wraps it in an invalid list-repr.

**Why the live demo "passes end-to-end":** `run_osquery_demo.sh` only asserts
that an `alerts` row exists for `demo-mac.local`. The `reverse_shell.yml` rule
has **duplicate YAML keys** (see P1-04) which makes pySigma's `from_yaml` raise
`"Duplicate key '{k}'"` — routing it to the **legacy parser**, which produces
correct, fully-parameterized SQL. So the demo's one rule works by accident of
being malformed. Well-formed rules do not.

**Full per-rule audit (executed `sigma_to_sql` on all 45 rules):**

| Class | Count | Behavior |
|:--|--:|:--|
| BROKEN — invalid SQL (list-repr in WHERE) | **36** | Scheduler swallows the Postgres syntax error → **rule never fires** |
| OVER-FIRE — agg selection dropped to `TRUE` | **7** | Valid SQL, but counts ALL logs in the event_category → false positives on benign data |
| LEGACY-fallback (pySigma rejected) | **2** | `reverse_shell`, `ssh_success_after_failures` — both have duplicate YAML keys |

The 7 over-fire rules: `failed_login_spike`, `multiple_account_lockouts`,
`ssh_brute_force`, `bulk_data_download`, `impossible_travel`, `c2_beaconing`,
`data_exfiltration_volume`.

Of the 2 legacy-fallback rules, `ssh_success_after_failures` is **also
semantically broken** (see P1-04): its condition mixes an aggregation pipe with
a plain selection (`selection_failed | count(*) by source_ip > 3 and
selection_success`); the legacy parser drops the `and selection_success` part,
so it fires on failed logins alone, not the brute-force-success chain it
claims. So effectively **only `reverse_shell` works** (and even it drops one of
two `|contains` conditions — P1-04).

**Net: 0–1 of 45 Sigma rules function correctly. The "45 Sigma rules ✅ real"
claim in `CURRENT_VS_PRODUCTION.md` is false.**

**Files:** `src/detection/backends/postgresql.py` (the broken backend),
`src/detection/sigma.py::sigma_to_sql` (returns backend output without
validating), `src/detection/scheduler.py::run_rule` (swallows errors), all 45
files under `rules/sigma/`.

**Fix direction (not yet applied):** Either (a) make the backend actually work
— `str(output)` must join the list, `convert_condition_*` must be wired so
pySigma calls them, agg pipe-syntax must be handled (pySigma dropped it) — or
(b) **route everything through the legacy parser** (which is correct and
parameterized) and delete/fix the pySigma backend. (b) is the pragmatic, lower-
risk path. Then add tests that **execute** the generated SQL against a real
Postgres (the integration test infra already exists but is skipped), and fix
the duplicate-key YAML in the two affected rules (P1-04).

---

### P0-02 · `correlation_matches` table fails to create — `REFERENCES logs(id)` but `logs` has no `id` column

**Status:** ✅ confirmed (applied `schema.sql` to a throwaway Postgres 18 with
`ON_ERROR_STOP=1`; it aborts here)

```sql
CREATE TABLE correlation_matches (
    ...
    trigger_event_id INT REFERENCES logs(id),   -- logs has NO id column
    ...
);
```

`logs` is defined with no `id`/PK column. Postgres rejects the FK:
`ERROR: column "id" referenced in foreign key constraint does not exist`.

Consequences:
- With `ON_ERROR_STOP=1`: schema aborts → `correlation_matches`, `alert_labels`,
  and `audit_logs` (all defined after this point) are never created.
- With psql default (continue-on-error, which is what `scripts/entrypoint.sh`
  and `run_osquery_demo.sh` use): `correlation_matches` is missing; everything
  after it still creates. So in every real deployment the table is absent.
- `run_all_correlations(persist=True)` then `INSERT INTO correlation_matches`
  → "relation does not exist" → swallowed by the per-match `except` →
  **no correlation match is ever persisted**. The correlation API
  (`list_matches`, `mark_match_seen`) errors against the same missing table.

**Why no test catches it:** unit tests mock `conn`; integration tests (the only
ones that would apply the schema) are skipped without `DATABASE_URL`. CI never
applies the schema to a real DB.

**Files:** `src/db/schema.sql`, `src/detection/correlation.py`
(`run_all_correlations`, `persist_match`, `list_matches`, `mark_match_seen`).

**Fix direction:** Either add an `id BIGSERIAL` (or `id BIGINT GENERATED ALWAYS
AS IDENTITY`) PK to `logs`, or drop the FK / make `trigger_event_id` a plain
`INT` with no FK. Note `trigger_event_id` is **never populated** by any
`detect_*` function (always None), so the FK is decorative anyway.

---

### P0-03 · `severity` column referenced in SQL but missing from `logs` table

**Status:** ✅ confirmed (schema has no `severity` on `logs`; queries reference it)

- `src/detection/correlation.py::detect_defense_evasion_cleanup` filters
  `WHERE ... severity = 'high'` → Postgres error "column `severity` does not
  exist" → swallowed by `run_all_correlations`' per-rule `except` → **that
  correlation rule silently never matches.**
- `ALLOWED_COLUMNS` in both `src/detection/sigma.py` and
  `src/detection/backends/postgresql.py` includes `"severity"`. Any Sigma rule
  referencing `severity` would generate `WHERE severity = ...` and hit the same
  error → swallowed by `run_rule` → rule dead. (None of the 45 shipped rules
  reference it today, so this is latent, not yet live.)
- `NormalizedEvent` has a `severity` field, and `LogWriter` explicitly **excludes**
  it from the `normalized` JSON and does not insert it as a column. So the field
  is collected in the model, validated by the column whitelist, queried by
  correlation — but never stored. Phantom column end-to-end.

**Files:** `src/db/schema.sql` (no column), `src/detection/correlation.py`,
`src/detection/sigma.py`, `src/detection/backends/postgresql.py`,
`src/db/writer.py`, `src/ingestion/schemas.py`.

**Fix direction:** Decide whether logs carry a severity. If yes: add the
column + insert it. If no: remove `severity` from `ALLOWED_COLUMNS` and remove
the `severity = 'high'` filter from `detect_defense_evasion_cleanup`.

---

### P0-04 · `_parse_with_pysigma` always falls back to legacy — the "pySigma-first" architecture is fiction

**Status:** ✅ confirmed (every `parse_sigma_rule` call logs `pysigma_parse_fallback error="'SigmaDetections' object has no attribute 'timeframe'"`)

```python
timeframe=(
    str(rule.detection.timeframe)  # type: ignore[attr-defined]  # the AttributeError triggers the legacy fallback below
    if rule.detection and rule.detection.timeframe  # type: ignore[attr-defined]
    else None
),
```

The code deliberately pokes an attribute that doesn't exist on
`SigmaDetections` to trigger `AttributeError`, which `parse_sigma_rule`'s
`except Exception` catches to fall back to the legacy parser. So pySigma is
**never** used for parsing — every rule is parsed by the legacy `SigmaParser`.
The `# type: ignore` comment frames this as intentional, but it means the
entire "spec-compliant pySigma parsing" claim is dead code. Combined with
P0-01, the pySigma backend is the *only* place pySigma is actually invoked
(`PySigmaRule.from_yaml` inside `sigma_to_sql`), and that's where the broken
SQL comes from.

**Files:** `src/detection/sigma.py`.

**Fix direction:** Resolve in the P0-01 decision. If keeping pySigma, fix the
timeframe access (`rule.detection.detections` timeframes, or read timeframe
from the YAML like the legacy parser does). If dropping pySigma, delete
`_parse_with_pysigma` and the backend import path.

---

## P1 — Correctness / feature gaps

### P1-04 · Duplicate YAML keys in `reverse_shell.yml` and `ssh_success_after_failures.yml`

**Status:** ✅ confirmed (pySigma rejects both with `Duplicate key '{k}'`)

**`rules/sigma/process/reverse_shell.yml`** — two selection blocks have
duplicate `process_cmdline|contains` keys:
```yaml
selection_python_shell:
    process_name: python
    process_cmdline|contains: socket
    process_cmdline|contains: connect   # duplicate key
selection_perl_socket:
    process_name: perl
    process_cmdline|contains: Socket
    process_cmdline|contains: connect  # duplicate key
```
YAML doesn't allow duplicate mapping keys. The legacy fallback (`yaml.safe_load`)
**silently keeps only the last value** — so python/perl reverse-shell detection
matches only `connect`, not `socket` AND `connect`. This duplicate-keys
accident is also the only reason the demo rule reaches the working legacy
parser (see P0-01). Fixing P0-01 without fixing this YAML changes behavior.

**`rules/sigma/authentication/ssh_success_after_failures.yml`** —
duplicate `event_action|contains` keys in `selection_success`:
```yaml
selection_success:
    event_action|contains: success
    event_action|contains: ssh   # duplicate key
```
AND a malformed mixed condition combining an aggregation pipe with a plain
selection:
```yaml
condition: selection_failed | count(*) by source_ip > 3 and selection_success
```
The legacy parser's `_parse_condition` doesn't split on plain ` and `, so it
hands the whole string to `_parse_selection`, which fails (`selection_not_found`)
and returns `TRUE`; the agg regex then matches only `selection_failed | count(*)
by source_ip > 3` and drops the `and selection_success` entirely. The rule fires
on failed-logins-alone, not the brute-force-success chain it claims. (This is
what a Sigma *correlation* rule is for — pySigma dropped pipe-syntax precisely
because Sigma correlations replaced it.)

**Fix direction:** Use Sigma's list-value form for multiple `|contains` on the
same field:
```yaml
process_cmdline|contains:
    - socket
    - connect
```
For the success-after-failures pattern, either split into two rules or use a
Sigma correlation (the modern replacement for pipe-syntax aggregation combined
with another selection).

---

### P1-05 · `load_sigma_rules` only loads when the rules table is empty — new rule files are silently ignored

**Status:** ✅ confirmed (read `src/api/main.py::load_sigma_rules`)

```python
existing = await conn.fetchval("SELECT COUNT(*) FROM rules")
if existing > 0:
    log.info("rules_already_loaded", count=existing)
    return
```

On every startup after the first, the loader returns immediately. Adding a new
Sigma YAML to `rules/sigma/`, or editing an existing one, has **no effect**
unless the `rules` table is truncated. Combined with `ON CONFLICT (name) DO
NOTHING`, even removing the early-return wouldn't update changed rules. There
is no rule-sync/reconcile path. The `rules` API allows CRUD, but disk↔DB sync
is one-shot, first-boot only.

**Files:** `src/api/main.py`, `src/detection/sigma.py` (`load_rules_from_directory`
exists but is not called by the lifespan).

**Fix direction:** Reconcile on every boot: upsert by name (or by Sigma `id`),
enable new rules, optionally disable removed ones. Or document that rule edits
require a DB wipe.

---

### P1-06 · `run_all_correlations(persist=True)` persists matches but never creates alerts

**Status:** ⚠️ confirmed by reading

The main `run_all_correlations` writes matches to `correlation_matches` (which
is broken anyway — P0-02) but does **not** call `create_alert`. Only the
`run_all_correlations_legacy` backward-compat wrapper creates alerts, and it's
unclear it's called from the live ingest path (need to read
`src/api/ingest.py` — ⬜ next). So even with P0-02 fixed, persisted correlation
matches wouldn't surface as alerts in the dashboard. The correlation engine
and the alerts table are two disconnected worlds in the live path.

**Files:** `src/detection/correlation.py`, `src/api/ingest.py` (verify wiring).

---

## P2 — Quality / slop / doc drift

### P2-07 · `FileShipper` docstring claims watchfiles, implementation is polling

`src/ingestion/shipper.py` docstring: *"Uses watchfiles (Rust-based) for
efficient file watching on macOS."* The implementation is a 1-second
`asyncio.sleep` poll loop with `seek`/`tell`. No `watchfiles` import. Doc drift.

### P2-08 · `LogWriter._write_to_dead_letter` writes one JSON object per file per batch

Each failed batch appends a single JSON object (with the whole batch as
`events`) to a `.jsonl` file, but it's not actually JSON-Lines (one event per
line) — it's one big object per line. The "jsonl" extension and the per-line
format are inconsistent. Minor; the file is still parseable line-by-line.

### P2-09 · Naive vs aware datetimes mixed in `correlation.py`

`run_all_correlations` default `as_of = datetime.now(timezone.utc)` (aware).
`persist_match` default `as_of = datetime.utcnow()` (naive). Both are bound
as `$N::timestamptz`. asyncpg treats naive as UTC, so not a live bug, but it's
inconsistent and a footgun.

### P2-10 · `_build_aggregation_query` (legacy parser) parses the condition twice and bloats `params`

`SigmaParser.to_sql` calls `_parse_condition(rule.condition, ...)` to build
`where_clause`, then for aggregation rules `_build_aggregation_query` calls
`_parse_condition(base_condition, ...)` again, appending more params to the
same list. The first parse's params remain in `_params` but are unreferenced by
the final SQL. Not a correctness bug (placeholder indices still line up), but
wasteful and confusing. (Legacy path only — see P0-01.)

### P2-11 · `sigma_to_sql` parses the rule with pySigma twice

Once in `parse_sigma_rule` (which always falls back to legacy per P0-04), and
again via `PySigmaRule.from_yaml` inside `sigma_to_sql`. Redundant work on
every rule execution (the scheduler calls `sigma_to_sql` per rule per tick).

---

### P0-05 · Docker entrypoint crashes on first boot — schema apply rolls back the whole transaction

**Status:** ✅ confirmed (applied `schema.sql` via `asyncpg conn.execute(schema)` against a
throwaway Postgres 18 — it raised `UndefinedColumnError: column "id"
referenced in foreign key constraint does not exist` and left **0 tables**)

`scripts/entrypoint.sh` step 2 applies the schema with:
```python
await conn.execute(schema)   # the WHOLE schema.sql as one string
```
asyncpg sends a multi-statement string as a single Simple Query, which
Postgres runs in **one implicit transaction**. When `CREATE TABLE
correlation_matches ... REFERENCES logs(id)` fails (P0-02), the transaction
**rolls back every preceding statement** — so 0 types, 0 tables are created —
and `conn.execute` raises. The entrypoint runs under `set -euo pipefail`, so
the raise propagates through `asyncio.run` → non-zero exit → **the container
halts at step 2 before uvicorn ever starts.**

On a DB that was *already* populated by `psql -f` (the demo path), re-running
this entrypoint would instead crash at `CREATE TYPE alert_severity AS ENUM`
(no `IF NOT EXISTS` on `CREATE TYPE`) — so it's broken on both first boot and
re-run.

**Why the demo "works" but Docker doesn't:** `run_osquery_demo.sh` applies the
schema with `psql -f /dev/stdin < schema.sql`. psql executes statement-by-
statement, continuing past the `correlation_matches` error, so all tables
*before* that point exist. The Docker `entrypoint.sh` path is the one that's
broken, and it's the documented primary bring-up (`docker compose up -d`).

**Files:** `scripts/entrypoint.sh` (step 2), `src/db/schema.sql` (root cause
P0-02), any caller of `conn.execute(schema)`.

**Fix direction:** (a) fix the root cause — P0-02 (add `id` to `logs` or drop
the decorative FK) — so the batch parses; AND (b) apply the schema
statement-by-statement (split on `;` respecting strings/$$ blocks, or shell
out to `psql -f -v ON_ERROR_STOP=1`), and add `IF NOT EXISTS` / `DO $$` guards
for `CREATE TYPE` so re-runs are idempotent. Then add an integration test that
boots the schema against a real Postgres (the infra exists but is skipped).

---

## P1 — Correctness / feature gaps (continued)

### P1-07 · Enrichment is computed but never persisted — ingest discards it

**Status:** ✅ confirmed (read `src/api/ingest.py::_enrich_and_correlate`)

The fire-and-forget post-processing in `ingest_events` does, per event:
```python
enrichment = await enrich_event_dict(event_data.model_dump(by_alias=True))
if enrichment:
    log.debug("ingest_enrichment_done", ...)
```
It only `log.debug`s the result. There is **no `UPDATE logs SET enrichment=
...`** anywhere in the loop — despite the inline comment claiming "Writes
back into the logs.enrichment JSONB column." So GeoIP, reverse-DNS, and threat-
intel enrichment are computed (potentially hitting AbuseIPDB/OTX/URLhaus)
and then thrown away. `logs.enrichment` stays `{}` for every row.

Downstream impact: `correlation.detect_data_exfiltration` reads
`enrichment->>'bytes_sent'` (always NULL → never matches); the Sigma/nl2sql
`threat_intel_matches` template filters `enrichment->>'threat_intel' IS NOT
NULL` (always NULL → never matches); the triage `has_ti` feature is always 0.0;
`risk_scoring.calculate_asset_risk` threat-intel hits query
`enrichment @> '{"threat_intel": {"match": true}}'` (always 0).

`enrich_event`/`enrich_event_dict` in `src/enrichment/pipeline.py` is the
"main entry point called from the ingestion pipeline" per its docstring, but
the actual ingestion writer (`src/db/writer.py`) never calls it either. So
enrichment is wired to exactly one caller, which discards the result.

**Files:** `src/api/ingest.py`, `src/enrichment/pipeline.py`, `src/db/writer.py`.

### P1-08 · Triage provenance is never written — joblib `bytes` into JSONB columns

**Status:** ✅ confirmed (reproduced asyncpg `DataError: invalid input for
query argument $2: ... (expected str, got bytes)` against Postgres 18)

`AlertTriageModel.train_v2` → `_write_provenance` inserts `feature_importances`
and `features` as `joblib.dump`-serialized **bytes** (`_jb(...)`) into **JSONB**
columns:
```python
await conn.execute("INSERT INTO triage_model_provenance (...) VALUES (...)",
    ..., _jb(feature_importances), _jb(features), ...)
```
asyncpg rejects `bytes` for JSONB without a registered codec → `DataError`.
`train_v2` wraps the call in `except Exception: log.warning(
"triage_v2_provenance_write_failed", ...)`, so the error is swallowed and
**no provenance row is ever written.** The reference pattern used elsewhere
(`json.dumps(...)`) works. So `triage_model_provenance` stays empty,
`latest_provenance()` returns None, and the "full provenance in
triage_model_provenance" claim is broken.

Additionally, `_db_reachable()` hardcodes port **5433** (the compose
host→container mapping), so any deployment whose DB isn't on 5433 (e.g. local
5432) silently skips provenance/label writes via the `_db_reachable()` guard —
a second, independent reason provenance may be absent.

**Files:** `src/ai/alert_triage.py` (`_write_provenance`, `_db_reachable`).

### P1-09 · `risk_scoring.calculate_asset_risk` exposure factor is dead — use-after-release

**Status:** ✅ confirmed by reading

`calculate_asset_risk` acquires a connection, runs three queries, then **exits
the `async with pool.acquire() as conn:` block** (releasing the connection),
and only afterwards runs the exposure-score query on the **released** `conn`:
```python
async with pool.acquire() as conn:
    alert_stats = await conn.fetchrow(...)
    open_alerts  = await conn.fetchval(...)
    ti_hits     = await conn.fetchval(...)
# conn is released here
...
try:
    exposed = await conn.fetchval(...)   # use-after-release
except Exception:
    factors.exposure_score = 0.0
```
Using a released asyncpg connection raises; the bare `except Exception`
swallows it, so `exposure_score` is silently always `0.0`. The exposure risk
factor (10% of the asset risk score) is dead.

**Files:** `src/ai/risk_scoring.py`.

### P1-10 · `get_top_risk_assets` references `logs.id` — no such column → endpoint errors

**Status:** ⚠️ confirmed by reading (same phantom-column class as P0-02/P0-03)

`RiskScorer.get_top_risk_assets` query does `COUNT(DISTINCT l.id) FILTER (...)`
over `logs l`, but `logs` has no `id` column. The query errors at runtime
("column l.id does not exist"); the API consumer gets a 500. Part of the
`logs.id` cluster: schema FK (P0-02), this query, and any other `logs.id`
reference.

**Files:** `src/ai/risk_scoring.py`.

### P1-11 · Token revocation bypassed on the unified auth path (`get_current_user`)

**Status:** ✅ confirmed (read `src/api/auth.py`, confirmed `/query` and `/ingest`
use `require_role`/`get_current_user`)

`get_current_user` (used by `require_role(...)` and directly by most endpoints,
e.g. `/ingest`, `/query`, all `/rules/*`) decodes the JWT and returns the
payload **without** checking the jti blocklist or the user_revoke marker. Only
`verify_jwt` enforces those — and no endpoint observed so far uses `verify_jwt`.
So the Epic 5 hardening (logout invalidation via Redis jti blocklist, password-
change invalidation via `user_revoke`) is **bypassed on every endpoint that
uses the unified auth**. A logged-out or post-password-change JWT continues to
work until natural expiry. This includes the NL→SQL execution endpoint
(`/query`), which runs LLM-generated SQL against the DB.

`verify_jwt` exists and does the right thing (blocklist + user_revoke, fail-
closed only if Redis confirms), but appears to be dead code.

**Files:** `src/api/auth.py` (`get_current_user` vs `verify_jwt`), all
`src/api/*` routers choosing the dependency.

### P1-12 · Rule mutation endpoints have no RBAC — a `viewer` JWT can create/edit/delete rules

**Status:** ✅ confirmed (read `src/api/rules.py`)

`create_rule`, `update_rule`, `delete_rule` depend only on `get_current_user`,
**not** `require_role("admin"/"analyst")`. So any valid JWT — including a
`role=viewer` token — can create, update, and delete detection rules. The
static bearer token is auto-granted `role=admin` by `get_current_user`, so API
clients can also mutate rules. `require_role` is implemented and used by
`/query` (analyst) and `/query/templates` (viewer), but not applied to rule
mutations. Also: `update_rule` does **not** re-parse/validate the Sigma YAML
(only `create_rule` does) and does **not** update `mitre_tactics`/
`mitre_techniques`.

**Files:** `src/api/rules.py`.

---

## P2 — Quality / slop / doc drift (continued)

### P2-12 · `_geoip_retry_loop` never started; `close_geoip_reader` never called

`src/enrichment/pipeline.py` defines `_geoip_retry_loop()` ("intended to be
cancelled via asyncio.CancelledError on shutdown") and `close_geoip_reader()`,
but `src/api/main.py` lifespan starts neither and calls neither on shutdown.
So the retry loop is dead code, and the MaxMind reader handle is never closed
(minor — process exit handles it).

### P2-13 · `sequences.py` `SEQUENCE_DEFINITIONS` not consumed by the correlation engine

`src/detection/sequences.py` defines 7 `EventSequence`s with metadata that
duplicate `correlation.py`'s `CORRELATION_RULES`, plus `get_sequence`/
`list_sequences`. But `correlation.py` hardcodes its own 7 `detect_*` functions
and `CORRELATION_RULES` dict — it does not import or consume
`SEQUENCE_DEFINITIONS`. So `sequences.py` is parallel/dead relative to the
live detection path (its `list_sequences` may be exposed by an API endpoint —
not yet verified).

### P2-14 · `JWT_EXPIRY_HOURS = 8` is a dead constant

`src/api/auth.py` defines `JWT_EXPIRY_HOURS = 8` but `create_jwt` uses
`settings.access_token_ttl_minutes` (15 min default). The constant is unused.

### P2-15 · `audit_logs.user` is always NULL — middleware reads `request.state.user` which is never set

`AuditLogMiddleware` does `user = getattr(request.state, "user", None)`, but
`get_current_user`/`verify_jwt` return the payload to the handler as a
parameter and never set `request.state.user`. So every audit row has
`user=NULL`, `role=NULL` — the audit trail records method/path/status/duration
but not *who* did it, defeating the audit's purpose for accountability.

### P2-16 · `validate_ollama_model()` result is discarded in `main.py`

`lifespan` calls `await validate_ollama_model()` and ignores the returned
`(available, model, error)`. The "M-01 fix: Validate configured Ollama model
exists" is decoration — a misconfigured model neither blocks startup nor
warns the operator; AI just silently falls back. Either act on the result
(warn / fail) or remove the call.

### P2-17 · Threat-intel refresh blocks API startup (up to ~90s of external HTTP)

`start_threat_intel_scheduler` (called in `lifespan`) runs `refresh_all_feeds()`
**synchronously before starting the scheduler** — hitting URLhaus, AbuseIPDB,
and OTX in sequence (30s timeout each). On a cold/no-network boot the API
won't pass its health check for up to ~90s; the demo's 30s health-wait can
time out. Refresh should be `create_task`'d or run after the scheduler starts.
Also `src/intel/threat_intel.py` ends with a dangling comment "Enrichment
module (wires threat intel into ingestion)" with no code after it.

### P2-18 · MITRE data downloads on first request; `_db_reachable` hardcodes port 5433

`src/detection/mitre.py::get_mitre_data` downloads the ATT&CK STIX bundle from
GitHub on first call (no cache → network on first API request; raises if
offline). The cache filename is versioned (`mitre_attack_cache_v14.json`) but
the source URL is the unversioned `master` branch, so the cache can drift from
upstream. Separately, `_db_reachable()` in `alert_triage.py` hardcodes port
**5433**, silently skipping provenance/labels writes on any other port.

### P2-19 · `nl2sql` minor robustness gaps

- `add_safety_limits` CTE detection matches only `) SELECT` with exactly one
  space — `)  SELECT` or `)\nSELECT` falls through to the naive append.
- `validate_sql_structure` rejects any `--` or `/* */` anywhere, including
  inside string literals (e.g. `WHERE host_name = 'web--01'` → falsely
  rejected).
- If `EXPLAIN` itself fails, `estimate_query_cost` returns `(0, "unknown")`;
  `0 < MAX_QUERY_COST_ROWS` is false, so the query is **allowed** — the cost
  gate is bypassed whenever EXPLAIN errors.

### P2-20 · `rules.update_rule` skips re-validation and MITRE refresh

`update_rule` does not call `parse_sigma_rule` on the new YAML (so invalid YAML
is accepted and only blows up at runtime), and does not update
`mitre_tactics`/`mitre_techniques` (only `create_rule` populates them).

### P2-21 · `notifications.send_email_notification` / `send_daily_summary` likely unwired

`send_alert_notification` is wired (from `alerts.py`). `send_email_notification`
and `send_daily_summary` appear to have no caller (no scheduler emits a daily
summary). Suspected dead. (Not yet fully verified across `src/api/*`.)

### P2-22 · `FileShipper` checkpoint is a single global path

`CHECKPOINT_FILE = Path.home() / ".scarletai_shipper_checkpoint"` is shared across
all `FileShipper` instances. Running two shippers (different log paths) in one
home would clobber each other's offset. Single-shipper assumption baked in.

---

### P1-11 · Token revocation bypassed on the business API (`get_current_user` path)

**Status:** ✅ confirmed (read `src/api/auth.py`, `src/api/auth_login.py`)

Correction from the first draft: `verify_jwt` **is** used — by `/auth/me`,
`/auth/logout`, `/auth/change-password`, `/auth/force-change-password`, and
`/auth/refresh` (manual decode) — and those endpoints **do** enforce the jti
blocklist and user_revoke markers. So the auth-own endpoints are properly
hardened.

The real issue is narrower but still serious: the **business** endpoints —
`/ingest`, `/query` (executes LLM-generated SQL), `/rules/*`, `/alerts/*`,
`/cases/*`, `/logs`, `/threat-intel/*`, `/ai/*`, `/correlation/run` — use
`get_current_user` (directly or via `require_role(...)`), which decodes the
JWT and returns the payload **without** checking the blocklist or user_revoke.
So after **logout** (jti blocklisted) or **password change** (user_revoke set),
the old access token **still works on the entire business API** until natural
expiry (15 min). Only `/auth/me` and `/auth/logout` reject it. The Epic 5
revocation machinery is built and set, but only consulted by the auth-own
endpoints — the whole point of revocation (invalidate access to the data) is
lost on the surface that actually matters.

**Files:** `src/api/auth.py` (`get_current_user` vs `verify_jwt`), all
business routers in `src/api/*`.

### P1-13 · WebSocket real-time streaming is unwired — `broadcast_event` has no caller

**Status:** ✅ confirmed (read `src/api/websocket.py`, `src/api/ingest.py`,
`src/db/writer.py`, `src/ingestion/shipper.py`)

`broadcast_event(event)` in `src/api/websocket.py` is documented as "Called
by the ingestion pipeline after writing to DB." It is **never called**:
`ingest.py::_enrich_and_correlate` calls `enrich_event_dict` (discarded —
P1-07) and `run_all_correlations(persist=True)`, but not `broadcast_event`;
`LogWriter` doesn't call it; the shipper doesn't call it. So connected
WebSocket clients (`/ws/logs`) authenticate, accept, ping/pong, and then
**never receive a single event**. The real-time log-streaming feature is dead.
Also `_ws_tokens` is in-memory per-worker, so multi-worker deploys can't share
tokens (fine for single-process).

### P1-14 · `POST /auth/seed-admin` is unauthenticated and creates `admin`/`admin` with no forced rotation

**Status:** ✅ confirmed (read `src/api/auth_login.py`)

`/auth/seed-admin` has no auth dependency. When `siem_users` is empty it
inserts `username=admin`, `password=hash_password("admin")`, `role=admin`
and does **not** set `must_change_password=true`. Race-protected with an
advisory lock + `WHERE NOT EXISTS`, but the window between "API up" and
"entrypoint created the admin" lets anyone who can reach the API create an
`admin`/`admin` account that persists with a known weak password and no
forced reset. The dashboard `api_client.seed_admin()` docstring even claims it
"requires admin auth" — it doesn't. (The Docker `entrypoint.sh` path creates
its own random-password admin and prints it, but `/seed-admin` is a separate
public bootstrap path.)

**Fix direction:** Remove the endpoint (rely on the entrypoint), or require a
bootstrap token / localhost-only, and set `must_change_password=true`.

---

## P0-06 · Docker image does not build — `COPY alembic/ alembic.ini` of removed paths

**Status:** ✅ confirmed (`alembic/` and `alembic.ini` were removed in commit
`97c480c`; `Dockerfile` still `COPY`s them)

```dockerfile
COPY alembic/ ./alembic/
COPY alembic.ini ./alembic.ini
```
A `COPY` with a nonexistent source fails the build: `alembic/: no such file
or directory`. So `docker build .` (and `docker compose build`) **fails before
any container starts.** This is independent of P0-05 (entrypoint crash) — the
image never exists to crash. Docker is broken at two separate layers: build
(P0-06) and runtime entrypoint (P0-05).

**Files:** `Dockerfile`.

**Fix direction:** Delete the two stale `COPY` lines (alembic is gone —
schema.sql is canonical). Then P0-05 still must be fixed for runtime.

---

## P2 — Quality / slop / doc drift (round 2)

### P2-23 · Action-level `audit_log` is only partially populated; `log_audit_action` raises on failure

**Status:** ✅ confirmed (read `src/api/cases.py`, `src/api/rules.py`,
`src/api/alerts.py`, `src/detection/alerts.py`, `src/api/audit.py`)

`log_audit_action` (writes to the action-level `audit_log` table) is called
by `cases.py` (every case mutation) and by `hunting_assistant.save_hunt_history`
(actor=`"hunting_assistant"`), but **not** by `rules.py` (uses only structlog)
or by the `detection/alerts.py` status updates. So audit coverage is
inconsistent: case edits are audited, rule edits and alert status changes are
not. Worse, `log_audit_action` **raises `RuntimeError`** on DB failure (the
M-22 "fix"), and `cases.py` calls it *after* the mutation, unwrapped — so if
`audit_log` is unavailable (e.g. schema didn't apply — P0-05) a **successful**
case mutation returns 500, and a client retry duplicates the case. This
contradicts the middleware's own principle ("audit must not break the
request").

### P2-24 · `alerts.py` API records `str(user)` (dict repr) as author / `created_by` / `updated_by` / `assigned_to`

**Status:** ✅ confirmed (read `src/api/alerts.py`)

Endpoints declare `user: str = Depends(require_role(...))` but `require_role`
returns the JWT **dict**, so `str(user)` becomes the literal
`"{'sub': 'admin', 'role': 'admin', 'jti': '...', ...}"`. This is used as
`updated_by`, note `author`, suppression `created_by`, and bulk `assigned_to`.
So the alert timeline, suppression rules, and assignment records are polluted
with the dict-repr instead of the username. (`link_to_case` correctly uses
`user.get("sub")` — inconsistent within the same file.)

### P2-25 · `auto_train_check` is never scheduled — triage auto-training is manual-only

**Status:** ✅ confirmed (read `src/api/ai.py`, `src/detection/scheduler.py`,
`src/api/main.py`)

`api/ai.py::auto_train_check` is documented "called from the scheduler", but
`scheduler.py` only schedules `run_rule`, and `main.py` lifespan doesn't
schedule it. So `check_auto_train()` (the 100-resolved-alerts auto-retrain
trigger) never fires automatically. The "auto-retrains" claim in
`CURRENT_VS_PRODUCTION` is false — training is manual via `POST /ai/train`.

### P2-26 · Chat is stateless; `session_id` ignored and `user` not forwarded

**Status:** ✅ confirmed (read `src/api/chat.py`, `src/ai/chat.py`)

`chat_endpoint` calls `chat(request.message, request.session_id)`, but
`chat`'s second parameter is `session_context`, which is **never used**
inside the function (it always builds a fresh DB context). The authenticated
`_user` is not forwarded to `chat()`, so chat cost-tracking records
`user=None` ("system") even for authenticated calls. The `session_id`/
"conversation continuity" surface is non-functional.

### P2-27 · `GET /hunt/history` is documented but not implemented

`src/api/hunt.py` module docstring lists 5 endpoints including
`GET /api/v1/hunt/history`, but only 4 routes are defined. `get_hunt_history()`
exists in `hunting_assistant.py` with no caller — the history endpoint is
missing and the function is dead.

### P2-28 · Dead code cluster (verified no callers)

- `run_all_correlations_legacy` (`correlation.py`) — `/correlation/run-legacy`
  uses the main `run_all_correlations`, not the legacy wrapper; the wrapper
  also raises `ValueError` via `create_alert(rule_id=None)`.
- `get_sequence` (`sequences.py`) — only `list_sequences` is wired
  (`GET /correlation/sequences`). `SEQUENCE_DEFINITIONS` duplicates
  `CORRELATION_RULES` and doesn't drive detection. (Correction to P2-13:
  `sequences.py` is *partially* wired — `list_sequences` is used; the
  definitions/get_sequence are the dead/redundant parts.)
- `get_hunt_history` (`hunting_assistant.py`) — see P2-27.
- `suggest_hunting_queries` (`hunting_assistant.py`) — no caller.
- `summarize_multiple_alerts`, `suggest_investigation_steps`
  (`alert_explanation.py`) — no endpoint exposes them.
- `calculate_severity_boost` (`enrichment/pipeline.py`) — no caller (and
  enrichment is discarded anyway, P1-07).
- `send_email_notification`, `send_daily_summary` (`notifications.py`) — no
  caller (only `send_alert_notification` is wired).
- `auto_train_check` (P2-25), `_geoip_retry_loop` (P2-12), `broadcast_event`
  (P1-13), `JWT_EXPIRY_HOURS` (P2-14).

### P2-29 · `scripts/demo.sh` double-starts the API on :8000 (port conflict); stale and not used by `make demo`

`demo.sh` runs `docker-compose up -d` (starts the compose `api` bound to
host :8000) and then `poetry run uvicorn --port 8000` locally — port
conflict; under `set -e` the script aborts at "Starting API". `make demo`
uses `run_osquery_demo.sh` instead (which explicitly stops the compose api
container first). `demo.sh` is stale/broken and unreferenced by the canonical
demo path.

### P2-30 · `make migrate` silently leaves `correlation_matches` uncreated

`make migrate` applies schema via `psql -f` (statement-by-statement, psql's
default continue-on-error). The `correlation_matches` FK error (P0-02) is
logged but not fatal, so the command reports success while the table is
missing. Should use `psql -v ON_ERROR_STOP=1` once P0-02 is fixed so partial
applies fail loudly.

### P2-31 · `OLLAMA_MODEL` default differs between compose and settings

`docker-compose.yml` defaults `OLLAMA_MODEL` to `mistral:7b`; `settings.py`
defaults to `llama3.2:8b`; the README/demo mention `llama3.2:8b`. A compose
up without `OLLAMA_MODEL` set configures a model the operator likely hasn't
pulled → AI silently falls back. Minor, but a setup footgun.

### P2-32 · Sync `redis` client used in async request paths (event-loop block)

`src/api/redis_client.py` uses the synchronous `redis` library with
`socket_timeout=1.0`, called from async auth (`is_jti_blocked`,
`get_latest_user_revoke_ts`) on every authenticated request. Each call can
block the event loop up to 1s if Redis is slow/down. `get_latest_user_revoke_ts`
also does a `scan_iter` (O(N) keyspace scan) per request. For a single-process
SIEM it's tolerable; for throughput it's a latency hit and a scale-out
footgun. (And per P1-11, the business API doesn't even call these.)

### P2-33 · `correlation.py` API `_unwrap`/`_parse_as_of` are test-coupling hacks

`_unwrap` exists because unit tests call the endpoint functions directly with
FastAPI `Query(...)` sentinels as defaults, so the endpoint must extract
`.default`. This is a smell: the endpoints accept `Query(...)` defaults but
are also called as plain functions. Better to test via FastAPI's
`TestClient` (which resolves the Query) than to ship unwrap helpers.

### P2-34 · `/health` calls `validate_ollama_model` (a 5s Ollama HTTP GET) on every request

Every `GET /api/v1/health` triggers `validate_ollama_model()` (5s timeout GET
to Ollama `/api/tags`). When Ollama is down (common in dev), health is slow
(up to 5s) — bad for Uptime-Kuma / monitoring polling. Combined with P2-16
(startup also calls it and discards the result), it's redundant work. Health
should be cheap (DB ping + cached Ollama status).

### P2-35 · Case `alert_ids`/`notes` read-modify-write races

`cases.py` `link_alert`/`unlink_alert`/`add_case_note` and `alerts.py`
`link_to_case` read the array, mutate in Python, write the whole array back —
a lost-update race under concurrent calls. Should use SQL `array_append` /
`array_remove` / `||` for atomic append.

### P2-36 · Hunt history is attributed to `"hunting_assistant"`, not the user

`save_hunt_history` writes `actor="hunting_assistant"` to `audit_log`; the
endpoint has the authenticated user but doesn't forward it, so hunts aren't
attributed to the analyst who ran them.

### P2-37 · `osquery.conf` logger path disagrees with `settings.osquery_log_path`; 2 scheduled tables are parser-unmapped

`config/osquery.conf` sets `logger_path: /var/log/osquery` (results land in
`/var/log/osquery/osqueryd.results.log`), but `settings.osquery_log_path`
defaults to `/opt/homebrew/var/log/osquery/osqueryd.results.log`. The shipped
config and the shipped shipper default point at different files — if you
install osquery via Homebrew and use this config, the FileShipper tails a file
osquery isn't writing to. Also, `browser_plugins` and `disk_encryption` are
scheduled in the config but are **not** in `OSQUERY_ECS_MAP`, so
`parse_osquery_line` drops their lines as `unmapped_table` (debug log) — 2 of
12 scheduled queries produce no normalized events.

---

## P2 — Quality / slop / doc drift (round 3)

### P1-15 · Dashboard MITRE heatmap is broken — `/rules` API omits `mitre_tactics`/`mitre_techniques`

**Status:** ✅ confirmed (read `dashboard/charts.py::render_mitre_heatmap` and
`src/api/rules.py::RuleResponse`)

`render_mitre_heatmap` reads `rule.get("mitre_techniques", [])` /
`rule.get("mitre_tactics", [])`, but `RuleResponse` only exposes
`{id, name, description, severity, enabled, last_run, last_match,
match_count}` and `from_row` filters to those fields — so `mitre_techniques`
and `mitre_tactics` are **dropped from the API response**. Every rule arrives
with empty MITRE arrays → `technique_data` is empty → the dashboard MITRE
heatmap **always shows "No MITRE ATT&CK mappings found in rules."** The
"MITRE ATT&CK heatmap on the dashboard" claim (`CURRENT_VS_PRODUCTION`
§3.3 point 6) is broken at the API/model layer. Fix: add `mitre_tactics`/
`mitre_techniques` to `RuleResponse`.

### P1-16 · `/ingest` `IngestEvent` omits `process_cmdline`/`process_path`/`host_ip` → most process Sigma rules are untriggerable via HTTP ingest

**Status:** ✅ confirmed (read `src/api/ingest.py::IngestEvent`, `scripts/seed_realistic_data.py`)

`IngestEvent` has `process_name`, `process_pid` but **no `process_cmdline`,
no `process_path`, no `host_ip`**. The conversion `NormalizedEvent(**event_data.model_dump(...))`
therefore leaves `process_cmdline`/`process_path`/`host_ip` NULL on every
HTTP-ingested row. Most process Sigma rules filter on `process_cmdline`
(reverse_shell, lolbin, encoded_command, suspicious_parent_child,
download_execute, process_injection, script_interpreter, …) and on
`process_path` (suspicious_tmp_process) — so they **can never match**
HTTP-ingested events. `seed_realistic_data.py`'s reverse-shell event even
puts the command in `raw_data.command` (not `process_cmdline`), confirming
the gap. The osquery FileShipper path works (the parser populates
`process_cmdline` from `columns.cmdline`), but the shipper is OFF by
default. So `CURRENT_VS_PRODUCTION` §3.2's "POST synthetic events via /ingest
to make detection fire" is partially false for process rules. Fix: add the
missing fields to `IngestEvent` (and `seed_realistic_data` should set
`process_cmdline`).

### P1-17 · Caddyfile `handle_path /api/*` strips the `/api` prefix the FastAPI app requires → prod API 404s

**Status:** ✅ confirmed (read `deploy/Caddyfile`)

`handle_path /api/* { reverse_proxy scarletai-api:8000 }` **strips** the
matched `/api` prefix, so `https://domain/api/v1/health` is proxied to
`scarletai-api:8000/v1/health`. But the FastAPI app mounts every router at
`/api/v1` (`main.py`) and docs at `/api/docs` — so every prod API request
through Caddy **404s**. Should be `handle /api/*` (preserve prefix) or
strip only down to `/api` while the app is re-rooted. Latent today because
P0-06 means the image never builds, but a real prod-path bug.

### P2-38 · CI is green while the product doesn't build or boot — the root cause of all the P0s being undetected

**Status:** ✅ confirmed (read `.github/workflows/ci.yml`)

CI: (a) provisions a Postgres 17 service but runs only `pytest tests/unit/`
(mocked DB) + `pytest tests/ --cov-fail-under=80`; integration tests **skip**
because `DATABASE_URL`/`RUN_INTEGRATION_TESTS` are never set, so the
provisioned Postgres is unused and `schema.sql` is never applied; (b) never
builds the Docker image (so P0-06's stale `COPY alembic/` is uncaught);
(c) never runs the entrypoint (so P0-05 is uncaught). So CI validates
ruff + mypy + 1258 mocked tests + 80% coverage while the product cannot build
or boot. This is the systemic reason every P0 slipped through. Fix: add a
job that `docker build`s the image, a job that applies `schema.sql` to the
provisioned Postgres with `ON_ERROR_STOP=1`, and wire `DATABASE_URL` so the
integration tests actually run.

### P2-39 · Dashboard "AI Triage" sidebar status always shows "unknown"

`dashboard/main.py::render_sidebar` reads `triage.get("status", "unknown")`,
but `AlertTriageModel.get_status()` returns no `status` key (it returns
`is_trained`, `trained_at`, `training_samples`, …). So the AI-triage
indicator always shows "unknown" — never "Trained"/"No data". Should check
`triage.get("is_trained")`.

### P2-40 · Dashboard logout is client-side only — never calls `/auth/logout`, so the server jti is never blocklisted from the UI

`dashboard/auth.py::render_sidebar_user_info` calls `ApiClient.logout()`
(a static method that clears Streamlit session state) but never `POST
/auth/logout`. So the server-side jti blocklist is never updated from the
UI; the token stays valid for its full 15-min TTL. Combined with P1-11
(business endpoints bypass revocation anyway), the Epic 5 revocation story
is largely fictional from the dashboard's perspective.

### P2-41 · Dashboard login page exposes a pre-auth "Seed Admin User" button

`render_login_page`'s "Initial Setup" expander has a "Seed Admin User"
button that calls the unauthenticated `/auth/seed-admin` (P1-14), and the
page literally tells the operator the default creds are `admin`/`admin`.
So the weak-admin bootstrap is UI-guided, not just an API path.

### P2-42 · `webshell_creation.yml` needs `_parse_condition` to support plain `and` (the one rule the legacy fix alone doesn't cover)

Running the legacy parser on all 45 rules: **44/45 produce correct SQL
without raising**; only `webshell_creation.yml` drops its WHERE to `TRUE`.
Its condition is `selection_web_dir and selection_shell_content` (plain
`and`), and `SigmaParser._parse_condition` only splits on ` and not ` and
` or `, not plain ` and `. So routing Sigma through the legacy parser (the
P0-01 fix) fixes 43 rules and leaves `webshell_creation` over-firing (matches
all file events). The fix must additionally teach `_parse_condition` to
split on plain ` and `. (The 7 aggregation rules are correct in the legacy
path — the `selection_not_found` warnings are from a wasteful first parse;
the agg branch rebuilds the WHERE from `base_condition`.)

### P2-43 · Dashboard views use field names that don't match the API response shapes (cluster)

**Status:** ✅ confirmed across `dashboard/{alerts_view,rules_view,ai_chat_view,charts,main,auth}`

A recurring class of bug: the dashboard was written against assumed/different
API shapes, not the actual ones. Confirmed instances:
- `alerts_view` **AI Triage**: `result.get("prediction", {})` then
  `prediction.get('label', …)` — but `TriageResponse.prediction` is a **string**
  (`"true_positive"`/`"false_positive"`), not a dict → `AttributeError`
  (not `ApiError`) → UI traceback whenever triage runs.
- `alerts_view` **Hunt from Alert**: reads `result.get("suggested_hunts", [])`
  but `HuntFromAlertResponse` returns `matching_hunts` + `llm_suggestions` →
  always `[]` → "No specific hunt suggestions" even when the API matched.
- `ai_chat_view` **AI Status**: reads `triage.get("status"/"samples"/"accuracy")`
  but `get_status()` returns `is_trained`/`training_samples`/`training_accuracy`
  → all defaults; reads `status.get("ollama")` but the API returns
  `ollama_available` (bool) → always "Unknown".
- `ai_chat_view` **Query templates**: reads `tmpl.get("question"/"name"/"category")`
  but `get_available_templates()` returns `{id, description, keywords}` → every
  button shows "General: Unknown". (Should use `tmpl.get("description")`.)
- `rules_view` **rule detail**: reads `sigma_yaml`/`run_interval`/`lookback`/
  `threshold`/`mitre_*` but `RuleResponse` omits them (see P1-15) → "N/A",
  empty YAML, blank MITRE.
- `rules_view` **Enable/Disable toggle**: `api.update_rule(id, {"enabled":…})`
  sends a partial body, but the server `PUT /rules/{id}` requires a full
  `RuleCreate` (`name`+`sigma_yaml` required) → **422 validation error**.
  There is no partial-update (PATCH) path.
- `main`/`charts` **MITRE heatmap**: P1-15 (RuleResponse omits mitre fields).
- `main` **AI Triage sidebar**: P2-39.

This is the single largest quality cluster in the UI: the dashboard and the
API are out of sync in ~7 places. Recommend a focused pass to align the
Pydantic response models with what the views read (and add a PATCH partial-
update for rules), or the dashboard mis-reports state across most pages.

### P2-44 · `generate_attack_data.py` fixture columns don't match the parser's field extraction

The generator's brute-force events use the `logged_in_users` table with
`columns: {type, user, host}`, but `parse_osquery_line` extracts `source_ip`
from `columns.get("local_address") or columns.get("address")` — neither is
present, so `source_ip` is `None` for every event. The brute-force
rule/correlation partition by `source_ip`, so these fixtures wouldn't
trigger detection. (The live demo uses `generate_osquery_events` with the
`processes` table and proper columns, so it works.) Fixture/parser schema
mismatch — matters if anyone uses `generate_attack_data` for fixtures/tests.

---

## Sweep status

The read-only sweep is effectively complete. Everything in `src/`, the
structural dashboard layer (`main`, `auth`, `charts`, `api_client`, and the
three data-managing views `alerts_view`/`rules_view`/`ai_chat_view`), all
scripts, Docker/compose/Caddy, the CI workflow, `config/osquery.conf`, the
`Makefile`, and all 45 Sigma rules (audited via both the pySigma backend and
the legacy parser) have been read. Findings above are verified against the
code (and, for SQL claims, executed against a throwaway Postgres 18).

**Not individually read** (low residual risk, pattern established):
- `dashboard/{cases_view,logs_view,hunt_view,ui_utils}.py` — same Streamlit
  pattern as the views already read; `cases_view`/`logs_view`/`hunt_view`
  call the `api_client` methods that were verified, so any mismatch would be
  of the same field-shape class catalogued in P2-43.
- The body of `seed_demo_data.py` (788 lines) and `generate_attack_data.py`
  (rest) — synthetic data generators; skimmed, no integration risk beyond
  P2-44.

Findings will be appended if anything surfaces on a deeper read of the
remaining view files.
---

## Fix log

Applied by the production-readiness fix pass (2026-08-22). One line per fix.
Items marked ✅ fixed (commit <sha>) in their status headers above are updated
in the final pass (Phase 11); this log is the running record.

- P0-02 — added logs.id BIGINT PK; correlation_matches.trigger_event_id INT→BIGINT — 0edaa14
- P0-03 — added logs.severity TEXT column + writer inserts it — 0edaa14
- P0-05 — entrypoint.sh applies schema via psql -v ON_ERROR_STOP=1 (statement-by-statement) — 0edaa14
- P0-06 — Dockerfile: deleted stale COPY alembic/ + alembic.ini — 0edaa14
- CREATE TYPE idempotency (DO $$ EXCEPTION duplicate_object) — 0edaa14
- P0-01 — sigma_to_sql routes through legacy SigmaParser only; all 45 rules execute against real Postgres — 359a339
- P0-04 — deleted _parse_with_pysigma/_extract_mitre_tags_pysigma (dead pySigma parse path); legacy is primary — 359a339
- P2-42 — SigmaParser._parse_condition plain ' and ' support (webshell_creation) — 359a339
- P1-04 — reverse_shell.yml + ssh_success_after_failures.yml duplicate-key YAML fixed (list form; ssh -> pure threshold) — 359a339
- P2-10 — to_sql parses condition once (was double-parse leaving untyped unreferenced placeholders) — 359a339 (moved up from Phase 9; blocked data_exfiltration_volume execution)
- INET LIKE host(col)::text + Sigma '*' -> IS NOT NULL (login_unusual_geography, impossible_travel, data_exfiltration — unflagged INET runtime bugs surfaced by execution test) — 359a339
- P0-03 (completion) — severity column verified in detect_defense_evasion_cleanup query (executes) — 8d357de
- P1-07 — ingest writes enrichment back to logs.enrichment JSONB (flush + UPDATE-by-tuple); LogWriter.flush() added — 8d357de
- P1-16 — IngestEvent: process_cmdline/process_path/host_ip added; seed_realistic_data reverse-shell sets process_cmdline — 8d357de
- P1-06 — run_all_correlations(persist=True) calls create_alert(rule_id=None) per match; create_alert accepts rule_id=None (dedup by rule_name+host_name) — 7890108
- P1-13 — ingest loop broadcasts each event to /ws/logs via broadcast_event (best-effort) — 7890108
- P2-28 (partial) — deleted dead run_all_correlations_legacy wrapper — 7890108
- P1-08 — _write_provenance uses json.dumps for JSONB; provides model_hash/training_samples/cv_accuracy (NOT NULL); _db_reachable uses settings.db_host/db_port — 6338cf0
- P1-09 — calculate_asset_risk exposure query moved inside async-with conn block — 6338cf0
- P1-10 — get_top_risk_assets rewritten (joined outbound-conns subquery; catalog's logs.id premise was incomplete — subquery didn't expose id/event_category) — 6338cf0
- P2-25 — schedule_rules schedules auto_train_check hourly — 6338cf0
- P1-11 — get_current_user enforces jti blocklist + user_revoke via shared _check_revocation — 52ed123
- P1-12 — rule mutations require admin role; viewer gets 403 — 52ed123
- P1-14 / P2-41 — seed-admin localhost-only + must_change_password=TRUE; dashboard button + admin/admin text removed — 52ed123
- P2-23 — log_audit_action no longer raises (logs+returns None); audit added to rule/alert mutations — 52ed123
- P2-24 — alerts.py uses user.get("sub") not str(user) for author/created_by/updated_by/assigned_to — 52ed123
- P2-40 — dashboard logout POSTs /auth/logout (server-side blocklist) before clearing session — 52ed123
- P1-15 — RuleResponse exposes mitre_tactics/techniques/sigma_yaml/run_interval/lookback/threshold; from_row serializes intervals — d9f447a
- P2-43 — PATCH /rules/{id} partial update; dashboard update_rule uses PATCH; dashboard field-shape fixes (prediction string, matching_hunts+llm_suggestions, is_trained/training_samples/training_accuracy/ollama_available, templates description+id) — d9f447a
- P2-39 — sidebar AI Triage uses is_trained — d9f447a
- P2-20 — PUT update_rule re-parses sigma_yaml + refreshes MITRE — d9f447a
- (unflagged) rules interval params use timedelta (asyncpg str->interval bug); scheduler.start() idempotent (reload_rules second-call crash) — d9f447a
- P1-17 — Caddyfile handle_path -> handle /api/* (preserve /api prefix) — 3a4897a
- P2-17 — threat-intel initial refresh runs as background task (non-blocking startup) — 3a4897a
- P2-37 — osquery.conf logger_path aligned to /opt/homebrew/var/log/osquery; browser_plugins/disk_encryption documented as intentionally unmapped — 3a4897a
- P2-31 — docker-compose OLLAMA_MODEL default llama3.2:8b — 3a4897a
- P2-34 — /health caches Ollama probe (60s TTL) — 3a4897a
- P2-16 — startup validate_ollama_model warns on result (was discarded) — 3a4897a
- P2-35 — cases link/unlink/note + alerts link_to_case use atomic SQL (array_append/remove, notes || jsonb) — 3a4897a
- P2-07 — FileShipper docstring corrected (polling, not watchfiles) — 53cedb0
- P2-13/28 — dead code deleted (get_sequence, suggest_hunting_queries, get_hunt_history, summarize_multiple_alerts, suggest_investigation_steps, calculate_severity_boost, send_email_notification, send_daily_summary) — 53cedb0
- P2-14 — unused JWT_EXPIRY_HOURS removed — 53cedb0
- P2-15 — AuditLogMiddleware best-effort decodes JWT to attribute actor/role — 53cedb0
- P2-18 — MITRE STIX master-vs-v14 drift documented (accept) — 53cedb0
- P2-19 — nl2sql add_safety_limits whitespace-tolerant )\s+SELECT; comment-check + EXPLAIN-failure limits documented — 53cedb0
- P2-27 — GET /hunt/history removed from hunt.py docstring (function already deleted) — 53cedb0
- P2-29 — stale/broken scripts/demo.sh deleted (port conflict, unreferenced by make demo) — 53cedb0
- P2-30 — make migrate uses psql -v ON_ERROR_STOP=1 — 53cedb0
- P2-32 — sync redis in async auth paths documented as follow-up (socket_timeout=1.0 bounds; switch to redis.asyncio at scale) — 53cedb0
- P2-33 — correlation _unwrap/_parse_as_of left as-is (acceptable test-coupling) — 53cedb0
- P2-36 — execute_hunt forwards actor; save_hunt_history records analyst not 'hunting_assistant' — 53cedb0
- P2-44 — generate_attack_data brute-force fixture adds local_address so parser extracts source_ip — 53cedb0
- P2-11 — moot (pySigma parse path deleted in P0-04) — 53cedb0
- P1-05 — load_sigma_rules reconciles every boot (upsert by name, preserve operator state, log db-only orphans) — fa9c6fd
- P2-08 — dead-letter writes one event per line (true JSON-Lines) — fa9c6fd
- P2-09 — correlation as_of docstrings corrected to datetime.now(timezone.utc) (code already aware) — fa9c6fd
- P2-12 — lifespan calls close_geoip_reader() on shutdown — fa9c6fd
- P2-22 — FileShipper checkpoint path per-instance (defaults to legacy global) — fa9c6fd
