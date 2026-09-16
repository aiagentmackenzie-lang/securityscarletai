# Local Production — SecurityScarletAI on a single host

This is the **"my computer, doing everything it is meant to do"** path: the SIEM
runs on the local machine, ingests REAL host telemetry via osquery, feeds Sigma
detection live, and keeps every credential in-house. For the client-facing demo
flow, see [`DEMO.md`](DEMO.md). For the internet-exposed TLS path (Caddy +
DOMAIN), see [`DEPLOYMENT.md`](DEPLOYMENT.md) — this document is the loopback,
single-host variant.

Two modes, one stack:

| | Demo mode | Local production mode |
|---|---|---|
| Data | `DEMO_SEED_ENABLED=true` synthetic alerts | Real host telemetry via osquery |
| Shipper | optional (`ENABLE_INGESTION_SHIPPER` off) | **on** |
| Redis auth | none (localhost-only dev default) | `REDIS_PASSWORD` (staged for cutover) |
| Demo credential | `demo_analyst` | real admin (entrypoint bootstrap) |

The demo can always be regenerated (`DEMO_SEED_ENABLED=true` + `make
demo-refresh`), so switching modes costs nothing.

---

## 1. Real telemetry: osquery → FileShipper → Sigma → alert

The API process runs a `FileShipper` (`src/ingestion/shipper.py`) that tails
osquery's results log, parses each line to an ECS-normalized event
(`src/ingestion/schemas.py` — **only tables in `OSQUERY_ECS_MAP` are
ingested**), writes them to Postgres, and the Sigma detection scheduler picks
them up on its normal run interval (default 60s). Verified end-to-end
2026-09-04: appended reverse-shell-pattern event → critical alert within one
scheduler tick.

### 1.1 Install osqueryd (zero-sudo, user space)

The official pkg requires sudo for `installer`; the same binary runs fine from
user space:

```bash
brew fetch --cask osquery          # downloads the official signed pkg
pkg=$(brew --cache --cask osquery)
pkgutil --expand-full "$pkg" /tmp/osquery-pkg
mkdir -p ~/Applications/osquery
cp -R /tmp/osquery-pkg/Payload/opt/osquery/lib/osquery.app ~/Applications/osquery/
rm -rf /tmp/osquery-pkg
```

⚠️ **Run the binary from inside the `.app` bundle** —
`~/Applications/osquery/osquery.app/Contents/MacOS/osqueryd`. The code signature
covers the bundle resources; a bare copy of the binary breaks the seal and macOS
kills it at exec (`Killed: 9`).

### 1.2 LaunchAgent

`deploy/osqueryd.launchagent.plist.example` holds the service definition with
`__REPO_ROOT__`/`__HOME__` placeholders. Install:

```bash
repo="$(pwd)"
sed -e "s|__REPO_ROOT__|$repo|g" -e "s|__HOME__|$HOME|g" \
  deploy/osqueryd.launchagent.plist.example > \
  ~/Library/LaunchAgents/com.scarletai.osqueryd.plist
mkdir -p data/osquery
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.scarletai.osqueryd.plist
```

Hard-won facts baked into that plist (verified against osquery 5.23.1 on this
host):

- **CLI-only flags**: `logger_plugin`, `logger_mode` are ignored (with a
  warning) if set in the config file — pass them as flags. `log_result_events`
  **does not exist** in 5.23.1 (results logging is default-on); passing it
  kills the daemon at flag-parse.
- **`/var/osquery` defaults are root-only**: pidfile, extension-manager socket
  and (in older configs) database/logger paths all default there — the daemon
  refuses to boot as a user agent until each is redirected to a writable path
  (`--pidfile`, `--extensions_socket`, `--logger_path`, `--database_path`).
- **`--logger_mode=0644`**: osquery's default 0640 results log is not readable
  by the API container's uid. 0644 lets the read-only bind mount work.
- **First run stores a baseline only** — differential results appear in
  `results.log` from the second schedule tick onward (~2 min with the 60s
  queries). An empty results log immediately after boot is not a failure.

### 1.3 FIM: root LaunchDaemon + EndpointSecurity (validated 2026-09-11)

FIM (`file_events`) is ENABLED in `config/osquery.conf` and live-verified.
Validated facts (scratch pass, osquery 5.23.1, 2026-09-11):

- EndpointSecurity (process + FIM events) requires osqueryd running as
  **root** -> osqueryd deploys as a **root LaunchDaemon**
  (`/Library/LaunchDaemons/com.scarletai.osqueryd`), replacing the old
  user-space LaunchAgent. The binary must live in a root-owned path
  (`/Library/osquery/osquery.app`) — a root process refuses to execute a
  binary under a user-writable path (`[Ref #1382] unsafe permissions`).
- Config keys: watched paths go under top-level `file_paths` /
  `exclude_paths`; the required flags are `disable_events=false`,
  `disable_endpointsecurity=false`, `disable_endpointsecurity_fim=false`,
  `enable_file_events=true` (all default to the disabled state).
- Root context bypasses user TCC: no Full Disk Access grant is needed for
  the daemon (`startup_items` and ES read the BTM store directly).
- `es_process_events` (evented process telemetry) IS ingested (2026-09-12):
  the parser maps it per the closed vocabulary (exec -> process_start,
  exit -> process_end, fork -> unmapped fail-closed; raw preserved), and
  the schedule query collects event-precise exec/exit/fork rows. Value:
  processes that live and die inside one 60s `processes`-differential
  window are now visible, and codesigning evidence (signing_id, team_id,
  platform_binary, cwd) rides in raw_data for investigations. The plain
  `process_events` table stays out of the schedule (OpenBSM-backed and
  empty on macOS 10.15+).

Daemon install (Raphael-run, sudo):

```bash
cd "<repo>"
sudo cp deploy/com.scarletai.osqueryd.daemon.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.scarletai.osqueryd.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.scarletai.osqueryd.daemon.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.scarletai.osqueryd.daemon.plist
```

Scratch-validation procedure (repeatable): deploy
`deploy/com.scarletai.fim-scratch.daemon.plist` (isolated config + logger
paths), touch watched files, confirm `file_events` rows in
`data/osquery-scratch/osqueryd.results.log`, bootout + remove the plist.

NOTE: `launchctl bootout` of LaunchAgents does not stick — macOS Background
Task Management re-registers plists that remain in `~/Library/LaunchAgents`
(managed LWCR). To retire an agent permanently, move its plist aside.

### 1.4 Verify the pipe end-to-end

```bash
launchctl print gui/$(id -u)/com.scarletai.osqueryd | grep -E "state|pid"
wc -l data/osquery/osqueryd.results.log                      # grows every tick
docker exec scarletai-db psql -U scarletai -d scarletai -tAc \
  "SELECT source, count(*) FROM logs WHERE source LIKE 'osquery:%' GROUP BY source;"
# Fire a labeled detection event through the REAL pipe:
python scripts/generate_osquery_events.py --path data/osquery/osqueryd.results.log
docker exec scarletai-db psql -U scarletai -d scarletai -tAc \
  "SELECT severity, rule_name FROM alerts ORDER BY created_at DESC LIMIT 1;"
# expect: critical|Reverse Shell Pattern Detected (within ~70s)
```

The detection event is a labeled synthetic (`TEST-NET-3` destination) appended
to the real log — the only synthetic in an otherwise real stream.

### 1.5 Scope honesty

This is a **user-level agent** (LaunchAgent, your uid): it sees your processes,
your sockets, your shell history, plus system-wide listener and launchd tables.
A root LaunchDaemon (official pkg `installer`, needs sudo) would add full
system-wide socket/process visibility — same config, different launch scope,
and is a documented upgrade, not a requirement.

## 2. Secrets & posture (Phase 2)

Generated in `.env` (never committed; `openssl rand` per `.env.example`):

- `REDIS_PASSWORD`, `INGEST_BEARER_TOKEN`, `METRICS_BEARER_TOKEN` — staged for
  the local-production overlay (redis auth gates on the overlay, tokens are
  honored by the API immediately).
- Retention windows (`LOGS/ALERTS/AUDIT/CORRELATION/AI_USAGE_RETENTION_DAYS`) —
  bounded storage, job runs hourly.
- `PASSWORD_PEPPER` — **DO NOT set on a live DB with existing users**: there is
  no pepper-less fallback in verification, so every existing hash stops
  validating. Correct sequence: set it at the same moment as the fresh-volume
  production cutover, so every hash is created peppered.

Shipper runtime: `ENABLE_INGESTION_SHIPPER=true`, checkpoint at
`data/shipper_checkpoint` (persistent volume — a `Path.home()` default broke
in-container; fixed 2026-09-04).

## 3. Production cutover — EXECUTED 2026-09-04

The cutover ran on 2026-09-04 with Raphael's approval. Current posture:

- **Loopback-only publishing** (the F-04 LAN-exposure finding is closed):
  postgres `127.0.0.1:5433` (host backup path preserved), api
  `127.0.0.1:8000`, dashboard `127.0.0.1:8501`; redis publishes NOTHING.
- **Redis authenticated** (`--requirepass`, password from `.env`); the API's
  `REDIS_URL` is rewritten with the password; verified: unauthenticated
  `redis-cli ping` → NOAUTH, rate-limit counters live in redis
  (`LIMITS:LIMITER/...` keys, 5/min login limit fired 5×401 → 429 live).
- **PASSWORD_PEPPER active** (required by the overlay, fail-fast). Set at the
  cutover moment, BEFORE the first hash — every user hash is peppered.
- **Docs closed** (`DOCS_ENABLED=false` → `/api/docs` 404), JSON logs,
  no-new-privileges + cap_drop ALL on api/dashboard, memory limits
  (api 1g / dashboard 512m), dashboard live-reload mount removed.
- **Fresh volume**: 0 alerts / 0 demo users; the entrypoint bootstrapped the
  real `admin` (random password → `data/admin_initial_password`, chmod 600 —
  read it once with `cat data/admin_initial_password`, then treat it as
  sensitive; bootstrap sets must_change_password=true, so first login is
  forced through the M-10 change flow).
- Demo data preserved: `data/backups/demo-pre-cutover-20260904-0853.dump`
  (pg_restore custom format, 13 tables verified readable).

### Mode switching

**Production (current default):**
```bash
docker compose -f docker-compose.yml -f docker-compose.local-prod.yml up -d
```

**Demo (client-facing):** stop prod, boot dev compose with the seed flag —
```bash
docker compose -f docker-compose.yml -f docker-compose.local-prod.yml down
cp .env /tmp/prod-env-backup && sed -i '' 's/^DEMO_SEED_ENABLED=.*/DEMO_SEED_ENABLED=true/' .env
docker compose up -d   # entrypoint seeds demo data (demo_analyst / demo_analyst_2026)
# then: make demo-refresh — and restore DEMO_SEED_ENABLED=false in .env afterwards
```
The demo volume is wiped/rewritten by seed-on-empty; the production volume is
untouched while the demo runs on the same named volumes — **pick one mode at a
time**; switching back to production requires `down -v` + re-bootstrap.

### Post-cutover verification (executed, all green)

| Check | Result |
|---|---|
| Publishing | loopback-only (redis unpublished) ✅ |
| Redis auth | NOAUTH unauth / PONG authed ✅ |
| `/api/docs` | 404 ✅ |
| `/api/v1/metrics` | 401 no-token / 200 with token ✅ |
| Login rate limit | 5/min → 429s, counter in redis ✅ |
| Fresh DB | 0 alerts, `admin` only ✅ |
| Telemetry | 189 events within 1 min, growing ✅ |
| Dashboard | 200 / `_stcore` 200 ✅ |
| Health | healthy (api/db/ollama ok) ✅ |

### Known residuals (updated 2026-09-04, P4)

- ~~Audit immutability is convention-only~~ — **RESOLVED**: the two-role deploy
  is live (see §4). Verified: app role has INSERT/SELECT only on audit tables,
  UPDATE/DELETE/TRUNCATE denied at the DB level,
  `check_audit_grants --strict --app-role "$DB_USER"` exits 0 (the script's
  role default reads the `$DB_USER` process env — pass the role explicitly
  or it audits the owner and false-alarms).
- FDA note: terminal-spawned single-shot osquery queries still deny the BTM
  directory (TCC attributes to the terminal); the launchd daemon itself is
  granted and emits `startup_items` rows every 300 s — judge by the daemon's
  own results log, not by hand-run queries.

## 4. Ops: backups, watchdog, audit immutability (P4 — executed 2026-09-04)

### Two-role audit immutability (the "compromised app can't rewrite its own trail" guarantee)

Live setup:
- `scarletai` = cluster superuser + table OWNER (applies schema via
  `DATABASE_SUPERUSER_URL`).
- `scarletai_app` = restricted LOGIN role the API actually runs as: CRUD on
  business tables, **INSERT+SELECT only on audit tables** (UPDATE/DELETE/
  TRUNCATE revoked by `scripts/harden_audit.sql`, re-applied EVERY boot by the
  entrypoint), no CREATE on schema public (least privilege — the entrypoint
  applies the schema via the owner DSN precisely because of this).
- The entrypoint gained the two-role branch: when `DATABASE_SUPERUSER_URL` is
  set, schema apply switches to the owner DSN (a non-owner fails
  `schema.sql` at the first CREATE — verified live; granting CREATE to the app
  role would regress the hardening).
- Verified: tamper tests (UPDATE/DELETE/TRUNCATE → permission denied),
  ingest + audit INSERT through the app role,
  `pg_stat_activity` shows all 10 API connections as `scarletai_app`,
  `check_audit_grants --strict --app-role "$DB_USER"` → exit 0.
- **Retention interaction (by design):** the app role can no longer DELETE
  audit rows, so the in-app retention job reports `audit_sweep_failed`
  (sentinel -2, non-fatal). Audit pruning is owned by the backup script below,
  as the owner, honoring `AUDIT_RETENTION_DAYS`.

### Backups (`scripts/backup_local.sh`, launchd nightly 02:30)

dump (docker exec, custom format) → **VERIFY** (`pg_restore --list`, fails on
zero TABLE DATA — an unverifiable dump is not a backup) → rotate
(`BACKUP_KEEP_DAYS`, default 14) → owner-only audit prune → `--restore-test`
mode restores the newest dump into a throwaway `postgres:17-alpine` and counts
public tables (`--no-privileges`: ACLs target deployment roles, re-applied at
boot). Verified live: `RESTORE TEST PASS: 13 public tables restored`.
Backups live in `data/backups/` (persistent bind; the demo archive from the
cutover is there too).

### Health watchdog (`scripts/health_watchdog.sh`, launchd every 5 min)

Edge-triggered (alerts only on state change — no spam): API health endpoint
(healthy/degraded/down) + Streamlit `_stcore`. Alerts go to
`SLACK_WEBHOOK_URL` (from `.env`, optional) and are ALWAYS appended to
`data/backups/watchdog.log` — never silently dropped.

### Enforcing-flip plan (Sep 16, Raphael's two-week P3.5 window)

**EXECUTED 2026-09-10, six days early** — the flip condition ("remediation
verified complete") held before the window opened: pip-audit residual = the
two documented risk-accepts only (pip-audit now reports them as PYSEC IDs,
aliased to the CVEs; all four IDs ignored with the rationale above), trivy
zero findings. The diff below is retained as the record of what the flip
was.
1. `trivy-image-scan`: currently **zero findings** — remove
   `continue-on-error: true` from the job. Done (executed 2026-09-10).
2. `dependency-audit`: add `--ignore-vuln` entries for the two P4
   risk-accepts (expiry 2026-12-01, rationale in the YAML comment) then
   remove `continue-on-error: true`. Done (executed 2026-09-10; ignore IDs
   cover both the PYSEC and CVE aliases).
3. `python -m scripts.check_audit_grants --strict --app-role "$DB_USER"` is a
   candidate boot gate once any deploy pipeline wants it (exits 0 in the
   local-prod posture; the app role must be explicit or via the exported
   `$DB_USER`).
## 5. Response authority + verified outcomes (V0.4, 2026-09-11)

The production posture carries BOUNDED response actions. The rules:

- **Policy file is law.** `config/response_policy.yaml` maps every action
  type to allow / approval_required / never with blast-radius limits
  (max_per_day) and a requires_case rule. Missing file, unknown action,
  malformed entry, or max_per_day=0 -> NEVER (fail-closed). Edit the file
  to change authority — never the code paths.
- **HITL is non-negotiable.** approval_required actions sit in
  `requested` until an admin approves. The approver cannot be the
  requester (four-eyes, enforced 403 live). Approve = execute + verify;
  `POST /response/actions/{id}/execute` separates the moments when wanted.
- **Verification is a re-query of the source system**, recorded in the
  action's evidence with its mode. Unverified is never reported as
  verified; capability-absent executors (pf/pwpolicy root, osquery fleet)
  refuse with an honest reason instead of simulating.
- **Enforcement point for quarantine_host**: the ingest endpoint refuses
  events from quarantined hosts (batch response carries
  rejected_quarantine). Rollback = delete the row (the action's
  rollback_note documents it).
- **Live-fire protocol** (executed 2026-09-11): dedicated lf-* principals,
  requester/admin token pairs, behavioral proofs (login 200 -> 401 ->
  rollback -> 200), capability refusals recorded. Reports under runs/.

## 6. The Agentic SOC: agent + MCP server runbook (V0.4/5, 2026-09-11)

The frontier layer: a read-only investigation agent, the SIEM as an MCP
server for the analyst's agents, and AI usage as a detection domain.

### Component map

- `scarletai-api` — the agent path: `POST /api/v1/agent/investigate`,
  `GET /agent/runs[/{id}]`, `POST /agent/runs/{id}/hitl` (the HITL gate).
  Runs persist to `agent_investigations`; every step rides the audit
  chain.
- `scarletai-mcp` — the MCP server (same image, `python -m src.mcp_server`,
  loopback-only `127.0.0.1:8002` in local production). Runs AS
  `scarletai_readonly` (scoped read-only DB role). Tools: `investigate`,
  `hunt`, `explain` — read-only, always.

### Scoped read-only role (two-role posture extension)

- Provisioned by the API entrypoint (owner path) when
  `DB_READONLY_PASSWORD` is set; idempotent — re-applying rotates the
  password and re-asserts grants. The password reaches psql via STDIN
  (`\set` lines piped ahead of the script); it never appears in argv or
  logs.
- Grants: SELECT on SIEM data tables; INSERT/SELECT/UPDATE on
  `agent_investigations` (run lifecycle); INSERT/SELECT on
  `audit_log`/`audit_logs`/`ai_usage` (append-only chain). No
  DELETE/TRUNCATE anywhere; no CREATE on schema public.
- The MCP server re-verifies the scope at boot from
  `information_schema.role_table_grants`; any drift -> tools refused
  (fail-closed). `/healthz` reports `scope_ok` + violations.

### MCP protocol surface (POST /mcp, JSON-RPC 2.0)

- `initialize`, `ping`, `tools/list` (3 tools, `readOnlyHint` annotated),
  `tools/call`. Unknown method -> -32601; unknown tool -> -32002 + audit;
  SSE requested -> 422; missing/wrong bearer -> 401 (constant-time).
- Auth token: `MCP_BEARER_TOKEN` in .env (unset = server refuses ALL
  calls — no silent open server).
- Every allowed/denied tools/call writes an audit row
  (`mcp.tool_call`/`mcp.tool_denied`, actor `mcp:<session>`).

### HITL for AI verdicts (non-negotiable, as everywhere)

An AI verdict is a DRAFT with `hitl_state='required'`. Only
`POST /agent/runs/{id}/hitl` moves it — confirmed/rejected with a
mandatory note, attributed to the human reviewer, audited. Committing a
verdict to a case stays the existing human-only `POST /cases/{id}/verdict`
(mandatory rationale). The agent cannot commit anything — by construction
(no write tools exist), by API (409 on already-decided drafts), and by DB
(the scoped role cannot write cases).

### Detection domain (AI usage)

The agent path and MCP server emit AI-usage events (see
docs/AI_USAGE_DETECTIONS.md): closed vocabulary, 4 Sigma rules with OWASP
Agentic ASI mappings, `scripts/generate_ai_usage_events.py` drives the
true/false matrix through the real pipe. Synthetic matrix rows carry
`host_name LIKE 'ai-matrix-%'` (scoped cleanup).

### Triage

| Symptom | First action |
|---|---|
| `/healthz` shows `scope_ok: false` | Read the `scope_violations` list; re-run provisioning (rotate `DB_READONLY_PASSWORD` if needed). Tools are refused until clean — by design. |
| `password authentication failed for user "scarletai_readonly"` | The role was never provisioned or the .env password changed without re-apply. The API entrypoint provisions on boot when `DB_READONLY_PASSWORD` is set. |
| MCP 401 on every call | `MCP_BEARER_TOKEN` unset or wrong — the server refuses all calls rather than serving open (by design). |
| `mcp.tool_denied` with `unknown_tool` | A client called something outside the closed 3-tool surface — expected behavior; check the actor in the audit chain. |
| Agent runs failing with "LLM unavailable" | Ollama down or model unloaded — the run refuses honestly instead of returning a canned verdict (by design). |

## 7. TimescaleDB (V0.5c, shipped 2026-09-12)

`logs` is a TimescaleDB hypertable (1-day chunks). The engine image is
pinned `timescale/timescaledb:2.30.0-pg17`; the schema's `$tsdb$` block is
idempotent and a NO-OP on vanilla PostgreSQL (CI + dev volumes), so the
same schema applies identically on both engines.

What runs where now:

- **Chunk pruning**: time-range scans prune by chunk (BRIN index dropped).
- **Compression**: chunks older than 7 days, segmentby host_name, orderby
  time DESC. Config lives on the table reloptions (TimescaleDB 2.30
  columnstore API); `add_compression_policy` only schedules it.
- **Retention**: `drop_chunks` drops chunks older than 30 days. The in-app
  retention job still owns alerts/correlation/ai_usage and remains a
  fallback sweep for logs (both paths are idempotent in effect).

Standing-volume conversion runbook (executed 2026-09-12):

1. **VERIFIED BACKUP FIRST**: `bash scripts/backup_local.sh` (dump ->
   pg_restore verify -> restore test into throwaway Postgres).
2. **Pre-counts**: `SELECT count(*)` per table (logs / alerts /
   correlation_matches) — the zero-data-loss gate for step 5.
3. `docker compose -f docker-compose.yml -f docker-compose.local-prod.yml
   down` (volumes kept), then `up -d postgres` — db-only boot on the new
   engine; verify healthy before anything else.
4. **Apply the schema as the OWNER**: `docker cp src/db/schema.sql
   scarletai-db:/tmp/schema.sql` then `docker exec scarletai-db psql -U
   scarletai -d scarletai -v ON_ERROR_STOP=1 -f /tmp/schema.sql`. A failed
   DO block rolls back in full (loud failure is the design; no catch-all).
5. **Verify**: hypertable exists, chunk count matches days of data, row
   counts IDENTICAL to pre-counts, both policies present in
   `timescaledb_information.jobs`, `compression_enabled = true`.
6. `make prod` — rebuilds the api image so it carries the new schema.sql
   (build sha re-verified in /health), then the full posture battery + a
   pipeline check (logs growing through the same writer).

**Rollback**: restore the verified backup into a fresh vanilla
`postgres:17-alpine` volume and point compose at the old image. NEVER boot
a timescale-converted volume with the vanilla image: the extension's
objects live in the database catalog and the vanilla binary cannot serve
them.

## 8. Notification channels + scheduled reports (Wave 1, 2026-09-15)

Config (both FAIL-CLOSED, both ship default-off):

- `config/notification_channels.yaml` -- alert routing to Slack / generic
  webhook (HMAC-signed) / PagerDuty / email, per-severity. Secrets are
  env-referenced only (`*_env` keys): a LITERAL secret in the file rejects
  the channel; a missing env at dispatch time refuses that delivery
  (audited), never an unconfigured send.
- `config/scheduled_reports.yaml` -- renders the standing reports
  (coverage / posture / retention / closed-cases digest) on a schedule and
  delivers them through the SAME channels. Closed-case evidence packs stay
  on-demand: the digest carries case ids + evidence-pack pointers, never
  the packs themselves (auto-broadcasting case evidence would be a leak).

Webhook receiver verification (generic webhook channels):

1. The sender signs the CANONICAL body:
   `json.dumps(body, sort_keys=True, separators=(",", ":")).encode()` --
   sort_keys + compact separators. This is the exact byte string signed.
2. `X-ScarletAI-Signature: sha256=<hex hmac_sha256(secret, canonical_body)>`.
3. Receiver-side verify: re-serialize the RAW received body with the same
   canonicalization and compare HMACs (constant-time compare), OR accept
   the raw body if your receiver cannot canonicalize -- then the sender
   must NOT set sort_keys. Both sides must agree on ONE form; the default
   here is the canonical form above.
4. Replay window: the body carries `sent_at` (UTC); drop payloads older
   than your tolerance.

Delivery semantics: bounded retries (default 3, cap 5) with exponential
backoff (1s, 2s, 4s... capped at 30s); 4xx (except 429) fails fast
non-retryable (a config error is not retried); every dispatch outcome is
audited (`notification.attempt` / `report.attempt` in audit_log); delivery
failure NEVER blocks alert creation.

## 9. Release verification (supply chain) — Wave 1, 2026-09-16

Tagged releases (`v*`) build + push the image to ghcr.io by digest, boot-gate
the published image against a live Postgres, generate a CycloneDX SBOM from
that digest, and attach cosign keyless signatures + SLSA v1.0 provenance —
all verified in-pipeline BEFORE the release is published. The buyer-side
verification commands live in **SECURITY.md → "Release verification (supply
chain)"** (single source of truth; not duplicated here). Receipts exist only
from the first tagged release produced by that workflow onward.

## 10. SSF/CAEP identity signals (Wave 1, 2026-09-16)

The SIEM exchanges Shared Signals Framework Security Event Tokens with the
identity layer in both directions. **Both legs ship OFF** — this capability
is behind explicit operator configuration (`config/ssf.yaml`), and
production use is customer-gated (the wave-1 contract).

### Receiver (IdP → SIEM)

`POST /api/v1/ingest/ssf` implements the RFC 8935 push contract:

- request body = the SET (a JWS-signed JWT), `Content-Type:
  application/secevent+jwt` (enforced);
- valid SET → **202 Accepted, empty body** — persisted (source=ssf,
  category=identity) BEFORE the response; detection runs through the
  standard post-ingest pipeline;
- refusal → 400 `{"err", "description"}` + `Content-Language: en-US`, err
  from the IANA SET registry (`invalid_request`, `invalid_audience`,
  `invalid_issuer`, `invalid_key`, `access_denied`); every refusal is
  audited (`ssf.set_refused`, unverified issuer named for the trail only).

Authentication is the SET signature itself — there is intentionally NO
bearer dependency (a leaked SIEM bearer token must not become the SSF trust
root). Enabling the receiver:

```yaml
# config/ssf.yaml
receiver:
  enabled: true
  transmitters:
    - issuer: "https://idp.example.com/"       # the transmitter's iss claim
      aud: "securityscarletai-receiver"        # OUR audience in received SETs
      jwks_uri: "https://idp.example.com/jwks.json"   # TLS required; or inline jwks
      events: [session-revoked, credential-change, verification]
```

Validation (all fail-closed, in RFC order): explicit `secevent+jwt` typ; alg
ES256/RS256 only (HS256 SETs are unsupported in v1); issuer must be
configured; kid-pinned JWKS verification; audience required and matching
(scalar or RFC 7519 array); NO `sub`/`exp` claims; top-level `sub_id`
(RFC 9493); jti + iat required; exactly one event; closed CAEP vocabulary
(credential-change requires credential_type + change_type from the
published sets). A config with a literal private key REJECTS at load —
secrets are env-referenced only. Config path: `SSF_CONFIG_PATH` env override
or the repo default.

### Transmitter (SIEM → IdP layer)

When a response action's outcome is verify()-proven (currently the
session-terminating containment actions: `disable_siem_user`,
`disable_macos_user`), a signed CAEP session-revoked SET is emitted to every
configured receiver. Signing is per receiver (a JWS carries a single aud
claim; each receiver has its own audience). Emission is **best-effort
fire-and-forget**: it never blocks or fails the containment action itself,
every attempt is audited (`ssf.emit_attempt`), each receiver POST gets a 5s
timeout, and there is NO automatic retry (the audited attempt is the honest
record; retransmission policy is an operator decision).

```yaml
# config/ssf.yaml
transmitter:
  enabled: true
  issuer: "https://siem.example.com/"          # our iss claim
  signing_key_env: "SSF_SIGNING_KEY"           # PEM EC P-256 private key, env only
  key_id: "scarletai-caep-1"                   # the kid receivers pin in their JWKS
  receivers:
    - endpoint_url: "https://idp.example.com/ssf/events"
      audience: "https://idp.example.com/"     # the receiver's aud claim
      authorization_header_env: "SSF_RECEIVER_1_AUTH"   # optional
```

Generate the signing key: `openssl ecparam -name prime256v1 -genkey -out
ssf_signing.pem` and load it into the environment (`SSF_SIGNING_KEY`).
Receivers verify our SETs against the public half of that key (the JWKS with
`kid: scarletai-caep-1`).

### Honest scope (wave boundary)

- Validated: unit matrix (64 tests), the RFC 8935 wire contract, and a
  live-DB E2E — signed SET → 202 → logs row (source=ssf, category=identity,
  severity high) → the Sigma rule fired → alert created; refusal → 400 +
  audited; and the full loop (our own transmitter's SET accepted by our own
  receiver).
- NOT yet exercised: a REAL IdP transmitter (Authentik 2025.2+ / Okta dev
  org) pushing live SETs; RFC 8936 (event-stream polling) and the SSF
  management API are follow-ups. HS256-signed SETs are unsupported in v1.
