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

### 1.3 Full Disk Access (TCC)

`startup_items` reads the Background Task Management directory and returns
empty (with a TCC warning) until osqueryd has Full Disk Access. Grant it via
System Settings → Privacy & Security → Full Disk Access → add
`~/Applications/osquery/osquery.app/Contents/MacOS/osqueryd` (or the app
bundle). Everything else in the schedule works without it. FIM (`file_events`)
is currently DISABLED in the conf: osquery's macOS FIM runs on EndpointSecurity
(the official build carries the entitlement) but needs its own FDA grant +
validation pass before being trusted — treat it as a follow-up, not a
given.

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
  sensitive; first login forces a password change).
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

### Known residuals (documented, P4 queue)

- Audit immutability is convention-only (single-role deploy) — the two-role
  `harden_audit.sql` deploy is the P4 ops item.
- FDA note: terminal-spawned single-shot osquery queries still deny the BTM
  directory (TCC attributes to the terminal); the launchd daemon itself is
  granted and emits `startup_items` rows every 300 s — judge by the daemon's
  own results log, not by hand-run queries.