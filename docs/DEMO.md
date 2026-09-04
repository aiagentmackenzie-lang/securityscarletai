# SecurityScarletAI — Demo Builder Guide

The authoritative sequence for standing up a correct, good-looking demo of
SecurityScarletAI: stack up → health gate → **demo-data freshness** →
page-by-page live verification → serve → teardown. Follow it top to bottom;
every command below was executed and verified against a real spin-up.

**Who this is for:** anyone running the demo — operator, contributor, or
agent. If a step here fails, see [Troubleshooting](#troubleshooting) before
improvising; the gotchas listed there were all hit for real.

---

## 1. The stack

`make up` brings up four services (docker compose):

| Container | Port | Role |
|---|---|---|
| `scarletai-db` | **5433** → 5432 | Postgres (schema, demo data) |
| `scarletai-redis` | 6379 | revocation list, rate limiting, cache |
| `scarletai-api` | **8000** | FastAPI (15 routers, Sigma scheduler, retention) |
| `scarletai-dashboard` | **8501** | Streamlit UI (dark theme) |

Prerequisites: a running docker daemon (`docker info` must answer — Docker
Desktop on desktop Macs, **colima on this Mac mini**: `colima start`; the
compose daemon dies with it), and for live AI features a host Ollama with
**`mistral:7b`** installed (`ollama list | grep mistral:7b`).

```bash
make up        # first boot trains the triage model (~1 min); later boots ~30s
docker compose ps   # wait for all four to report (healthy)
```

> **Demo seed is opt-in (2026-09-01):** fresh boots start with an EMPTY
> database unless `.env` sets `DEMO_SEED_ENABLED=true` before the first
> `make up`. Enable it on demo hosts only — production boots stay empty.

## 2. Health gate

**The API health endpoint is `/api/v1/health` — NOT `/health`.** The root
path 404s by design (docs are env-gated); a 404 here means you typed the
wrong URL, not that the API is down.

```bash
curl -s http://localhost:8000/api/v1/health
# expect: {"status":"healthy","checks":{"api":"ok","database":"ok","ollama":"ok"},...}
curl -s http://localhost:8501/_stcore/health        # expect: ok
ollama list | grep mistral:7b                        # expect: a mistral:7b line
```

All three `checks` must be `ok`. `ollama: down` → the host Ollama isn't
running (or the model isn't installed); AI chat/explain pages degrade
gracefully but say so.

## 3. Demo data freshness — READ THIS FIRST

The seed (`scripts/seed_demo_data.py`) generates timestamps relative to
**seed time** (logs now−1..2880 min, alerts now−1..48 h, cases now−6..72 h),
and the entrypoint **only seeds an empty database**. Consequence: after the
first boot, every later spin-up reuses the same snapshot, and within ~24–48 h
of wall-clock time it ages out of every dashboard window. The demo then
**looks broken** — empty Log Viewer, stale Overview — while the API is
perfectly healthy. This is the #1 demo failure mode.

**The fix — one command before every demo:**

```bash
make demo-refresh
# or: docker compose exec api python -m scripts.refresh_demo_timestamps
# preview only:  ... --dry-run
```

It shifts every demo timestamp (logs, alerts, cases, correlation matches,
threat-intel seen-windows, AI usage — 14 columns across 6 tables) plus the
timestamps embedded inside `cases.notes` JSON by ONE interval, so the newest
attack event lands ~10 minutes before now and every relative offset — attack
story, case timelines, IOC windows — is preserved. Never touched: `siem_users`,
`rules`, `alert_suppressions`, and the append-only `audit_log`/`audit_logs`.
Idempotent: exits 0 with "already fresh" if the newest event is < 60 min old.

Verify:

```bash
docker exec scarletai-db psql -U scarletai -d scarletai -tAc \
  "SELECT max(time) FROM logs; SELECT max(time) FROM alerts;"
# both should be within the last hour after a refresh
```

## 4. Page-by-page live verification

Log in as the demo user, grab a token, and hit every endpoint a dashboard
page uses — **the way the dashboard calls it**. A container can be "healthy"
while a page is broken (that's how a route-shadowing bug shipped); verify
rendered reality, not just green containers.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo_analyst","password":"demo_analyst_2026"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
```

| Dashboard page | Call it like the dashboard does | Expected on a fresh demo |
|---|---|---|
| Overview | `GET /api/v1/alerts/stats` | `total_count: 35`, 12 critical / 12 high / 9 medium / 2 low |
| Alerts | `GET /api/v1/alerts?limit=500` | 200, 35 rows |
| Log Viewer (default **All time**) | `GET /api/v1/logs?limit=100` | 20 rows |
| Log Viewer — 24 h window | `GET /api/v1/logs?limit=100&time_minutes=1440` | ~11 rows — the seed spreads logs uniformly over 48 h (`randint(1, 2880)` min), so ~half sit beyond 24 h by design (2026-09-04: corrected — "20 rows" was a stale expectation that never matched the seed shape). **0 rows ⇒ stale data, run `make demo-refresh`** |
| Cases | `GET /api/v1/cases` | 3 cases |
| Threat Intel | `GET /api/v1/threat-intel/stats` | `total_indicators: 15` |
| Rules | `GET /api/v1/rules` | 100 Sigma rules |
| **Suppressions** | `GET /api/v1/alerts/suppressions` | **200 `[]`** — a 422 here is the route-shadowing regression (`/{alert_id}` swallowing the literal path); fixed in repo history: `fix/suppressions-route-shadowing` |
| AI status | `GET /api/v1/ai/status` | `mistral:7b` ready |

Example:

```bash
curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/alerts/suppressions     # expect 200
```

## 5. Credentials & login

- **Demo login:** `demo_analyst` / `demo_analyst_2026` (role `analyst` —
  seeded by `scripts/seed_demo_data.py`).
- **Admin:** `admin` exists but its password is random, generated once by the
  entrypoint bootstrap. Post-hardening bootstraps write it to
  `data/admin_initial_password` inside the api container (chmod 600);
  bootstraps from before that fix have no recoverable password — reset it
  against the demo DB if admin access is needed.
- The dashboard's `DASHBOARD_API_TOKEN` auto-auth is **off** unless you set
  the env var (and it means admin — see DEPLOYMENT.md "Dashboard exposure").

Open the demo: **http://localhost:8501** (Chrome).

## 6. Optional — live telemetry (the streaming demo)

Static demo data proves the UI; the live demo proves the pipeline:

```bash
make demo    # scripts/run_osquery_demo.sh
```

Streams realistic osquery events through the FileShipper → ingest → Sigma
scheduler → fires a real critical alert, end-to-end. It deliberately uses
port 8001 and waits ~70 s for a scheduler tick — that wait is the real
scheduler working. Note: it stops the compose `api` container to avoid two
schedulers racing on one DB; re-run `make up` afterwards to restore the
full four-container stack.

## 7. Teardown

```bash
make down      # removes containers + network, KEEPS volumes (pgdata/redisdata)
```

Volumes survive: alerts, cases, users come back on the next `make up`
(seeding is skipped when data exists — hence §3). The host Ollama is
untouched. Log the end state wherever you track sessions.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker info` fails | Docker daemon not running (Mac rebooted; colima host: VM stopped) | `open -a "Docker Desktop"` or `colima start`, wait for `docker info` to answer, then `make up` |
| API crash-loops: `entrypoint.sh: psql: command not found` | Pre-fix slim image: Phase C dropped postgresql-client with the build toolchain; entrypoint schema-apply needs `psql -f` (fixed `fix/slim-image-boot-deps`) | Rebuild: `git pull` main, `docker compose build api dashboard`, `make up` |
| API container runs but reports `(unhealthy)`, dashboard stuck on `api: service_healthy` | Pre-fix compose healthchecks used `curl`, which is not in the slim image (same regression) | Same fix — rebuild compose services so the compose file's python probes take effect |
| Empty DB on fresh boot (no demo alerts, no demo login) | Demo seed is opt-in since 2026-09-01 (`DEMO_SEED_ENABLED`) | Add `DEMO_SEED_ENABLED=true` to `.env` BEFORE the first `make up`, then `make down && make up` |
| Log Viewer / pages empty, API healthy | Demo data older than the page's time window (seed ages out in ~24–48 h) | `make demo-refresh`, re-check §4 |
| `GET /health` → 404 | Wrong path — it's `/api/v1/health` | Use §2 verbatim |
| `GET /alerts/suppressions` → 422 | Route-shadowing regression (literal path captured by `/{alert_id}`) | Fixed on main (`fix/suppressions-route-shadowing`); confirm branch history before re-debugging |
| AI chat / explain says model unavailable | Ollama down or model missing | `ollama list | grep mistral:7b`; start host Ollama; `OLLAMA_MODEL` must say `mistral:7b` (the installed model — llama3.2 is NOT installed) |
| Dashboard login loop / 401 | Session expired (JWT TTL) | Log in again with §5 credentials |
| Admin password unknown | Random bootstrap password, pre-hardening stack (no password file) | Reset the hash against the demo DB (ask the maintainer/agent); durable file exists on post-hardening bootstraps |
| `make demo-refresh` can't connect | API container not running (env + network live there) | `make up` first |

---

*Verified end-to-end 2026-08-28: stack up → health gate → demo-refresh →
all nine page checks green (35 alerts / 20 logs / 3 cases / 15 TI / 100 rules
/ suppressions 200). Maintained alongside `scripts/refresh_demo_timestamps.py`
(tests: `tests/unit/test_demo_refresh.py`).*