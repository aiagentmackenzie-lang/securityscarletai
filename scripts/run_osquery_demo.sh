#!/usr/bin/env bash
# SecurityScarletAI — live telemetry demo.
#
# Proves the SIEM ingests a REAL log source (osquery results log) and fires
# detection live, end-to-end:
#   osquery log  ->  FileShipper (tail)  ->  parser  ->  writer  ->  DB
#   ->  Sigma detection scheduler  ->  alerts row
#
# It does NOT require osqueryd to be installed — scripts/generate_osquery_events.py
# writes realistic osquery-format lines to a temp log that the FileShipper tails.
#
# Prerequisites:
#   - Docker (for Postgres)  +  .env in the repo root with DB_PASSWORD,
#     API_SECRET_KEY, API_BEARER_TOKEN set.
#   - Poetry environment installed (poetry install).
#
# The detection scheduler runs each Sigma rule on its run_interval (default 60s),
# so this script waits ~70s for the first tick. That wait IS the demo — it's the
# real scheduler, not a forced run.
#
# Design notes (hard-won):
#   - The API is launched from poetry on port 8001 (NOT 8000) to avoid collisions
#     with stale compose api containers, colima port-forwards, or ssh tunnels
#     that may already hold :8000.
#   - We do NOT `set -a; . ./.env` — bash quote-stripping corrupts JSON values
#     like API_CORS_ORIGINS and crashes pydantic on startup. pydantic reads .env
#     itself; we only export the overrides (DB port + shipper flags).
#   - We stop any stale compose `api` container first so it can't serve :8000
#     with old code or run a competing scheduler against the same DB.
#   - We verify the API *process* is alive, not just that a port answers.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
API_PORT=8001

# --- 0. Prerequisites --------------------------------------------------------
if [ ! -f .env ]; then
  echo "❌ No .env found in $REPO_ROOT. Copy .env.example and set DB_PASSWORD,"
  echo "   API_SECRET_KEY, and API_BEARER_TOKEN before running this demo."
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "❌ docker not found. This demo needs Docker to run Postgres."
  exit 1
fi

# --- 1. Start Postgres + stop any stale API container ------------------------
echo "📦 Starting Postgres + Redis via docker compose..."
docker compose up -d postgres redis 2>/dev/null || docker-compose up -d postgres redis
# Stop a stale compose api container so it can't serve :8000 with old code or
# run a competing detection scheduler against the same database.
docker compose stop api 2>/dev/null || true
echo "⏳ Waiting for Postgres to accept connections..."
for i in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U scarletai >/dev/null 2>&1 \
     || docker-compose exec -T postgres pg_isready -U scarletai >/dev/null 2>&1; then
    echo "   Postgres ready."
    break
  fi
  sleep 1
  [ "$i" -eq 30 ] && { echo "❌ Postgres did not become ready in 30s."; exit 1; }
done

# --- 2. Apply schema (schema.sql is canonical; Alembic is not used) ----------
echo "🗄️ Applying src/db/schema.sql..."
docker compose exec -T postgres psql -U scarletai -d scarletai \
  -f /dev/stdin < src/db/schema.sql >/dev/null 2>&1 \
  || docker-compose exec -T postgres psql -U scarletai -d scarletai \
       -f /dev/stdin < src/db/schema.sql >/dev/null 2>&1
echo "   Schema applied."

# --- 2.5. Clear prior demo data for this demo host so a re-run isn't -----
#       fooled by stale alerts from a previous run. Scoped to demo-mac.local.
echo "🧹 Clearing prior demo-mac.local alerts/events (if any)..."
docker compose exec -T postgres psql -U scarletai -d scarletai -c \
  "DELETE FROM alerts WHERE host_name='demo-mac.local'; DELETE FROM logs WHERE host_name='demo-mac.local';" \
  >/dev/null 2>&1 || true

# --- 3. Prepare a temp osquery log the FileShipper will tail -----------------
OSQ_LOG="$(mktemp -t osqueryd.results.XXXXXX.log)"
API_PID=""
trap 'rm -f "$OSQ_LOG"; [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true' EXIT
echo "📄 Temp osquery log: $OSQ_LOG"

# --- 4. Start the API with the ingestion shipper enabled ---------------------
echo "🚀 Starting API (poetry, port $API_PORT) with ENABLE_INGESTION_SHIPPER=true..."
export ENABLE_INGESTION_SHIPPER=true
export OSQUERY_LOG_PATH="$OSQ_LOG"
export DB_HOST=localhost
export DB_PORT=5433            # compose maps host 5433 -> container 5432
poetry run uvicorn src.api.main:app --host 127.0.0.1 --port "$API_PORT" >/tmp/scarletai_demo_api.log 2>&1 &
API_PID=$!
echo "   API PID $API_PID (logs: /tmp/scarletai_demo_api.log)"
sleep 3
if ! kill -0 "$API_PID" 2>/dev/null; then
  echo "❌ API crashed on startup. Last log lines:"
  tail -30 /tmp/scarletai_demo_api.log
  exit 1
fi
echo "⏳ Waiting for API health on :$API_PORT..."
for i in $(seq 1 30); do
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "❌ API process died during startup. Last log lines:"
    tail -30 /tmp/scarletai_demo_api.log
    exit 1
  fi
  if curl -sf "http://127.0.0.1:$API_PORT/api/v1/health" >/dev/null 2>&1; then
    echo "   API healthy (our process $API_PID)."
    break
  fi
  sleep 1
  [ "$i" -eq 30 ] && { echo "❌ API did not become healthy in 30s. See /tmp/scarletai_demo_api.log"; tail -30 /tmp/scarletai_demo_api.log; exit 1; }
done

# --- 5. Emit osquery events (benign + reverse-shell) ------------------------
echo "✍️  Writing osquery events to the tailed log..."
poetry run python3 scripts/generate_osquery_events.py --path "$OSQ_LOG"

# --- 6. Poll for the fired alert (robust to scheduler timing) ----------------
# The Sigma scheduler runs each rule on its run_interval (default 60s), but API
# startup (Ollama validation, rule loading) delays the first tick. A fixed wait
# races the tick; instead poll up to 150s and report as soon as the alert lands.
echo "⏱️  Polling for the fired alert (up to 150s — real Sigma scheduler tick)..."
ALERT_FOUND=""
for i in $(seq 1 30); do
  RESULT=$(docker compose exec -T postgres psql -U scarletai -d scarletai -t -A -c \
    "SELECT rule_name || ' | ' || severity || ' | ' || host_name FROM alerts WHERE host_name='demo-mac.local' ORDER BY time DESC LIMIT 1;" 2>/dev/null || true)
  if [ -n "$RESULT" ]; then
    ALERT_FOUND="$RESULT"
    echo ""
    echo "   ✅ alert fired after ~$((i*5))s: $RESULT"
    break
  fi
  printf "\r   waiting for scheduler tick... %3ds/150s" $((i*5))
  sleep 5
done
echo ""
if [ -z "$ALERT_FOUND" ]; then
  echo "   ⚠️  No alert fired within 150s. Check /tmp/scarletai_demo_api.log for"
  echo "       detection errors (the ingestion above still proves the shipper pipe)."
fi

# --- 7. Show the fired alert (filtered to THIS demo's host) ------------------
echo ""
echo "🔔 Alerts fired by THIS demo (host demo-mac.local):"
docker compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT rule_name, severity, status, host_name, time FROM alerts WHERE host_name='demo-mac.local' ORDER BY time DESC;" \
  2>/dev/null || docker-compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT rule_name, severity, status, host_name, time FROM alerts WHERE host_name='demo-mac.local' ORDER BY time DESC;"

echo ""
echo "🔎 Events ingested from THIS demo's osquery log (host demo-mac.local):"
docker compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT event_action, process_name, left(process_cmdline,55) AS cmdline, ingested_at FROM logs WHERE host_name='demo-mac.local' ORDER BY ingested_at DESC;" \
  2>/dev/null || docker-compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT event_action, process_name, left(process_cmdline,55) AS cmdline, ingested_at FROM logs WHERE host_name='demo-mac.local' ORDER BY ingested_at DESC;"

echo ""
echo "🟢 Demo complete. If a 'Reverse Shell Pattern Detected' (critical) alert"
echo "   appears above for host demo-mac.local, the full telemetry pipe is wired:"
echo "   osquery log -> FileShipper -> parser -> LogWriter -> Postgres -> Sigma"
echo "   scheduler -> alert."
echo ""
echo "   Dashboard:  poetry run streamlit run dashboard/main.py --server.port 8501"
echo "   Stop API:   kill $API_PID  (or just exit this script)"
echo ""
echo "Press Ctrl+C to stop the API and clean up."
wait "$API_PID" 2>/dev/null || true