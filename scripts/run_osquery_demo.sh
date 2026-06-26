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
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

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

# --- 1. Start Postgres -------------------------------------------------------
echo "📦 Starting Postgres via docker compose..."
docker compose up -d postgres 2>/dev/null || docker-compose up -d postgres
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

# --- 3. Prepare a temp osquery log the FileShipper will tail -----------------
OSQ_LOG="$(mktemp -t osqueryd.results.XXXXXX.log)"
trap 'rm -f "$OSQ_LOG"; kill "$API_PID" 2>/dev/null || true' EXIT
echo "📄 Temp osquery log: $OSQ_LOG"

# --- 4. Start the API with the ingestion shipper enabled ---------------------
echo "🚀 Starting API with ENABLE_INGESTION_SHIPPER=true..."
export ENABLE_INGESTION_SHIPPER=true
export OSQUERY_LOG_PATH="$OSQ_LOG"
# shellcheck disable=SC1091
set -a; . ./.env; set +a
poetry run uvicorn src.api.main:app --host 127.0.0.1 --port 8000 >/tmp/scarletai_demo_api.log 2>&1 &
API_PID=$!
echo "   API PID $API_PID (logs: /tmp/scarletai_demo_api.log)"
echo "⏳ Waiting for API health..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
    echo "   API healthy."
    break
  fi
  sleep 1
  [ "$i" -eq 30 ] && { echo "❌ API did not become healthy in 30s. See /tmp/scarletai_demo_api.log"; exit 1; }
done

# --- 5. Emit osquery events (benign + reverse-shell) ------------------------
echo "✍️  Writing osquery events to the tailed log..."
poetry run python3 scripts/generate_osquery_events.py --path "$OSQ_LOG"

# --- 6. Wait for the detection scheduler tick -------------------------------
echo "⏱️  Waiting 70s for the Sigma detection scheduler to tick (run_interval=60s)..."
for s in 70 60 50 40 30 20 10 5 4 3 2 1; do
  printf "\r   %2ss remaining... " "$s"
  sleep 1
done
echo ""
echo "   done waiting."

# --- 7. Show the fired alert ------------------------------------------------
echo ""
echo "🔔 Alerts in the database:"
docker compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT title, severity, status, created_at FROM alerts ORDER BY created_at DESC LIMIT 5;" \
  2>/dev/null || docker-compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT title, severity, status, created_at FROM alerts ORDER BY created_at DESC LIMIT 5;"

echo ""
echo "🔎 Events ingested from the osquery log:"
docker compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT event_action, process_name, left(process_cmdline,60) AS cmdline, ingested_at FROM logs WHERE source LIKE 'osquery%' ORDER BY ingested_at DESC LIMIT 5;" \
  2>/dev/null || docker-compose exec -T postgres psql -U scarletai -d scarletai -c \
  "SELECT event_action, process_name, left(process_cmdline,60) AS cmdline, ingested_at FROM logs WHERE source LIKE 'osquery%' ORDER BY ingested_at DESC LIMIT 5;"

echo ""
echo "🟢 Demo complete. If a 'Reverse Shell Pattern Detected' (critical) alert"
echo "   appears above, the full telemetry pipe is wired: osquery -> shipper ->"
echo "   parser -> DB -> Sigma scheduler -> alert."
echo ""
echo "   Dashboard:  poetry run streamlit run dashboard/main.py --server.port 8501"
echo "   Stop API:   kill $API_PID  (or just exit this script)"
echo ""
echo "Press Ctrl+C to stop the API and clean up."
wait "$API_PID" 2>/dev/null || true