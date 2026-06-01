#!/bin/bash
# Docker entrypoint for SecurityScarletAI.
#
# Responsibilities (in order):
# 1. Wait for Postgres to be reachable.
# 2. Apply schema (idempotent — all CREATE TABLE IF NOT EXISTS).
# 3. Seed demo data IF the alerts table is empty (first run only).
# 4. Train the triage model IF models/triage_model.joblib is missing.
# 5. Train the UEBA model IF models/ueba_model.joblib is missing.
# 6. Create an admin user IF no users exist. Print credentials to stdout ONCE.
# 7. exec uvicorn so it becomes PID 1 (signals work properly).
#
# All steps are idempotent: re-running this script on a populated database
# is a no-op for steps 3-6.
#
# Failure policy: `set -e` means any failed step halts the container.
# That's intentional — better to crash and let Compose restart than to
# start the API against an uninitialised DB.

set -euo pipefail

echo "[entrypoint] $(date -u +%Y-%m-%dT%H:%M:%SZ) — starting SecurityScarletAI"

# ───────────────────────────────────────────────────────────────
# Helper: run a Python block with asyncio.run, in the project root.
# ───────────────────────────────────────────────────────────────
run_async() {
    python -c "$1"
}

# ───────────────────────────────────────────────────────────────
# 1. Wait for Postgres
# ───────────────────────────────────────────────────────────────
echo "[entrypoint] Waiting for Postgres at ${DB_HOST}:${DB_PORT}..."
if command -v pg_isready >/dev/null 2>&1; then
    until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}"; do
        echo "[entrypoint]   postgres not ready, retrying in 2s..."
        sleep 2
    done
else
    # Fallback for slim images without postgresql-client: TCP probe.
    until (echo > "/dev/tcp/${DB_HOST}/${DB_PORT}") 2>/dev/null; do
        echo "[entrypoint]   postgres TCP not open, retrying in 2s..."
        sleep 2
    done
fi
echo "[entrypoint] Postgres is reachable."

# ───────────────────────────────────────────────────────────────
# 2. Apply schema (idempotent)
# ───────────────────────────────────────────────────────────────
echo "[entrypoint] Applying schema if needed..."
run_async "
import asyncio
from pathlib import Path
from src.db.connection import get_pool

async def main():
    pool = await get_pool()
    schema = Path('src/db/schema.sql').read_text()
    async with pool.acquire() as conn:
        await conn.execute(schema)
    await pool.close()
    print('[entrypoint] schema OK')

asyncio.run(main())
"

# ───────────────────────────────────────────────────────────────
# 3. Seed demo data if alerts table is empty
# ───────────────────────────────────────────────────────────────
ALERT_COUNT=$(run_async "
import asyncio
from src.db.connection import get_pool

async def main():
    pool = await get_pool()
    async with pool.acquire() as conn:
        n = await conn.fetchval('SELECT COUNT(*) FROM alerts')
    await pool.close()
    print(n)
asyncio.run(main())
")
if [ "${ALERT_COUNT}" = "0" ]; then
    echo "[entrypoint] alerts table empty — seeding demo data..."
    python -m scripts.seed_demo_data
else
    echo "[entrypoint] alerts table has ${ALERT_COUNT} rows — skipping seed."
fi

# ───────────────────────────────────────────────────────────────
# 4. Train triage model if missing
# ───────────────────────────────────────────────────────────────
if [ ! -f models/triage_model.joblib ]; then
    echo "[entrypoint] Training triage model (first run)..."
    run_async "
import asyncio
from src.ai.alert_triage import AlertTriageModel
async def main():
    m = AlertTriageModel()
    await m.train()
    print('[entrypoint] triage model trained')
asyncio.run(main())
"
else
    echo "[entrypoint] triage model already present."
fi

# ───────────────────────────────────────────────────────────────
# 5. Train UEBA model if missing
# ───────────────────────────────────────────────────────────────
if [ ! -f models/ueba_model.joblib ]; then
    echo "[entrypoint] Training UEBA baseline (first run)..."
    run_async "
import asyncio
from src.ai.ueba import UEBABaseline
async def main():
    m = UEBABaseline()
    await m.train()
    print('[entrypoint] UEBA model trained')
asyncio.run(main())
"
else
    echo "[entrypoint] UEBA model already present."
fi

# ───────────────────────────────────────────────────────────────
# 6. Create admin user if no users exist
# ───────────────────────────────────────────────────────────────
USER_COUNT=$(run_async "
import asyncio
from src.db.connection import get_pool

async def main():
    pool = await get_pool()
    async with pool.acquire() as conn:
        n = await conn.fetchval('SELECT COUNT(*) FROM siem_users')
    await pool.close()
    print(n)
asyncio.run(main())
")
if [ "${USER_COUNT}" = "0" ]; then
    ADMIN_PW=$(python -c "import secrets; print(secrets.token_urlsafe(24))")
    echo "[entrypoint] No users — creating admin..."
    # Pass ADMIN_PW as an env var to the Python subprocess to avoid shell-quoting issues.
    export ADMIN_PW
    run_async "
import asyncio, os
from src.db.connection import get_pool
from src.api.auth import hash_password

ADMIN_PW = os.environ['ADMIN_PW']

async def main():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            'INSERT INTO siem_users (username, email, password_hash, role) VALUES (\$1, \$2, \$3, \$4)',
            'admin', 'admin@localhost', hash_password(ADMIN_PW), 'admin',
        )
    await pool.close()
    print('[entrypoint] admin user created')

asyncio.run(main())
"
    unset ADMIN_PW
    # Surface the password so the operator can grab it from `docker logs`.
    echo "================================================================"
    echo "  ADMIN USER CREATED"
    echo "  username: admin"
    echo "  password: ${ADMIN_PW}"
    echo "  CHANGE THIS PASSWORD IMMEDIATELY on first login."
    echo "================================================================"
else
    echo "[entrypoint] ${USER_COUNT} user(s) present — skipping admin seed."
fi

# ───────────────────────────────────────────────────────────────
# 7. Hand off to uvicorn
# ───────────────────────────────────────────────────────────────
echo "[entrypoint] Starting uvicorn on 0.0.0.0:8000"
exec uvicorn src.api.main:app --host 0.0.0.0 --port 8000
