#!/usr/bin/env bash
# Local production backup for SecurityScarletAI (single-host, docker-local).
#
# What it does, in order:
#   1. pg_dump (custom format) via the DB container's socket — no host client
#      or passwords needed (docker exec + trust auth).
#   2. VERIFY the dump: a backup that cannot be listed by pg_restore is a
#      hope, not a backup. Counts TABLE DATA entries (structure) AND records
#      per-table ROW COUNTS from the source into <dump>.counts.json (SS-044 —
#      a TOC entry proves a data section exists, not that rows exist).
#   3. Rotate: keep the newest KEEP_DAYS days of dumps.
#   4. Audit prune (two-role deploy): the app role can no longer DELETE
#      audit rows (append-only hardening), so the retention job reports
#      audit_sweep_failed (sentinel -2) by design — THIS script owns audit
#      pruning as the owner/superuser, honoring AUDIT_RETENTION_DAYS.
#   5. Optional restore test: --restore-test spins a THROWAWAY postgres:17
#      container, restores the newest dump, and compares per-table row counts
#      against <dump>.counts.json (SS-044). Fewer rows than the source = fail;
#      a table that had rows and restored zero = fail. Table presence alone is
#      no longer accepted as verification.
#
# Usage:
#   scripts/backup_local.sh                  # nightly run (launchd)
#   scripts/backup_local.sh --restore-test   # weekly full restore verification
#
# Designed for the repo-root CWD (launchd: WorkingDirectory set in the plist).
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
BACKUP_DIR="$REPO_ROOT/data/backups"
LOG="$BACKUP_DIR/backup.log"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
DB_CONTAINER="${DB_CONTAINER:-scarletai-db}"
DB_NAME="${DB_NAME:-scarletai}"
DB_USER_OWNER="${DB_USER_OWNER:-scarletai}"   # owner/superuser inside the container
TS="$(date +%Y%m%d-%H%M)"
DUMP="$BACKUP_DIR/scarletai-$TS.dump"

mkdir -p "$BACKUP_DIR"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"; }

# python for the JSON count bookkeeping: the project venv when present (launchd
# has a minimal PATH), else python3.
PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
    if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
        PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
    else
        PYTHON_BIN="$(command -v python3 || true)"
    fi
fi
if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR python3 not found — cannot record/verify backup row counts" >&2
    exit 1
fi

# ── 1. Dump ─────────────────────────────────────────────────────
if ! docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER_OWNER" -d "$DB_NAME" -F c -f /tmp/_backup.dump; then
    log "ERROR pg_dump failed"; exit 1
fi
docker cp "$DB_CONTAINER:/tmp/_backup.dump" "$DUMP" >/dev/null
docker exec "$DB_CONTAINER" rm -f /tmp/_backup.dump
log "dumped $DUMP ($(du -h "$DUMP" | cut -f1))"

# ── 2. Verify ───────────────────────────────────────────────────
docker cp "$DUMP" "$DB_CONTAINER:/tmp/_verify.dump" >/dev/null
TABLES=$(docker exec "$DB_CONTAINER" pg_restore --list /tmp/_verify.dump 2>/dev/null | grep -c "TABLE DATA" || true)
docker exec "$DB_CONTAINER" rm -f /tmp/_verify.dump
if [ "${TABLES:-0}" -lt 1 ]; then
    log "ERROR dump verification failed (0 TABLE DATA entries) — $DUMP is NOT trusted"
    exit 1
fi
log "verified $DUMP ($TABLES tables)"

# ── 2b. Row counts (SS-044) ─────────────────────────────────────
# Record what the SOURCE had at dump time. The TOC gate above proves the dump
# carries data sections; only row counts prove the data exists and restores.
VERIFY_TABLES="${BACKUP_VERIFY_TABLES:-logs alerts cases audit_log audit_logs}"
COUNTS="$DUMP.counts.json"
: > /tmp/_counts.txt
for t in $VERIFY_TABLES; do
    n=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER_OWNER" -d "$DB_NAME" -tAc \
        "SELECT count(*) FROM $t;" 2>/dev/null || echo "")
    if [ -z "$n" ]; then
        log "WARN row count unavailable for table $t (missing table?) — recording 0"
        n=0
    fi
    echo "$t=$n" >> /tmp/_counts.txt
done
if ! "${PYTHON_BIN}" - "$COUNTS" <<'COUNTSPY'
import json, sys
counts = {}
for line in open("/tmp/_counts.txt"):
    if "=" in line:
        t, _, v = line.strip().rpartition("=")
        if v.strip().isdigit():
            counts[t] = int(v)
json.dump(counts, open(sys.argv[1], "w"), indent=2, sort_keys=True)
COUNTSPY
then
    log "ERROR could not record source row counts — refusing to call this dump verified"
    exit 1
fi
rm -f /tmp/_counts.txt
log "recorded source row counts: $(tr '\n' ' ' < "$COUNTS")"

# ── 3. Rotate ───────────────────────────────────────────────────
find "$BACKUP_DIR" \( -name "scarletai-*.dump" -o -name "scarletai-*.dump.counts.json" \) \
    -mtime +"$KEEP_DAYS" -delete 2>/dev/null || true

# ── 4. Audit prune (owner-only; the app role is append-only-hardened) ──
AUDIT_DAYS="$(grep -E '^AUDIT_RETENTION_DAYS=' "$REPO_ROOT/.env" 2>/dev/null | cut -d= -f2)"
AUDIT_DAYS="${AUDIT_DAYS:-365}"
DELETED=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER_OWNER" -d "$DB_NAME" -tAc \
    "DELETE FROM audit_logs WHERE \"timestamp\" < now() - interval '$AUDIT_DAYS days'; \
     DELETE FROM audit_log WHERE created_at < now() - interval '$AUDIT_DAYS days'; \
     SELECT 1;" >/dev/null 2>&1 && echo "ok" || echo "failed")
log "audit prune (>${AUDIT_DAYS}d, owner): $DELETED"

# ── 5. Optional restore test ────────────────────────────────────
if [ "${1:-}" = "--restore-test" ]; then
    LATEST=$(ls -t "$BACKUP_DIR"/scarletai-*.dump | head -1)
    C="scarletai-restore-test-$$"
    log "restore test: spinning throwaway postgres for $LATEST"
    docker run -d --rm --name "$C" -e POSTGRES_PASSWORD=restoretest \
        -e POSTGRES_DB=scarletai -e POSTGRES_USER=scarletai postgres:17-alpine >/dev/null
    trap 'docker rm -f "$C" >/dev/null 2>&1' EXIT
    sleep 5
    docker cp "$LATEST" "$C:/tmp/restore.dump" >/dev/null
    if docker exec "$C" pg_restore -U scarletai -d scarletai --no-owner --no-privileges \
            --role=scarletai \
            /tmp/restore.dump >/dev/null 2>&1; then
        N=$(docker exec "$C" psql -U scarletai -d scarletai -tAc \
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
        if [ "$N" -lt 10 ]; then
            log "ERROR restore test restored only $N tables"; exit 1
        fi

        # SS-044: schema presence is not data presence. Compare the restored
        # row counts against the source snapshot recorded at dump time.
        RESTORED="/tmp/_restored_counts.json"
        : > /tmp/_restored.txt
        for t in $VERIFY_TABLES; do
            n=$(docker exec "$C" psql -U scarletai -d scarletai -tAc \
                "SELECT count(*) FROM $t;" 2>/dev/null || echo 0)
            echo "$t=${n:-0}" >> /tmp/_restored.txt
        done
        "${PYTHON_BIN}" - "$RESTORED" <<'RESTOREDPY'
import json, sys
counts = {}
for line in open("/tmp/_restored.txt"):
    if "=" in line:
        t, _, v = line.strip().rpartition("=")
        if v.strip().isdigit():
            counts[t] = int(v)
json.dump(counts, open(sys.argv[1], "w"), indent=2, sort_keys=True)
RESTOREDPY
        rm -f /tmp/_restored.txt
        if "${PYTHON_BIN}" "$REPO_ROOT/scripts/verify_backup_rows.py" \
                --expected "$LATEST.counts.json" --actual "$RESTORED"; then
            log "RESTORE TEST PASS: $N public tables + row counts verified from $(basename "$LATEST")"
        else
            log "ERROR restore test: row counts do not match the source — $(basename "$LATEST") is NOT a verified backup"
            exit 1
        fi
        rm -f "$RESTORED"
    else
        log "ERROR restore test: pg_restore failed"; exit 1
    fi
fi
log "backup cycle complete"