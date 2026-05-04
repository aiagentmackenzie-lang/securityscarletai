#!/bin/bash
# SecurityScarletAI Database Backup Script
# Run daily via cron: 0 2 * * * /path/to/backup.sh

set -e

# Configuration — override via environment variables
BACKUP_DIR="${SCARLET_BACKUP_DIR:-${HOME}/scarletai-backups}"
DB_NAME="${SCARLET_DB_NAME:-scarletai}"
DB_HOST="${SCARLET_DB_HOST:-localhost}"
DB_PORT="${SCARLET_DB_PORT:-5433}"
DB_USER="${SCARLET_DB_USER:-scarletai}"
RETENTION_DAYS="${SCARLET_RETENTION_DAYS:-7}"

# H-17 fix: Use ~/.pgpass file instead of PGPASSWORD env var
# Ensure ~/.pgpass exists with correct entry (chmod 600)
PGPASS_FILE="${HOME}/.pgpass"
if [ ! -f "$PGPASS_FILE" ]; then
    echo "❌ ~/.pgpass not found. Create it with: echo '${DB_HOST}:${DB_PORT}:${DB_NAME}:${DB_USER}:YOUR_PASSWORD' > ~/.pgpass && chmod 600 ~/.pgpass"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="scarletai_${TIMESTAMP}.sql.gz"

echo "Starting backup at $(date)"

# H-19 fix: Capture exit code immediately after pg_dump, before the if block
PGDUMP_CMD="pg_dump"
if [ ! -x "$(command -v pg_dump 2>/dev/null)" ] && [ -d "/opt/homebrew/opt/postgresql@17/bin" ]; then
    PGDUMP_CMD="/opt/homebrew/opt/postgresql@17/bin/pg_dump"
fi

if ! command -v "$PGDUMP_CMD" &> /dev/null; then
    echo "❌ pg_dump not found. Install PostgreSQL client tools."
    exit 1
fi

# Run backup and capture exit code before pipe
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"
"$PGDUMP_CMD" -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" > "${BACKUP_DIR}/_temp_backup.sql" 2>/dev/null
PGDUMP_EXIT=$?

if [ $PGDUMP_EXIT -eq 0 ]; then
    gzip "${BACKUP_DIR}/_temp_backup.sql"
    mv "${BACKUP_DIR}/_temp_backup.sql.gz" "$BACKUP_PATH"
    echo "✅ Backup successful: ${BACKUP_FILE}"
    ls -lh "$BACKUP_PATH"
else
    # Clean up temp file on failure
    rm -f "${BACKUP_DIR}/_temp_backup.sql" 2>/dev/null
    echo "❌ Backup failed! pg_dump exit code: ${PGDUMP_EXIT}"
    exit 1
fi

# Remove backups older than retention period
echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "scarletai_*.sql.gz" -mtime +"${RETENTION_DAYS}" -delete

# Count remaining backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "scarletai_*.sql.gz" | wc -l)
echo "📊 Total backups retained: ${BACKUP_COUNT}"

# Show backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
echo "💾 Total backup size: ${BACKUP_SIZE}"

# H-18 fix: Changed $(date} → $(date) — was mismatched braces
echo "Backup complete at $(date)"