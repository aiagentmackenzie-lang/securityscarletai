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

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="scarletai_${TIMESTAMP}.sql.gz"

echo "Starting backup at $(date)"

# Perform backup — requires .pgpass or PGPASSWORD env var for authentication
if command -v pg_dump &> /dev/null; then
    PGPASSWORD="${DB_PASSWORD}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"
elif [ -d "/opt/homebrew/opt/postgresql@17/bin" ]; then
    PGPASSWORD="${DB_PASSWORD}" /opt/homebrew/opt/postgresql@17/bin/pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"
else
    echo "❌ pg_dump not found. Install PostgreSQL client tools."
    exit 1
fi

# Check if backup was successful
if [ $? -eq 0 ]; then
    echo "✅ Backup successful: ${BACKUP_FILE}"
    ls -lh "${BACKUP_DIR}/${BACKUP_FILE}"
else
    echo "❌ Backup failed!"
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

echo "Backup complete at $(date}"