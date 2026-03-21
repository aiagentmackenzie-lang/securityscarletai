#!/bin/bash
# SecurityScarletAI Database Backup Script
# Run daily via cron or launchd

set -e

# Configuration
BACKUP_DIR="${HOME}/scarletai-backups"
DB_NAME="scarletai"
RETENTION_DAYS=7

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="scarletai_${TIMESTAMP}.sql.gz"

# Export PostgreSQL path for Homebrew installations
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"

echo "Starting backup at $(date)"

# Perform backup
pg_dump "$DB_NAME" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

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
find "$BACKUP_DIR" -name "scarletai_*.sql.gz" -mtime +${RETENTION_DAYS} -delete

# Count remaining backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "scarletai_*.sql.gz" | wc -l)
echo "📊 Total backups retained: ${BACKUP_COUNT}"

# Optional: Show backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
echo "💾 Total backup size: ${BACKUP_SIZE}"

echo "Backup complete at $(date)"
