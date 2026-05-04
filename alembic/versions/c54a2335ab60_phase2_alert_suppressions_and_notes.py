"""phase2_alert_suppressions_and_notes

Revision ID: c54a2335ab60
Revises:
Create Date: 2026-05-03 15:09:03.014116

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c54a2335ab60'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema for Phase 2: Alert management and threat intel enhancements."""

    # Add notes column to alerts (timeline entries)
    op.execute("""
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes JSONB DEFAULT '[]'::jsonb;
    """)

    # Create alert_suppressions table for false positive whitelisting
    op.execute("""
        CREATE TABLE IF NOT EXISTS alert_suppressions (
            id SERIAL PRIMARY KEY,
            rule_name TEXT,
            host_name TEXT,
            reason TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    # Add indexes for suppression rule lookups
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON alert_suppressions (rule_name) WHERE enabled = TRUE;
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_suppressions_host ON alert_suppressions (host_name) WHERE enabled = TRUE;
    """)

    # Add dedup column and escalation tracking to alerts
    op.execute("""
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_key TEXT;
    """)

    # Add dedup index for faster lookups
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts (rule_id, host_name, time DESC);
    """)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE IF EXISTS alert_suppressions")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS notes")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS dedup_key")
    op.execute("DROP INDEX IF EXISTS idx_alerts_dedup")
    op.execute("DROP INDEX IF EXISTS idx_suppressions_rule")
    op.execute("DROP INDEX IF EXISTS idx_suppressions_host")