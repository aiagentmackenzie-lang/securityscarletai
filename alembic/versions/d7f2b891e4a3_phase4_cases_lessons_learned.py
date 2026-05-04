"""phase4_cases_lessons_learned

Revision ID: d7f2b891e4a3
Revises: c54a2335ab60
Create Date: 2026-05-03 18:30:00.000000

Adds lessons_learned and resolution fields to cases table.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d7f2b891e4a3"
down_revision: Union[str, Sequence[str], None] = "c54a2335ab60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add lessons_learned and resolved_at columns to cases table."""
    op.execute("""
        ALTER TABLE cases ADD COLUMN IF NOT EXISTS lessons_learned TEXT;
    """)
    op.execute("""
        ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolution_note TEXT;
    """)
    op.execute("""
        ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
    """)

    # Add index on cases.status for filtering
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status, updated_at DESC);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_cases_assigned ON cases (assigned_to, status);
    """)


def downgrade() -> None:
    """Remove lessons_learned and resolution columns from cases."""
    op.execute("DROP INDEX IF EXISTS idx_cases_assigned")
    op.execute("DROP INDEX IF EXISTS idx_cases_status")
    op.execute("ALTER TABLE cases DROP COLUMN IF EXISTS resolved_at")
    op.execute("ALTER TABLE cases DROP COLUMN IF EXISTS resolution_note")
    op.execute("ALTER TABLE cases DROP COLUMN IF EXISTS lessons_learned")