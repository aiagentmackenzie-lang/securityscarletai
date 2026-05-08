"""add_process_cmdline_and_path_columns

Revision ID: 0cb50438803b
Revises: e8a1c9f7d5b3
Create Date: 2026-05-08 19:43:17.870760

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0cb50438803b'
down_revision: Union[str, Sequence[str], None] = 'e8a1c9f7d5b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('logs', sa.Column('process_cmdline', sa.Text(), nullable=True))
    op.add_column('logs', sa.Column('process_path', sa.Text(), nullable=True))
    op.add_column('cases', sa.Column('lessons_learned', sa.Text(), nullable=True))
    op.add_column('cases', sa.Column('resolution_note', sa.Text(), nullable=True))
    op.add_column('cases', sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('alerts', sa.Column('resolution_note', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('alerts', 'resolution_note')
    op.drop_column('cases', 'resolved_at')
    op.drop_column('cases', 'resolution_note')
    op.drop_column('cases', 'lessons_learned')
    op.drop_column('logs', 'process_path')
    op.drop_column('logs', 'process_cmdline')
