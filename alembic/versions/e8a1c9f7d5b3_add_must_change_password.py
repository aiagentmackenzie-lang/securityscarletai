"""add must_change_password column to siem_users

M-10 SHA-256 pre-hash migration: existing bcrypt(raw_password) hashes
are incompatible with the new bcrypt(sha256(password)) verification.
All existing users must change their password on next login.

Revision ID: e8a1c9f7d5b3
Revises: d7f2b891e4a3
Create Date: 2026-05-04

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = 'e8a1c9f7d5b3'
down_revision = 'd7f2b891e4a3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add must_change_password column and flag all existing users."""
    op.add_column(
        'siem_users',
        sa.Column('must_change_password', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    )

    # Flag all existing users for password reset
    op.execute("UPDATE siem_users SET must_change_password = true")

    # Log the migration
    op.execute(
        "INSERT INTO audit_log (actor, action, target_type, new_values) "
        "VALUES ('system', 'user.password_migration', 'user', "
        "'{\"description\": \"M-10 SHA-256 pre-hash migration: all users flagged for password reset\"}')"
    )


def downgrade() -> None:
    """Remove must_change_password column."""
    op.drop_column('siem_users', 'must_change_password')