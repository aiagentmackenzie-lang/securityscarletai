#!/usr/bin/env python3
"""
Password Migration: SHA-256 Pre-Hash (M-10 Fix)

After the M-10 security fix, hash_password() now SHA-256 pre-hashes passwords
before bcrypt. Old hashes in the database (bcrypt of raw password) will NOT
verify with the new code. This script:

1. Adds `must_change_password` column to siem_users
2. Flags all existing users for password reset on next login
3. Logs the migration in audit_log

IMPORTANT: Old password hashes are NOT migrated (we don't have plaintext).
Users must set a new password on next login. This is the safest approach.

Usage:
    # Dry run (preview changes, no DB writes)
    python scripts/migrate_passwords.py --dry-run

    # Live migration
    python scripts/migrate_passwords.py

    # With custom DB URL
    DATABASE_URL=postgres://user:pass@host:5432/db python scripts/migrate_passwords.py

Requires: asyncpg, dotenv
"""

import argparse
import asyncio
import hashlib
import os
import sys
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


async def get_pool():
    """Get database pool from DATABASE_URL."""
    try:
        import asyncpg
    except ImportError:
        print("ERROR: asyncpg not installed. Run: pip install asyncpg")
        sys.exit(1)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        # Try loading from .env
        try:
            from dotenv import load_dotenv
            load_dotenv()
            database_url = os.environ.get("DATABASE_URL")
        except ImportError:
            pass

    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set.")
        print("Set it or create a .env file with DATABASE_URL=postgres://...")
        sys.exit(1)

    return await asyncpg.create_pool(database_url, min_size=1, max_size=3)


async def check_column_exists(pool, column_name: str) -> bool:
    """Check if a column exists in siem_users."""
    async with pool.acquire() as conn:
        result = await conn.fetchval("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'siem_users' AND column_name = $1
        """, column_name)
        return result > 0


async def count_users(pool) -> int:
    """Count total users in siem_users."""
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT COUNT(*) FROM siem_users")


async def get_users(pool) -> list:
    """Get all users with their password hashes."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, password_hash, role, is_active FROM siem_users"
        )
        return [dict(r) for r in rows]


def is_new_hash_format(password_hash: str) -> bool:
    """Detect if a hash was created with SHA-256 pre-hash (new format).

    We can't definitively tell from the hash alone, but we CAN test:
    If bcrypt.checkpw(sha256("default_password"), hash) matches, it's new format.
    Since we don't know the original password, we use a heuristic:
    New hashes are bcrypt of a 64-char hex string (SHA-256 digest).
    Old hashes are bcrypt of the raw password (variable length).

    Since both produce valid bcrypt output, we can't distinguish them
    programmatically. The safest approach: treat ALL existing hashes as old
    and require password reset.
    """
    # All existing hashes are treated as old format — flag for reset
    return False


async def run_migration(dry_run: bool = False):
    """Execute the password migration."""
    print("=" * 60)
    print("SecurityScarletAI — Password Migration (M-10 SHA-256 Pre-Hash)")
    print("=" * 60)
    print()

    pool = await get_pool()
    try:
        # Step 1: Check current state
        total_users = await count_users(pool)
        print(f"📊 Found {total_users} users in siem_users")

        if total_users == 0:
            print("✅ No users to migrate. Done.")
            return

        users = await get_users(pool)
        for u in users:
            status = "🟢 active" if u["is_active"] else "🔴 disabled"
            print(f"   • {u['username']} ({u['role']}) — {status}")

        print()

        # Step 2: Check if migration already ran
        column_exists = await check_column_exists(pool, "must_change_password")
        if column_exists:
            print("⚠️  Column `must_change_password` already exists.")
            # Check how many still need to reset
            async with pool.acquire() as conn:
                pending = await conn.fetchval(
                    "SELECT COUNT(*) FROM siem_users WHERE must_change_password = true"
                )
            print(f"   {pending} users still need to change their password.")
            if pending == 0:
                print("✅ Migration already complete. No action needed.")
                return
            print("   Continuing to flag remaining users...")
        else:
            if dry_run:
                print("🔧 [DRY RUN] Would add column: must_change_password BOOLEAN DEFAULT false")
            else:
                print("🔧 Adding column: must_change_password BOOLEAN DEFAULT false")
                async with pool.acquire() as conn:
                    await conn.execute("""
                        ALTER TABLE siem_users
                        ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false
                    """)
                print("✅ Column added.")

        print()

        # Step 3: Flag all existing users for password reset
        # Their current hashes are bcrypt(raw_password) which won't work with
        # the new verify_password() that does bcrypt(sha256(raw_password)).
        if dry_run:
            print(f"🔧 [DRY RUN] Would flag {total_users} users for password reset")
            print("   UPDATE siem_users SET must_change_password = true")
        else:
            async with pool.acquire() as conn:
                affected = await conn.execute(
                    "UPDATE siem_users SET must_change_password = true"
                )
            count = int(affected.split()[-1])
            print(f"✅ Flagged {count} users for password reset on next login.")

        print()

        # Step 4: Log migration in audit_log
        if dry_run:
            print("🔧 [DRY RUN] Would log migration in audit_log")
        else:
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO audit_log (actor, action, target_type, new_values)
                    VALUES ($1, $2, $3, $4)
                """,
                "system",
                "user.password_migration",
                "user",
                '{"description": "M-10 SHA-256 pre-hash migration: all users flagged for password reset", "users_affected": ' + str(total_users) + '}',
            )
            print("📝 Migration logged in audit_log.")

        print()
        print("=" * 60)
        if dry_run:
            print("🔍 DRY RUN COMPLETE — no changes written to database")
        else:
            print("✅ MIGRATION COMPLETE")
        print()
        print("What happens next:")
        print("  1. When existing users log in, must_change_password=true")
        print("  2. The API should enforce password change before granting access")
        print("  3. After changing password, the new hash uses SHA-256 pre-hash")
        print("  4. must_change_password is set back to false")
        print()
        print("Admin can manually reset a user's flag:")
        print("  UPDATE siem_users SET must_change_password = false")
        print("  WHERE username = 'specific_user';")
        print("=" * 60)

    finally:
        await pool.close()


def main():
    parser = argparse.ArgumentParser(
        description="Migrate passwords for M-10 SHA-256 pre-hash fix"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without writing to database",
    )
    args = parser.parse_args()

    asyncio.run(run_migration(dry_run=args.dry_run))


if __name__ == "__main__":
    main()