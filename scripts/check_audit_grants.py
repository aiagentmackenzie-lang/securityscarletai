"""Check the audit tables' grant state (P1-C).

Reports whether the audit tables (audit_logs, audit_log) are append-only
enforced at the database level — i.e. whether the app role lacks
UPDATE/DELETE/TRUNCATE on them. By default the single-role deploy does NOT
enforce this (the app role is the table owner and owners bypass REVOKE);
this script tells you the truth and, with --strict, fails CI/deploy gates
when immutability is not enforced.

Usage:
    python -m scripts.check_audit_grants            # informational
    python -m scripts.check_audit_grants --strict   # exit 1 if not enforced
    python -m scripts.check_audit_grants --app-role scarletai

Exit codes:
    0  -- all checked tables are append-only (or informational mode)
    1  -- --strict and at least one audit table is mutable by the app role
    2  -- could not determine the grant state (DB unreachable / table missing)
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Iterable

# Privileges that let a role mutate or remove audit rows — i.e. break
# append-only. SELECT/INSERT are allowed (the audit middleware writes; analysts
# read). REFERENCES/TRIGGER etc. are not mutate-row privileges.
MUTATE_PRIVILEGES = frozenset({"UPDATE", "DELETE", "TRUNCATE"})

AUDIT_TABLES = ("audit_logs", "audit_log")


def evaluate_append_only(
    grants: dict[str, set[str]],
    tables: Iterable[str] = AUDIT_TABLES,
) -> tuple[bool, list[str]]:
    """Pure logic — unit-testable without a DB.

    Given a {table: {privileges}} map for the app role, returns
    (all_append_only, problems) where problems is a list of human-readable
    strings for each table that is mutable.
    """
    problems: list[str] = []
    for table in tables:
        privs = grants.get(table, set())
        mutate = privs & MUTATE_PRIVILEGES
        if mutate:
            problems.append(
                f"{table}: app role has {sorted(mutate)} — append-only NOT enforced"
            )
    return (len(problems) == 0, problems)


async def fetch_app_role_grants(database_url: str, app_role: str) -> dict[str, set[str]]:
    """Query information_schema.table_privileges for the app role's privileges
    on the audit tables. Returns {table: {privileges}}."""
    import asyncpg

    conn = await asyncpg.connect(database_url)
    try:
        rows = await conn.fetch(
            """
            SELECT table_name, privilege_type
            FROM information_schema.table_privileges
            WHERE table_schema = 'public'
              AND table_name = ANY($1::text[])
              AND grantee = $2
            """,
            list(AUDIT_TABLES),
            app_role,
        )
    finally:
        await conn.close()

    grants: dict[str, set[str]] = {t: set() for t in AUDIT_TABLES}
    for r in rows:
        grants.setdefault(r["table_name"], set()).add(r["privilege_type"].upper())
    return grants


def _database_url() -> str:
    url = os.environ.get("DATABASE_SUPERUSER_URL") or os.environ.get("DATABASE_URL")
    if not url:
        # Fall back to building from the app settings (the app role's DSN).
        from src.config.settings import settings

        url = settings.database_url.replace("+asyncpg", "")
    return url


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--app-role",
        default=os.environ.get("DB_USER", "scarletai"),
        help="The app role to check (default: $DB_USER or 'scarletai').",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any audit table is mutable by the app role.",
    )
    args = parser.parse_args()

    url = _database_url()
    try:
        grants = asyncio.run(fetch_app_role_grants(url, args.app_role))
    except Exception as e:
        print(f"Could not determine audit grant state: {e}", file=sys.stderr)
        return 2

    enforced, problems = evaluate_append_only(grants)
    for table in AUDIT_TABLES:
        privs = sorted(grants.get(table, set())) or ["(none)"]
        print(f"  {table}: app role privileges = {privs}")
    if enforced:
        print("Audit tables are append-only (app role lacks UPDATE/DELETE/TRUNCATE).")
        return 0
    for p in problems:
        print(f"  ⚠️  {p}")
    print(
        "Audit tables are NOT append-only at the DB level. This is expected in the "
        "default single-role deploy (the app role owns the tables). To enforce, "
        "run scripts/harden_audit.sql as a superuser with a separate app role — "
        "see docs/DEPLOYMENT.md → Audit immutability."
    )
    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
