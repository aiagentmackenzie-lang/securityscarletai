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


def evaluate_audit_posture(
    report: dict[str, dict],
    app_role: str,
    tables: Iterable[str] = AUDIT_TABLES,
) -> tuple[bool, list[str]]:
    """Evaluate the EFFECTIVE grant report (SS-036).

    ``report`` maps table -> {
        "privileges": set[str] | None,   # has_table_privilege results
        "table_owner": str | None,
        "member_of": list[str],          # role memberships (pg_auth_members)
    }

    Fails closed on:
      * a mutate privilege (UPDATE/DELETE/TRUNCATE) — INCLUDING one inherited
        through role membership (the old `grantee = app_role` query could not
        see those, so it certified append-only while an UPDATE succeeded);
      * ownership by the app role (an owner bypasses REVOKE, so append-only is
        convention only);
      * a missing audit table (nothing to verify is not a pass).
    """
    problems: list[str] = []
    for table in tables:
        entry = report.get(table) or {}
        privileges = entry.get("privileges")
        owner = entry.get("table_owner")
        member_of = entry.get("member_of") or []

        if privileges is None:
            problems.append(
                f"{table}: table missing or not inspectable — cannot verify append-only"
            )
            continue

        if owner and str(owner).lower() == app_role.lower():
            problems.append(
                f"{table}: app role '{app_role}' OWNS the table — owners bypass REVOKE, "
                "append-only is not DB-enforced (two-role deploy required)"
            )

        mutate = set(privileges) & MUTATE_PRIVILEGES
        if mutate:
            inherited = f" (role memberships: {', '.join(member_of)})" if member_of else ""
            problems.append(
                f"{table}: app role has {sorted(mutate)} — append-only NOT enforced{inherited}"
            )
    return (len(problems) == 0, problems)


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
            problems.append(f"{table}: app role has {sorted(mutate)} — append-only NOT enforced")
    return (len(problems) == 0, problems)


async def fetch_audit_grant_report(database_url: str, app_role: str) -> dict[str, dict]:
    """Effective-grant report for the app role on the audit tables (SS-036).

    `has_table_privilege` is the truth source: it accounts for role
    INHERITANCE and for ownership, which `information_schema.table_privileges
    WHERE grantee = $role` does not. `pg_auth_members` supplies the membership
    context so the failure message names the role that leaked the privilege.
    """
    import asyncpg

    conn = await asyncpg.connect(database_url)
    try:
        rows = await conn.fetch(
            """
            SELECT t AS table_name,
                   c.oid AS table_oid,
                   pg_get_userbyid(c.relowner) AS table_owner,
                   ARRAY(
                       SELECT p
                       FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p
                       WHERE c.oid IS NOT NULL AND has_table_privilege($2, c.oid, p)
                   ) AS privileges,
                   ARRAY(
                       SELECT r.rolname
                       FROM pg_auth_members m
                       JOIN pg_roles r ON r.oid = m.roleid
                       JOIN pg_roles u ON u.oid = m.member
                       WHERE u.rolname = $2
                   ) AS member_of
            FROM unnest($1::text[]) AS t
            LEFT JOIN pg_class c
                   ON c.relname = t
                  AND c.relnamespace = 'public'::regnamespace
                  AND c.relkind IN ('r', 'p')
            """,
            list(AUDIT_TABLES),
            app_role,
        )
    finally:
        await conn.close()

    report: dict[str, dict] = {}
    for r in rows:
        report[r["table_name"]] = {
            "privileges": None if r["table_oid"] is None else set(r["privileges"] or []),
            "table_owner": r["table_owner"],
            "member_of": list(r["member_of"] or []),
        }
    for t in AUDIT_TABLES:
        report.setdefault(t, {"privileges": None, "table_owner": None, "member_of": []})
    return report


async def fetch_app_role_grants(database_url: str, app_role: str) -> dict[str, set[str]]:
    """Effective privileges per audit table: {table: {privileges}}.

    Kept as the simple shape (SS-036): privileges now come from
    `has_table_privilege`, so an INHERITED UPDATE/DELETE/TRUNCATE is visible —
    the old `grantee = $2` query on information_schema.table_privileges saw
    direct grants only.
    """
    report = await fetch_audit_grant_report(database_url, app_role)
    return {table: set(entry["privileges"] or ()) for table, entry in report.items()}


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
        report = asyncio.run(fetch_audit_grant_report(url, args.app_role))
    except Exception as e:
        print(f"Could not determine audit grant state: {e}", file=sys.stderr)
        return 2

    enforced, problems = evaluate_audit_posture(report, app_role=args.app_role)
    for table in AUDIT_TABLES:
        entry = report.get(table, {})
        privs = sorted(entry.get("privileges") or ()) or ["(none)"]
        owner = entry.get("table_owner") or "?"
        members = ", ".join(entry.get("member_of") or []) or "-"
        print(
            f"  {table}: effective privileges = {privs} · owner = {owner} · member of = {members}"
        )
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
