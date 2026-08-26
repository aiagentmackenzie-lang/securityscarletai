-- scripts/harden_audit.sql
-- Audit append-only hardening (P1-C).
--
-- Run by a SUPERUSER (NOT the app role), typically via DATABASE_SUPERUSER_URL
-- in scripts/entrypoint.sh, or manually:
--   psql "$DATABASE_SUPERUSER_URL" -v app_role=scarletai -f scripts/harden_audit.sql
--
-- What this does:
--   Revokes UPDATE, DELETE, TRUNCATE on the audit tables from the app role
--   (and from PUBLIC), so a compromised app cannot rewrite or delete its own
--   audit trail. The app keeps INSERT + SELECT so the audit middleware can
--   write and analysts can read.
--
-- IMPORTANT — why the default deploy does NOT enforce this:
--   In the default single-role deploy, the app role (DB_USER) is also the
--   table OWNER (it applies schema.sql). Owners bypass GRANT/REVOKE on their
--   own tables, so REVOKE from the owner is a no-op. To actually enforce
--   append-only audit you need a two-role setup:
--     1. A superuser/owner role applies schema.sql + this script.
--     2. The app runs as a DIFFERENT, non-owner role that only has the
--        privileges granted here.
--   See docs/DEPLOYMENT.md → "Audit immutability" for the full setup.
--   Without it, the audit tables are append-only BY CONVENTION (the app only
--   INSERTs/SELECTs them) — not enforced by the database.
--
-- Verify after running:
--   python -m scripts.check_audit_grants --strict
--   (exits non-zero if the app role can still UPDATE/DELETE/TRUNCATE audit_logs)

-- The app role name is passed with `psql -v app_role=scarletai`.
-- :app_role is substituted by psql; the default matches the compose DB_USER.
\set app_role :app_role
\if :{?app_role}
\else
  \echo 'WARNING: app_role variable not set — defaulting to scarletai. Pass with -v app_role=<role>.'
  \set app_role scarletai
\endif

-- REVOKE from PUBLIC first (defense in depth — no role inherits mutate rights).
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log  FROM PUBLIC;

-- REVOKE from the app role. If the app role is the owner this is a no-op
-- (owners bypass their own GRANTs) — see the note above. The check script
-- reports the real state.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM :"app_role";
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log  FROM :"app_role";

-- Ensure the app role keeps INSERT + SELECT so the audit middleware can write
-- and analysts can read.
GRANT INSERT, SELECT ON audit_logs TO :"app_role";
GRANT INSERT, SELECT ON audit_log  TO :"app_role";

\echo 'harden_audit.sql applied: REVOKE UPDATE/DELETE/TRUNCATE, GRANT INSERT/SELECT on audit_logs + audit_log.'
\echo 'Verify with: python -m scripts.check_audit_grants --strict'