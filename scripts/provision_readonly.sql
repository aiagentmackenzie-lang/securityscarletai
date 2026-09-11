-- scripts/provision_readonly.sql
-- Scoped read-only DB role for the SIEM MCP server (V0.4/5 item 2).
--
-- Run by a SUPERUSER/OWNER (like harden_audit.sql), typically via the
-- entrypoint when DATABASE_SUPERUSER_URL + DB_READONLY_PASSWORD are set.
-- Idempotent: re-apply rotates the password and re-asserts the grants.
--
-- What the role can do:
--   SELECT on SIEM DATA tables (logs, alerts, rules, correlation_matches,
--     cases, case_events, response_actions)  -- the tool surface reads these
--   SELECT/INSERT/UPDATE on agent_investigations             -- its own run
--     records (lifecycle: running -> completed/failed + HITL state); the
--     audit chain records every transition
--   INSERT/SELECT on audit_log + audit_logs                  -- append-only
--     audit chain (same two-role posture as the app role)
--   INSERT/SELECT on ai_usage                                -- the AI-usage
--     ledger (cost tracking for MCP-driven LLM calls)
--   Future tables: SELECT via ALTER DEFAULT PRIVILEGES (owner = scarletai,
--     matching the standing volume's owner)
--
-- What it can NEVER do:
--   UPDATE/DELETE/INSERT/TRUNCATE on SIEM DATA (the MCP tools are read-only
--     by construction; the DB enforces it -- defense in depth below the
--     code-level allowlists)
--   CREATE on schema public (least privilege)
--
-- Verify after applying (run as any role):
--   SELECT table_name, privilege_type FROM information_schema.role_table_grants
--     WHERE grantee = 'scarletai_readonly' ORDER BY table_name;
-- The MCP server re-verifies the scope at boot and refuses tools on drift.
--
-- Caller contract (scripts/entrypoint.sh): psql variables :role and
-- :password are set via \set lines piped in through STDIN ahead of this
-- file -- the password never appears in any command line or log. Never
-- pass it with psql -v.

-- Create the role if absent (idempotent); rotate the password on re-apply.
SELECT 1 FROM pg_roles WHERE rolname = :'role' \gset
\if :{?found}
\else
CREATE ROLE :"role" LOGIN;
\endif
ALTER ROLE :"role" LOGIN PASSWORD :'password';

-- Least privilege: no schema ownership/creation.
REVOKE CREATE ON SCHEMA public FROM :"role";
GRANT USAGE ON SCHEMA public TO :"role";

-- SIEM DATA: strictly read-only for the tool surface.
GRANT SELECT ON logs, alerts, rules, correlation_matches,
    cases, case_events, response_actions TO :"role";

-- The MCP server's own evidence records (run lifecycle + audit chain +
-- AI-usage ledger). No DELETE/TRUNCATE anywhere.
GRANT SELECT, INSERT, UPDATE ON agent_investigations TO :"role";
GRANT INSERT, SELECT ON audit_log, audit_logs TO :"role";
GRANT INSERT, SELECT ON ai_usage TO :"role";
GRANT USAGE, SELECT ON
    agent_investigations_id_seq, audit_log_id_seq, audit_logs_id_seq, ai_usage_id_seq
    TO :"role";

-- Future tables created by the owner are automatically readable. No FOR
-- ROLE clause: the role executing this script IS the owner in the two-role
-- posture, so the default privileges attach to it (matches the standing
-- volume's existing pg_default_acl).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO :"role";

\echo 'provision_readonly.sql applied: scoped read-only role ready.'