# Security Policy

SecurityScarletAI is a defensive SIEM. This policy covers reporting
vulnerabilities in SecurityScarletAI itself — not the threats it detects.

## Reporting a vulnerability

If you find a security issue in SecurityScarletAI (e.g., an auth bypass, SQL
injection in the NL→SQL path, a way to tamper with the audit log, or a
secret-leak in the container image), please report it responsibly:

- **Do not** open a public GitHub issue for security reports.
- Email: **aiagent.mackenzie@gmail.com** with `[SecurityScarletAI security]`
  in the subject.
- Include a clear description, reproduction steps, and your assessment of
  impact.
- Please allow a reasonable window (default 90 days) before public disclosure.

## Scope

In-scope:

- The FastAPI API and its middleware (auth, rate limiting, request validation,
  audit logging).
- The NL→SQL translation path and its injection defenses.
- The ingestion shipper and parser (osquery result-log handling).
- The detection/correlation engine and Sigma rule loading.
- The Docker image, `entrypoint.sh`, and `docker-compose.yml` configuration.
- Secret handling (`.env`, JWT signing keys, bearer tokens, DB credentials).

Out of scope:

- Issues fixed by upgrading supported dependency versions.
- Vulnerabilities in Ollama, Postgres, Redis, or other third-party services the
  project integrates with — report those to their upstream maintainers.

## Hardening notes (already in place)

- JWT auth with Redis-backed token revocation; bearer-token ingestion auth
  compared with `secrets.compare_digest` (constant-time).
- Rate limiting via slowapi (Redis storage in prod; in-memory fallback).
- Audit log is append-only and written outside the agent's write path.
- Bounded request bodies; input validation on every ingest event.
- Fail-closed: the API refuses to start if `DB_PASSWORD` is the placeholder.

These do **not** make a deployment invulnerable. Review `docs/DEPLOYMENT.md`
for the production hardening checklist before exposing the API to a network.

## Supported versions

Only the latest minor release receives security fixes.