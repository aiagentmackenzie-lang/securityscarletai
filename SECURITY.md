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
- Fail-closed: the API refuses to start if `DB_PASSWORD`, `API_SECRET_KEY`, or
  `API_BEARER_TOKEN` is a `CHANGE_ME` placeholder — all three required secrets
  are placeholder-gated at startup.
- Scoped ingest token (P2.6): an optional `INGEST_BEARER_TOKEN` is
  viewer-class and honored ONLY on the ingest router — a leaked ingest token
  cannot read alerts, cases, or query results. The admin bearer's blast radius
  is unchanged; agents that only ship events should hold the scoped token.

These do **not** make a deployment invulnerable. Review `docs/DEPLOYMENT.md`
for the production hardening checklist before exposing the API to a network.

## Release verification (supply chain)

Every tagged release produced by `.github/workflows/release.yml` (trigger:
a `v*` tag push) ships with receipts a buyer can verify independently:

- **Image** on GHCR — `ghcr.io/aiagentmackenzie-lang/securityscarletai:<tag>`
  (the release notes carry its `sha256:` digest). Before anything is
  attested, the PUBLISHED digest is boot-gated: the real entrypoint runs
  against a live Postgres and must reach a healthy `/health` with the schema
  applied. The bytes that ship are the bytes that were booted.
- **CycloneDX SBOM** (Syft), generated FROM the published digest:
  `sbom.cdx.json` as a release asset, signed into the registry as a cosign
  attestation, and signed into GitHub's attestation store.
- **Build provenance** (SLSA v1.0 predicate via GitHub artifact
  attestations, GitHub-hosted runner) — in GitHub's attestation store and
  pushed to the registry.
- **Keyless Sigstore signatures** — no long-lived signing keys exist to
  rotate or steal; signatures are anchored in the public Rekor
  transparency log. The in-pipeline verify gate runs the same commands a
  buyer runs, so a release that cannot prove itself does not ship.

### Verify a release (buyer commands)

```bash
DIGEST=sha256:...   # from the release notes
ID_REG='^https://github\.com/aiagentmackenzie-lang/securityscarletai/\.github/workflows/release\.yml@refs/tags/.*$'
ISSUER='https://token.actions.githubusercontent.com'
SUBJECT="ghcr.io/aiagentmackenzie-lang/securityscarletai@${DIGEST}"

# 1. Image signature (cosign, keyless)
cosign verify "$SUBJECT" \
  --certificate-identity-regexp "$ID_REG" \
  --certificate-oidc-issuer "$ISSUER"

# 2. SBOM attestation in the registry (cosign)
cosign verify-attestation --type cyclonedx "$SUBJECT" \
  --certificate-identity-regexp "$ID_REG" \
  --certificate-oidc-issuer "$ISSUER"

# 3. Provenance (SLSA v1.0) in GitHub's attestation store
gh attestation verify "oci://${SUBJECT}" \
  -R aiagentmackenzie-lang/securityscarletai \
  --predicate-type https://slsa.dev/provenance/v1

# 4. SBOM attestation (CycloneDX) in GitHub's attestation store
gh attestation verify "oci://${SUBJECT}" \
  -R aiagentmackenzie-lang/securityscarletai \
  --predicate-type https://cyclonedx.org/bom
```

Check exit codes, not grepped output — silence is not success.

### Honest status of these claims

- ✅ CI-verified: the release workflow executes all four verification
  commands against its own receipts before publishing.
- ⚠️ **First tagged release pending**: receipts exist only for releases
  produced AFTER this workflow landed; versions before it carry none.
- ❌ **NOT claimed: certified SLSA Build Level 3.** GitHub documents its
  artifact-attestation provenance at SLSA v1 Build Level 2 (GitHub-hosted
  runner, non-isolated builder). The retired `slsa-framework` generator
  would have provided L3 but is maintenance-frozen as of 2026 and is no
  longer recommended for new integrations. Named trigger to revisit: an
  RFP that requires certified L3.
- One-time step after the first release: confirm the GHCR package
  visibility is public so buyers can pull and verify anonymously.

## Supported versions

Only the latest minor release receives security fixes.