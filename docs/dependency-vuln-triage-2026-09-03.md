# Dependency Vulnerability Triage — 2026-09-03

> **STATUS (2026-09-03, same day):** fast-wins EXECUTED and verified —
> pip-audit re-run: **109 → 9 findings**. Remaining: 7× starlette (needs
> Project A, the fastapi upgrade — incl. the KEV) + the 2 P4 risk-accepts
> (ecdsa Minerva, diskcache pickle — no upstream fix). Full suite 1644/0
> with the live demo stack; api + dashboard containers rebuilt and healthy
> on the new lockfile (boot gate + page checks green). Commits:
> 90c48e5 sqlparse · 2b384d2 aiosmtplib · 112c6b6 tornado+protobuf ·
> 091bf69 idna/pygments/cryptography/pydantic-settings · 0672104 insurance
> batch.

Reachability-first triage of the pip-audit findings against the locked
dependency set, per the vuln-triage methodology (normalize → enrich →
reachability → prioritize → remediate). Purpose: a defensible fix queue
before the dependency-audit enforcing flip (~2026-09-16, two-week window
from P3.5).

**Scanner input:** pip-audit against the poetry env (CI job
`dependency-audit`, run 33820903565): 126 raw findings → **109 unique**
after BIT-*/GHSA dedupe → 19 packages. Every finding enriched from
OSV.dev (summary + CVSS v3) + CISA KEV check (feed 2026-09-03).

**Scope note (read before panicking):** pip-audit runs against the DEV
environment. The runtime image is `poetry install --without dev` —
pytest-class findings are dev-only and never ship. Trivy scans the actual
runtime image; its results are the authoritative runtime view.

## Reachability map (the big filter)

| Package | Installed | Why it's there | Reachable? |
|---|---|---|---|
| starlette | 0.46.2 | fastapi (API framework) | **YES — every HTTP request** |
| sqlparse | 0.5.5 | direct (NL→SQL) | **YES — parses LLM output** |
| tornado | 6.5.5 | streamlit (dashboard server, :8501) | **YES — host-exposed** |
| protobuf | 3.20.3 | streamlit (browser protocol) | **YES — dashboard websocket** |
| idna | 3.11 | httpx URL parsing | yes — TI outbound lookups |
| pygments | 2.19.2 | streamlit markdown highlighting | narrow — analyst code fences |
| cryptography | 46.0.5 | python-jose, redis | import-time only (HS256 = hmac; redis TLS off) |
| pydantic-settings | 2.13.1 | direct (settings) | yes (boot, env parsing) — vuln path (secrets_dir) unused |
| aiohttp | 3.13.3 | geoip2 (web-service client) | **NO — app uses geoip2 local mmdb reader** |
| requests | 2.32.5 | geoip2 web-service, pysigma | no — app HTTP is httpx |
| urllib3 | 2.6.3 | under requests | no |
| gitpython | 3.1.46 | streamlit internals | no — no app-controlled git options |
| pillow | 12.1.1 | streamlit (image handling) | no — dashboard renders no images (verified: no st.image/st.media) |
| ecdsa / pyasn1 | 0.19.1 / 0.6.3 | python-jose ECDSA/RSA | no — JWT_ALGORITHM = HS256 (src/api/auth.py:35) |
| diskcache | 5.6.3 | pysigma | narrow — sigma eval path |
| aiosmtplib | 3.0.2 | direct (email alerting) | **feature not built** — no runtime import |
| click | 8.3.1 | CLI layer | no — boot-time operator args only |
| pytest | 9.0.2 | dev group | **not in runtime image** |

## CISA KEV

Exactly **one** finding is KEV-listed: **CVE-2026-48710 (starlette)** —
Host-header validation missing → `request.url.path` poisoned → path-based
security decisions bypassed. This API *makes* path-based decisions:

- `src/api/middleware.py:152` — ingest Content-Type enforcement keys on
  `request.url.path.endswith("/ingest")`
- `src/api/middleware.py:194` — audit logging skips `/health`, `/docs`,
  `/redoc` by path match

A poisoned path can (a) bypass ingest Content-Type enforcement and (b)
make an audited state-changing request look like a docs request → **audit
log entry skipped**. On a SIEM, skipping audit logs is the finding.

## Remediation queue

`Priority | Finding | Why (reachability + exploitability) | Action`

### P0 — now

| P | Finding | Why | Action |
|---|---|---|---|
| **P0** | **starlette CVE-2026-48710 (KEV) 0.46.2** | Front-door framework; Host-header path poisoning bypasses ingest Content-Type gate + audit skip-list; KEV-listed = actively exploited | **Upgrade fastapi 0.115.14 → 0.141.1 + starlette → 1.3.1 (project A below)**. Interim mitigation acceptable: middleware rejecting absolute-form request targets / unexpected Host before FastAPI routing. |
| P0 (fast win) | sqlparse 0.5.5 → 0.6.0 (5 findings) | Parses LLM output in NL→SQL (`src/ai/nl2sql.py:22`); ReDoS/quadratic-DoS reachable through prompt-injection-influenced chat input; direct dep | widen pin in pyproject.toml (`>=0.5.5,<0.6.0` → `>=0.6.0,<0.7`) + `poetry update sqlparse` — all 5 findings fixed in 0.6.0 |

### P1 — this week (reachable, trivial fixes)

| P | Finding | Why | Action |
|---|---|---|---|
| P1 | tornado 6.5.5 → 6.5.8 (7 findings) | Dashboard HTTP/websocket server, port 8501 host-published; body-parse event-loop stall + multipart memory amplification are browser-reachable | bump (streamlit allows >=6.0.3,<7 — free) |
| P1 | protobuf 3.20.3 → 5.29.6 (2 findings) | Streamlit browser protocol over websocket; recursion DoS reachable from the browser | bump (streamlit allows >=3.20,<7 — free; verify runtime) |
| P1 | idna 3.11 → 3.15 (1) | httpx URL parsing on TI lookups; DoS via crafted hostnames | bump (transitive — `poetry update idna`) |

### P2 — this sprint (reachable but narrow, or free insurance)

| P | Finding | Why | Action |
|---|---|---|---|
| P2 | cryptography 46.0.5 → 46.0.7 (2 of 6 findings) | JWT-adjacent; HS256 app doesn't hit the vulnerable paths but bump is trivial | `poetry update cryptography` (check python-jose pin) |
| P2 | pydantic-settings 2.13.1 → 2.14.2 (1) | Direct dep; vulnerable secrets_dir path unused (verified) — bump is free | bump |
| P2 | aiosmtplib 3.0.2 → 5.1.2 (2) | SMTP command injection + STARTTLS injection; **feature not built yet** (no runtime import) — but the dep is direct and the feature is planned; the constraint needs widening (>=3,<4) | widen constraint `>=5.1.2,<6` + bump, or drop dep until the feature ships (decision: bump + widen — the feature will need it) |
| P2 | pygments 2.19.2 → 2.20.0 (1) | ReDoS on GUID regexes; only reachable via analyst-authored ``` fences in st.markdown — authenticated-only | bump (free) |

### P3 — next patch cycle (unreachable in current code, cheap bumps)

| P | Finding | Why | Action |
|---|---|---|---|
| P3 | aiohttp 3.13.3 → 3.14.3 (24 findings) | ZERO runtime imports (verified) — geoip2 web-service path unused, app HTTP is httpx. Largest count, lowest reach | bump as insurance; do NOT let the count alarm you |
| P3 | gitpython 3.1.46 → 3.1.59 (24 findings) | RCE-class but requires app-controlled git options; nothing passes attacker input to git | bump (cheap, kill the tail risk) |
| P3 | pillow 12.1.1 → 12.3.0 (18 findings) | Image loaders unreachable — no image rendering/upload in app | bump if streamlit constraint allows |
| P3 | urllib3 2.6.3 → 2.7.0 (2) | Under requests — app HTTP is httpx | bump if free |
| P3 | requests 2.32.5 → 2.33.0 (1) | extract_zipped_paths unused | bump if free |
| P3 | ecdsa 0.19.1 → 0.19.2 (1 of 2) | DER DoS on crafted private keys — app never parses EC keys | bump; see P4 for the Minerva one |
| P3 | pyasn1 0.6.3 → 0.6.4 (3) | BER/DER decoders unused (HS256-only JWT) | bump |
| P3 | click 8.3.1 → 8.3.3 (1) | click.edit() never called | bump |
| P3 | pytest 9.0.2 → 9.0.3 (1) | dev-only, not in runtime image | bump; irrelevant to runtime |

### P4 — risk register (no fix available; acceptance WITH expiry)

| P | Finding | Why | Action |
|---|---|---|---|
| P4 | ecdsa CVE-2024-23342 (Minerva timing, P-256) | No upstream fix. Unreachable: app performs no ECDSA sign/verify (HS256-only JWT). | **Accept until 2026-12-01**; revisit if JWT algorithms ever change from HS256 |
| P4 | diskcache CVE-2025-69872 (unsafe pickle) | No upstream fix. pysigma's cache; pickle deserialization needs local file-write on the container | **Accept until 2026-12-01**; container isolation + read-only FS mitigates; revisit if pysigma usage changes |

## Projects (separate from fast-wins)

**Project A — fastapi/starlette upgrade: EXECUTED (2026-09-03).**
fastapi 0.115.14 → 0.141.1, starlette 0.46.2 → **1.6.0** (poetry resolved
beyond the 1.3.1 fix set — all 7 findings dead, incl. the KEV). fastapi
0.141.1 requires starlette >=0.46.0 with no ceiling. One test-compat
change: fastapi now wraps include_router() results in
fastapi.routing._IncludedRouter (prefix in .include_context, unprefixed
routes in .original_router.routes) — route-wiring tests now resolve
effective paths via tests/unit/_route_walker.py. Verified: full suite
1644/0, ruff+mypy clean, containers rebuilt + healthy, all 9 page
endpoints 200, ingest Content-Type enforcement + non-ingest passthrough
confirmed live. pip-audit residual: 2 (the P4 risk-accepts only).
Runtime-image CONFIRMED via trivy (run 33822815354, CI green): residual
should be the poetry-toolchain tail (Project C) only.

**Project B — first real trivy results (2026-09-03, run 33821877958):**
the image scan finally executed (two pinned-action bugs fixed). First
scan of the pre-bump image (debian 13.6: **0** OS HIGH/CRITICAL):
~14 distinct Python-package HIGH/CRITICALs — every one already fixed by
the fast-wins series above EXCEPT **jaraco.context 5.3.0
CVE-2026-23949** (path traversal, fix 6.1.0), which is NOT in
poetry.lock at all — it ships because **Poetry itself is installed in
the runtime image** (build tooling never evicted) and drags its own
transitive deps (cleo, build, cachecontrol, …) into site-packages. See
Project C. (2026-09-04 CORRECTION from the Project C execution: the
vulnerable 5.3.0 copy was setuptools' `_vendor/` pin from the BASE
image, not poetry's tail — poetry's own jaraco.context was 6.1.2, a
fixed version. Both were fixed by Project C's two-part change.) The post-bump image (run 33822072579) is expected to clear
everything except jaraco.context + starlette.

**Project C — evict the Poetry toolchain from the runtime image
(multi-stage build): EXECUTED (2026-09-04).** Two-part fix on branch
`feat/multistage-poetry-eviction`:

1. **Multi-stage Dockerfile** — builder stage installs poetry (pin kept:
   `>=2.3,<3.0`) + runs `poetry install --without dev --no-root` into an
   in-project virtualenv `/app/.venv` (poetry seeds it with pip only; the
   pip is stripped post-install); runtime stage copies ONLY the venv + app
   tree. Poetry's tail (cleo, build, cachecontrol, virtualenv, dulwich,
   keyring…) never enters the runtime image. Bonus found during the work:
   the old layout paid a hidden ~620MB layer tax (`RUN chown -R` re-commits
   every file — no overlay metacopy on this builder); ownership now set via
   `COPY --chown` → image **1.83GB → 1.11GB** (−40%).
2. **Root-cause correction to this doc's Project B claim:** the two HIGH
   findings did NOT come from poetry's tail — poetry's own copies were
   already fixed (jaraco.context 6.1.2, wheel 0.46.3, 0 findings). The
   vulnerable copies were the **`_vendor/` pins inside the setuptools that
   ships in the python:3.11-slim BASE** (jaraco.context 5.3.0,
   wheel 0.45.1). Evicting poetry alone therefore could NOT clear the
   scan. Fix: final stage upgrades `setuptools>=84` (vendors jaraco.context
   6.1.0 + wheel 0.46.3, both fixed).

Verified 2026-09-04: poetry check --lock + ruff(src/dashboard/scripts/tests)
+ mypy clean · full suite 1644/0 · both images rebuilt (legacy builder,
no cache mounts) · boot gate green (api/dashboard healthy, /api/v1/health
all-ok incl. ollama) · all 9 page endpoints 200 (35 alerts 12c/12h/9m/2l,
20 logs all-time, 3 cases, 15 TI, 100 rules, suppressions 200 `[]`) ·
site-packages inspection: poetry/cleo/jaraco.context/virtualenv/cachecontrol/
build ABSENT from both trees, dev group absent, fastapi 0.141.1 +
starlette 1.6.0 confirmed · local trivy (HIGH,CRIT, ignore-unfixed):
exit 0, ZERO findings. Note: DEMO.md's "20 rows" expectation for the 24h
log window was stale — the seed spreads logs uniformly over 48h
(`randint(1, 2880)`), so ~10-11 in-window is the correct healthy shape
(DEMO.md corrected same day).

**Enforcing flip (~2026-09-16):** dependency-audit `continue-on-error`
drops to blocking. The fast-wins above (P0-P2) clear the reachable set;
P3 bumps clear the rest. After those land, the flip should be a
formality — re-run pip-audit locally before the flip to confirm.

## Method notes

- Dedupe: BIT-*/GHSA aliases of a CVE counted once (126 raw → 109 unique).
- Reachability verified by code inspection, not assumed: direct-import
  grep (`import <mod>` across `src/ dashboard/ scripts/`), reverse-dep map
  from installed metadata, feature checks (geoip2 local-reader vs
  web-service, JWT algorithm, secrets_dir, dashboard media elements).
- Enrichment: OSV.dev API (severity + summary), CISA KEV feed
  (2026-09-03): 1/109 KEV-listed.
- "Free bump" = target version within the existing parent constraint;
  `poetry update <pkg>` without touching pyproject.toml.