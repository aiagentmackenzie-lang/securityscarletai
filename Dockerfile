# Multi-stage, multi-target build.
#
# HISTORY (Project C, 2026-09-04): the Poetry toolchain and its dependency
# tail (cleo, build, cachecontrol, virtualenv, dulwich, keyring, …) used to be
# installed straight into the runtime image, dragging ~20 build-only packages
# into site-packages. Stage 1 (builder) installs poetry + the locked runtime
# dependency set into an in-project virtualenv (/app/.venv); the runtime stages
# copy ONLY that venv + the application tree. Poetry itself never enters the
# runtime image.
#
# Trivy evidence (2026-09-04): the two HIGH findings in the old image
# (jaraco.context 5.3.0 CVE-2026-23949, wheel 0.45.1 CVE-2026-24049) came from
# the _vendor/ copies inside the setuptools that SHIPS IN THE python:3.11-slim
# BASE — not from poetry's tail (whose own jaraco.context 6.1.2 / wheel 0.46.3
# were fixed versions with 0 findings). Evicting poetry alone therefore does
# NOT clear the scan: the final stages upgrade setuptools (>=84 vendors
# jaraco.context 6.1.0 + wheel 0.46.3, both fixed) as base hygiene.
#
# Size note (2026-09-04): the previous single-stage layout paid a hidden
# ~620MB layer tax — `RUN chown -R appuser:appgroup /app` re-committed every
# file it touched (no overlay metacopy on this builder). Ownership is now set
# at COPY time via --chown, so no chown layer exists.
#
# MULTI-TARGET (AUD-014, 2026-09-18): the single shared image carried the full
# Streamlit stack (streamlit/altair/autorefresh/pandas + 20 exclusive
# transitives — pyarrow, tornado, gitpython, pillow, protobuf, …) for api and
# mcp, which never import any of it. Dependency groups (pyproject
# [dependency-groups].dashboard) + two builder variants now split the venv:
#   builder           → main deps only           → feeds the `api` runtime
#   builder-dashboard → main + dashboard groups  → feeds the `dashboard` runtime
# The api/mcp image drops the whole Streamlit stack — MEASURED (colima/aarch64,
# cold builds, 2026-09-18): 1.17GB→800MB disk / 249MB→166MB compressed content
# (−33%) for api/mcp; the dashboard target stays at parity (1.17GB/249MB, the
# same 99-distribution venv). Full numbers in docs/internal/CODEBASE_AUDIT.md
# Fix Wave 11.
# numpy/scikit-learn/joblib STAY in main deps for both: the API entrypoint
# trains AlertTriageModel + UEBABaseline at boot (entrypoint steps 4-5).
# `api` is the DEFAULT target (last stage): bare `docker build .` — and every
# workflow step that builds without an explicit --target — produces the api
# image, the primary shipped artifact (release.yml pushes it to ghcr).
# The dashboard image is built explicitly (compose `target:`, ci.yml).

FROM python:3.11-slim AS builder

# Install Poetry (C4: pinned >=2.3 to match the poetry.lock generator
# (2.3.2, lock-version 2.1) — poetry 2.1+ reads the PEP-735 [dependency-groups]
# table; 2.0.x does NOT and fails with 'Group(s) not found: dev').
# Poetry lives ONLY in this stage; it is never copied forward.
RUN pip install --no-cache-dir "poetry>=2.3,<3.0"

# In-project virtualenv = a copyable artifact at a stable path (/app/.venv).
# Poetry seeds its venv with pip ONLY (no setuptools/wheel); that pip is
# stripped after install — the runtime never invokes pip.
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

WORKDIR /app
COPY pyproject.toml poetry.lock ./

# API/MCP dependency set: everything EXCEPT the dashboard group.
# (--without dev: no pytest/mypy/ruff/hypothesis. --no-root: package-mode=false
# app (src-layout), not a distributable package.)
RUN poetry install --without dev,dashboard --no-root --no-interaction --no-ansi \
    && rm -rf /app/.venv/lib/python3.11/site-packages/pip* /app/.venv/bin/pip*

# Dashboard builder: SAME lock, dashboard group ADDED on top of the main set.
# Poetry installs only the missing group packages into the existing venv —
# the main-group packages are already satisfied at their locked versions.
# --without dev is REQUIRED here again: without it, this second install also
# pulls the dev group (pytest/mypy/ruff/hypothesis) — poetry's default install
# includes non-optional groups + dev — which would re-add the exact toolchain
# tail the multi-stage build evicted (measured: +118MB / 13 dev dists).
# (The inherited venv has pip stripped — poetry 2.x installs via its own
# vendored installer, not the target venv's pip. Verified empirically:
# the --with dashboard install succeeds on the pipless venv.)
FROM builder AS builder-dashboard
RUN poetry install --without dev --with dashboard --no-root --no-interaction --no-ansi \
    && rm -rf /app/.venv/lib/python3.11/site-packages/pip* /app/.venv/bin/pip*

# ─── Shared runtime base: OS hygiene + app tree + security posture ───────────
# Everything IDENTICAL for both runtime images lives here exactly once — the
# divergent venv/dashboard-source COPYs happen in the child stages.
FROM python:3.11-slim AS runtime-base

WORKDIR /app

# Build traceability (V0.3): GIT_SHA baked as a label AND an env var —
# /health, the entrypoint log, and `docker inspect` all answer "which
# build is running?" with the same commit sha. make build passes GIT_SHA;
# plain docker builds without the arg fall back to "unknown" (honest).
ARG GIT_SHA=unknown
ENV GIT_SHA=${GIT_SHA}
LABEL org.opencontainers.image.revision=${GIT_SHA} \
      org.opencontainers.image.source="https://github.com/aiagentmackenzie-lang/securityscarletai" \
      org.opencontainers.image.title="SecurityScarletAI"

# Boot-critical client tooling (2026-09-03 slim-image regression): the
# entrypoint applies the schema via `psql -f src/db/schema.sql`
# (statement-by-statement with ON_ERROR_STOP=1 — see the P0-05 note in
# scripts/entrypoint.sh for why asyncpg alone is not equivalent) and waits
# via pg_isready. The Phase C slimming removed these along with the build
# toolchain and the API crash-looped before uvicorn ever started, while the
# Sep-2 certification (build + `import ok`) could not see it. psql is a
# RUNTIME requirement, not build tooling. Bookworm ships the PG15 client;
# it speaks the wire protocol to a PG17 server fine (DDL is server-side).
#
# OS base hygiene (2026-09-13, trivy gate): the gate (HIGH,CRITICAL,
# ignore-unfixed) surfaced newly-disclosed CVEs in the slim base's OS
# packages that Debian has ALREADY FIXED in point releases (gzip
# CVE-2026-41992, pcre2 CVE-2026-86145/89161, sqlite3 CVE-2026-11822/11824
# among them) — the pinned base-image snapshot simply predates them.
# `apt-get -y upgrade` pulls the point releases, so the fixes land instead
# of the findings getting ignored into .trivyignore. Runs in the same layer
# as the psql install (one update pass).
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Base hygiene (see header comment): the base image's setuptools 79.0.1
# vendors jaraco.context 5.3.0 + wheel 0.45.1 — the ONLY two trivy HIGH
# findings in the pre-multi-stage image. setuptools >=84 vendors fixed
# versions (jaraco.context 6.1.0 / wheel 0.46.3). Runs before the venv COPY,
# so it upgrades the system site-packages with the system pip.

RUN pip install --no-cache-dir --upgrade "setuptools>=84"

# Security: run as non-root user. Created BEFORE the COPYs so each COPY can
# set ownership directly (--chown) — no post-hoc `chown -R` layer.
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Copy application code (identical for both runtime targets)
COPY --chown=appuser:appgroup src/ ./src/
COPY --chown=appuser:appgroup rules/ ./rules/
COPY --chown=appuser:appgroup config/ ./config/

# Copy scripts/ (entrypoint + seeders used by demo-data step)
COPY --chown=appuser:appgroup scripts/ ./scripts/
RUN chmod +x /app/scripts/entrypoint.sh

# Create data and models directories (entrypoint trains into models/, writes
# data/admin_initial_password — both must be appuser-writable even when no
# host volume is mounted, e.g. the CI boot gate).
RUN mkdir -p /app/data/dead_letter /app/models \
    && chown appuser:appgroup /app/data /app/models

# Environment: never buffer Python output (log streaming in docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ─── Runtime target: dashboard (Streamlit UI) ────────────────────────────────
# Full venv (main + dashboard groups) + the dashboard source tree.
# `streamlit run dashboard/main.py` needs BOTH (charts import altair/pandas).
FROM runtime-base AS dashboard

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=builder-dashboard --chown=appuser:appgroup /app/.venv /app/.venv

# Epic 10: the dashboard source, baked for prod (dev mounts ./dashboard over
# it). Only the dashboard target carries it — api/mcp never read it.
COPY --chown=appuser:appgroup dashboard/ ./dashboard/

USER appuser

# Expose dashboard port (compose overrides per service)
EXPOSE 8501

# Health check using Python stdlib — raises on HTTP >= 400, exits nonzero.
# Streamlit's own health endpoint; the compose dashboard service keeps this
# same probe (the shared-image-era check pinged :8000 and always failed).
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=8)" || exit 1

CMD ["streamlit", "run", "dashboard/main.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]

# ─── Runtime target: api (DEFAULT — last stage) ─────────────────────────────
# Also serves the mcp service (compose sets command + scoped-readonly env).
# venv carries ONLY the main dependency group — no Streamlit stack (AUD-014).
FROM runtime-base AS api

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv

USER appuser

# Expose API port
EXPOSE 8000

# Health check using Python stdlib — raises on HTTP >= 400, exits nonzero.
# `python` resolves to the venv interpreter via PATH; the compose api service
# overrides this check with the same stdlib probe pattern.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=8)" || exit 1

# Entrypoint (Epic 7) — waits for DB, applies schema, seeds, trains, then execs uvicorn.
CMD ["/app/scripts/entrypoint.sh"]