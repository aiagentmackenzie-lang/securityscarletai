# Multi-stage build (Project C, 2026-09-04): the Poetry toolchain and its
# dependency tail (cleo, build, cachecontrol, virtualenv, dulwich, keyring, …)
# used to be installed straight into the runtime image, dragging ~20
# build-only packages into site-packages. Stage 1 (builder) installs poetry +
# the locked runtime dependency set into an in-project virtualenv
# (/app/.venv); stage 2 copies ONLY that venv + the application tree. Poetry
# itself never enters the runtime image.
#
# Trivy evidence (2026-09-04): the two HIGH findings in the old image
# (jaraco.context 5.3.0 CVE-2026-23949, wheel 0.45.1 CVE-2026-24049) came from
# the _vendor/ copies inside the setuptools that SHIPS IN THE python:3.11-slim
# BASE — not from poetry's tail (whose own jaraco.context 6.1.2 / wheel 0.46.3
# were fixed versions with 0 findings). Evicting poetry alone therefore does
# NOT clear the scan: the final stage upgrades setuptools (>=84 vendors
# jaraco.context 6.1.0 + wheel 0.46.3, both fixed) as base hygiene.
#
# Size note (2026-09-04): the previous single-stage layout paid a hidden
# ~620MB layer tax — `RUN chown -R appuser:appgroup /app` re-committed every
# file it touched (no overlay metacopy on this builder). Ownership is now set
# at COPY time via --chown, so no chown layer exists.

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

# --without dev: the runtime image must NOT carry pytest/mypy/ruff/hypothesis.
# --no-root: package-mode=false app (src-layout), not a distributable package.
RUN poetry install --without dev --no-root --no-interaction --no-ansi \
    && rm -rf /app/.venv/lib/python3.11/site-packages/pip* /app/.venv/bin/pip*

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Boot-critical client tooling (2026-09-03 slim-image regression): the
# entrypoint applies the schema via `psql -f src/db/schema.sql`
# (statement-by-statement with ON_ERROR_STOP=1 — see the P0-05 note in
# scripts/entrypoint.sh for why asyncpg alone is not equivalent) and waits
# via pg_isready. The Phase C slimming removed these along with the build
# toolchain and the API crash-looped before uvicorn ever started, while the
# Sep-2 certification (build + `import ok`) could not see it. psql is a
# RUNTIME requirement, not build tooling. Bookworm ships the PG15 client;
# it speaks the wire protocol to a PG17 server fine (DDL is server-side).
RUN apt-get update \
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

# The runtime dependency set, built in stage 1. Same path (/app/.venv) as in
# the builder, so console-script shebangs and the python symlink stay valid.
# Deliberately NOT copied: pyproject.toml / poetry.lock — nothing in the
# runtime image reads them (host-mode dev uses the repo checkout).
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv

# Copy application code
COPY --chown=appuser:appgroup src/ ./src/
COPY --chown=appuser:appgroup rules/ ./rules/
COPY --chown=appuser:appgroup config/ ./config/
# Epic 10: copy the Streamlit dashboard so the `dashboard` compose
# service can `streamlit run dashboard/main.py` from this same image.
COPY --chown=appuser:appgroup dashboard/ ./dashboard/

# Copy scripts/ (entrypoint + seeders used by demo-data step)
COPY --chown=appuser:appgroup scripts/ ./scripts/
RUN chmod +x /app/scripts/entrypoint.sh

# Create data and models directories (entrypoint trains into models/, writes
# data/admin_initial_password — both must be appuser-writable even when no
# host volume is mounted, e.g. the CI boot gate).
RUN mkdir -p /app/data/dead_letter /app/models \
    && chown appuser:appgroup /app/data /app/models

USER appuser

# Expose API port
EXPOSE 8000

# Environment: never buffer Python output (log streaming in docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check using Python stdlib — raises on HTTP >= 400, exits nonzero.
# `python` resolves to the venv interpreter via PATH; the compose api and
# dashboard services override this check with the same stdlib probe pattern.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=8)" || exit 1

# Entrypoint (Epic 7) — waits for DB, applies schema, seeds, trains, then execs uvicorn.
CMD ["/app/scripts/entrypoint.sh"]