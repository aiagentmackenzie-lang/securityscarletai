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

# Install Poetry (C4: pinned >=2.3 to match the poetry.lock generator
# (2.3.2, lock-version 2.1) — poetry 2.1+ reads the PEP-735 [dependency-groups]
# table; 2.0.x does NOT and fails with 'Group(s) not found: dev').
RUN pip install --no-cache-dir "poetry>=2.3,<3.0"

# Copy project files
COPY pyproject.toml poetry.lock ./

# Configure Poetry (don't create virtualenv in container)
RUN poetry config virtualenvs.create false

# Install dependencies (without dev — the runtime image must NOT carry
# pytest/mypy/ruff/hypothesis; --no-root: app, not package)
RUN poetry install --without dev --no-root --no-interaction --no-ansi

# Copy application code
COPY src/ ./src/
COPY rules/ ./rules/
COPY config/ ./config/
# Epic 10: copy the Streamlit dashboard so the `dashboard` compose
# service can `streamlit run dashboard/main.py` from this same image.
COPY dashboard/ ./dashboard/

# Copy scripts/ (entrypoint + seeders used by demo-data step)
COPY scripts/ ./scripts/
RUN chmod +x /app/scripts/entrypoint.sh

# Create data and models directories
RUN mkdir -p /app/data/dead_letter /app/models

# Security: run as non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser && chown -R appuser:appgroup /app
USER appuser

# Expose API port
EXPOSE 8000

# Environment: never buffer Python output (log streaming in docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check using Python stdlib — raises on HTTP >= 400, exits nonzero.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=8)" || exit 1

# Entrypoint (Epic 7) — waits for DB, applies schema, seeds, trains, then execs uvicorn.
CMD ["/app/scripts/entrypoint.sh"]