FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# - gcc/libpq-dev: build asyncpg
# - curl: healthcheck
# - postgresql-client: pg_isready in entrypoint.sh
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY README.md ./

# Configure Poetry (don't create virtualenv in container)
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --without dev --no-root --no-interaction --no-ansi

# Copy application code
COPY src/ ./src/
COPY rules/ ./rules/
COPY alembic/ ./alembic/
COPY alembic.ini ./alembic.ini
COPY config/ ./config/
# Epic 10: copy the Streamlit dashboard so the `dashboard` compose
# service can `streamlit run dashboard/main.py` from this same image.
COPY dashboard/ ./dashboard/

# Copy entrypoint script (Epic 7)
COPY scripts/entrypoint.sh /app/scripts/entrypoint.sh
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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Entrypoint (Epic 7) — waits for DB, applies schema, seeds, trains, then execs uvicorn.
CMD ["/app/scripts/entrypoint.sh"]
