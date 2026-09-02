FROM python:3.11-slim

WORKDIR /app

# Install Poetry (pinned version for reproducibility)
RUN pip install poetry

# Copy project files
COPY pyproject.toml poetry.lock ./

# Configure Poetry (don't create virtualenv in container)
RUN poetry config virtualenvs.create false

# Install dependencies (without dev, no root, no-ansi)
RUN poetry install --no-root --no-interaction --no-ansi

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