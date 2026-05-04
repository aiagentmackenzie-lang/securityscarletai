# Deployment Guide

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Tested on 3.11.x |
| Docker | 20.10+ | For PostgreSQL and Redis |
| PostgreSQL | 15+ | Docker or local; 17 recommended |
| Poetry | 1.7+ | Python dependency management |
| Ollama | Latest | Local LLM runtime (optional, features degrade gracefully) |

## Environment Variables

Copy the template and edit:

```bash
cp .env.example .env
```

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password (no default) | `openssl rand -hex 32` |
| `API_SECRET_KEY` | JWT signing key (min 32 chars) | `openssl rand -hex 64` |
| `API_BEARER_TOKEN` | API ingestion auth token (min 16 chars) | `openssl rand -hex 32` |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5433` | PostgreSQL port (5433 avoids Homebrew conflict) |
| `DB_NAME` | `scarletai` | Database name |
| `DB_USER` | `scarletai` | Database user |
| `DB_POOL_MIN` | `2` | Min connection pool size |
| `DB_POOL_MAX` | `10` | Max connection pool size |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `127.0.0.1` | API bind address |
| `API_PORT` | `8000` | API bind port |
| `API_CORS_ORIGINS` | `["http://localhost:8501"]` | Allowed CORS origins |

### Ollama (AI Features)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `llama3.2:8b` | Model name |
| `OLLAMA_TIMEOUT` | `30` | Request timeout (seconds) |

AI features degrade gracefully when Ollama is unavailable — template fallbacks and rule-based responses are used instead.

### Threat Intel (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key |
| `OTX_API_KEY` | _(empty)_ | AlienVault OTX API key |

### Notifications (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook for alert notifications |
| `SMTP_HOST` | _(empty)_ | SMTP server for email alerts |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | _(empty)_ | SMTP username |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password |
| `ALERT_EMAIL_TO` | _(empty)_ | Alert recipient email |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `LOG_FORMAT` | `json` | Log format (`json` for production, `console` for dev) |

---

## Docker Compose Setup

The included `docker-compose.yml` provides PostgreSQL and Redis:

```bash
# Start infrastructure
docker-compose up -d

# Verify PostgreSQL is healthy
docker-compose ps

# View logs
docker-compose logs -f postgres

# Stop
docker-compose down

# Stop and remove data volumes
docker-compose down -v
```

### Port Assignments

| Service | Port | Notes |
|---------|------|-------|
| PostgreSQL | 5433 | Mapped from container's 5432 to avoid macOS conflicts |
| Redis | 6379 | Used for caching |
| API (manual) | 8000 | Run via `uvicorn` |
| Dashboard (manual) | 8501 | Run via `streamlit` |

### Running in Docker

The `docker-compose.yml` also includes an API service definition. To build and run:

```bash
# Build and start all services
docker-compose --profile api up -d

# The API container connects to PostgreSQL internally on port 5432
# Override DB_PORT for the API container:
# DB_PORT=5432 (set in docker-compose environment)
```

---

## Database Migrations

SecurityScarletAI uses Alembic for schema migrations:

```bash
# Apply all pending migrations
poetry run alembic upgrade head

# Check current migration status
poetry run alembic current

# Generate a new migration (after model changes)
poetry run alembic revision --autogenerate -m "description"

# Rollback one migration
poetry run alembic downgrade -1

# Rollback to specific revision
poetry run alembic downgrade <revision_id>
```

The initial schema is also available as raw SQL in `src/db/schema.sql` (used by Docker Compose for first-time init via `docker-entrypoint-initdb.d`).

---

## Security Hardening Checklist

### TLS Termination

- **Never expose the API directly in production** — use a reverse proxy (nginx, Caddy, Traefik) with TLS
- Example nginx config:

```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/scarletai.pem;
    ssl_certificate_key /etc/ssl/private/scarletai.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

- For Streamlit, run behind the same reverse proxy on a subpath

### JWT Secret Rotation

- Rotate `API_SECRET_KEY` regularly using `openssl rand -hex 64`
- Store the key in a secrets manager (Vault, AWS Secrets Manager, 1Password)
- After rotation, all existing JWT tokens become invalid — users must re-authenticate

### Network Isolation

- PostgreSQL should only be accessible from the API host
- Use Docker networks or firewall rules:
  ```bash
  # Only allow API host to connect to PostgreSQL
  iptables -A INPUT -p tcp --dport 5433 -s 127.0.0.1 -j ACCEPT
  iptables -A INPUT -p tcp --dport 5433 -j DROP
  ```
- Ollama should only listen on `127.0.0.1:11434` (default) — never expose to the network
- Redis should not be accessible externally

### Rate Limiting

- The API includes built-in rate limiting via SlowAPI (configured in `src/api/middleware.py`)
- Adjust limits as needed in the settings
- For production, add external rate limiting at the reverse proxy level

### Input Validation

- All API endpoints use Pydantic models for request validation
- NL→SQL queries undergo 7-layer injection defense (see [docs/AI.md](AI.md))
- Log ingestion validates against ECS-normalized schemas
- SQL queries use `$1, $2` parameterized placeholders exclusively

### Additional Hardening

- Set `LOG_FORMAT=json` in production for structured logging
- Use `LOG_LEVEL=WARNING` or higher in production to reduce log volume
- Enable SMTP STARTTLS for email notifications
- Restrict CORS origins to your actual dashboard URL
- Run the API as a non-root user
- Keep dependencies updated: `poetry update`

---

## Backup & Recovery

### Database Backup

```bash
# Full backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai -F c -f scarletai_backup_$(date +%Y%m%d).dump

# Schema-only backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai --schema-only -f schema_backup.sql

# Data-only backup
pg_dump -h localhost -p 5433 -U scarletai -d scarletai --data-only -f data_backup.sql
```

### Recovery

```bash
# Restore from custom format backup
pg_restore -h localhost -p 5433 -U scarletai -d scarletai -c scarletai_backup_20260601.dump

# Restore from SQL dump
psql -h localhost -p 5433 -U scarletai -d scarletai -f data_backup.sql
```

### Automated Backup Script

```bash
#!/bin/bash
# Add to crontab: 0 2 * * * /path/to/backup.sh
BACKUP_DIR="/var/backups/scarletai"
mkdir -p "$BACKUP_DIR"
pg_dump -h localhost -p 5433 -U scarletai -d scarletai \
  -F c -f "$BACKUP_DIR/scarletai_$(date +\%Y\%m\%d_\%H\%M).dump"
# Keep only last 30 days
find "$BACKUP_DIR" -name "*.dump" -mtime +30 -delete
```

### ML Model Files

Model files (`models/*.joblib`, `models/*.sha256`) are gitignored and should be backed up separately:
- They are auto-generated during triage model training
- Can be regenerated from training data in the `alerts` table
- Back up the entire `models/` directory

---

## Monitoring Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Liveness + readiness (checks DB and Ollama) |
| `/api/docs` | GET | Swagger UI |
| `/api/redoc` | GET | ReDoc documentation |

Health check response format:

```json
{
  "status": "healthy",
  "checks": {
    "api": "ok",
    "database": "ok",
    "ollama": "ok"
  }
}
```

When Ollama is unreachable, the status becomes `"degraded"` and AI features use template fallbacks.

---

## Troubleshooting

### Database Connection Errors

```bash
# Check PostgreSQL is running
docker-compose ps

# Test connection
psql -h localhost -p 5433 -U scarletai -d scarletai -c "SELECT 1"

# Check logs
docker-compose logs postgres
```

Common issues:
- **Port 5433 in use**: Stop Homebrew PostgreSQL (`brew services stop postgresql`) or change `DB_PORT`
- **Authentication failed**: Verify `DB_PASSWORD` matches in `.env` and `docker-compose.yml`
- **Migration errors**: Run `poetry run alembic upgrade head` to apply pending migrations

### Ollama Connection Issues

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Pull the default model
ollama pull llama3.2:8b
```

AI features work without Ollama using template fallbacks. Check the health endpoint:
```bash
curl http://localhost:8000/api/v1/health | jq '.checks.ollama'
```

### API Not Starting

```bash
# Check for port conflicts
lsof -i :8000

# Verify settings
poetry run python -c "from src.config.settings import settings; print(settings.database_url)"

# Check for missing .env
ls -la .env
```

### Dashboard Issues

```bash
# Start dashboard with verbose logging
poetry run streamlit run dashboard/main.py --server.port 8501 --logger.level debug

# Check API connectivity from dashboard
curl http://localhost:8000/api/v1/health
```

### High Memory Usage

- Reduce `DB_POOL_MAX` in `.env` (default: 10)
- Set `DB_POOL_MIN=2` for minimal connection pool
- Consider `OLLAMA_TIMEOUT=15` if Ollama requests are slow

### Slow Queries

- Check indexes: `\di` in `psql`
- NL→SQL queries are limited to 5 seconds max and 10,000 row cost
- Add GIN indexes for JSONB columns (already included in schema)