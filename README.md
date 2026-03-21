# SecurityScarletAI — AI-Native SIEM

A custom AI-Native Security Information and Event Management (SIEM) system built for macOS ARM64.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SecurityScarletAI                            │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  osquery  │───▶│  Log Shipper │───▶│  Normalizer  │              │
│  │  (agent)  │    │  (file tail) │    │  (ECS map)   │              │
│  └──────────┘    └──────────────┘    └──────┬───────┘              │
│                                             │                       │
│  ┌──────────┐    ┌──────────────┐           ▼                      │
│  │ External  │───▶│  HTTP Ingest │───▶┌───────────┐                │
│  │  Sources  │    │  (FastAPI)   │    │ Enrichment │                │
│  └──────────┘    └──────────────┘    │  Pipeline  │                │
│                                      └─────┬─────┘                 │
│                                            │                        │
│                    ┌───────────────────────▼──────────────┐         │
│                    │     PostgreSQL + TimescaleDB          │         │
│                    │  ┌──────┐ ┌────────┐ ┌───────┐      │         │
│                    │  │ logs │ │ alerts │ │ cases │ ...   │         │
│                    │  └──────┘ └────────┘ └───────┘      │         │
│                    └───────────────┬──────────────────────┘         │
│                                   │                                 │
│               ┌───────────────────┼───────────────────┐            │
│               ▼                   ▼                   ▼            │
│  ┌────────────────┐  ┌──────────────────┐  ┌────────────────┐     │
│  │ Detection Eng.  │  │   AI / ML Layer  │  │   Dashboard    │     │
│  │ - Sigma Rules   │  │ - Ollama (LLM)   │  │ - Streamlit    │     │
│  │ - Correlation   │  │ - UEBA (sklearn) │  │ - WebSocket    │     │
│  │ - Scheduler     │  │ - NL→SQL         │  │ - Auth (RBAC)  │     │
│  └────────┬───────┘  └────────┬─────────┘  └────────────────┘     │
│           │                   │                                     │
│           ▼                   ▼                                     │
│  ┌──────────────────────────────────┐                              │
│  │        Response / SOAR Lite      │                              │
│  │  - Slack webhook  - pf firewall  │                              │
│  │  - Email alert    - Case mgmt    │                              │
│  └──────────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- macOS ARM64 (Apple Silicon)
- Python 3.11+
- PostgreSQL 17
- Poetry

### Install

```bash
# Clone and setup
cd ~/SecurityScarletAI
poetry install

# Copy environment template
cp .env.example .env
# Edit .env with your database credentials

# Run database migrations
psql scarletai -f src/db/schema.sql

# Start the API
poetry run uvicorn src.api.main:app --reload
```

### Verify Installation

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Test ingestion (requires bearer token)
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"@timestamp": "2026-03-21T12:00:00Z", "host_name": "test", "source": "api", "event_category": "process", "event_type": "start", "raw_data": {}}]'
```

## Development

### Run Tests

```bash
# Unit tests
poetry run pytest tests/unit/

# Integration tests (requires PostgreSQL)
poetry run pytest tests/integration/
```

### Code Quality

```bash
poetry run black src/ tests/
poetry run ruff check src/ tests/
poetry run mypy src/
```

## Security Considerations

SecurityScarletAI is a learning project. It is NOT production-hardened for enterprise deployment.

Known limitations:
- Single-user JWT (no token rotation or refresh)
- No TLS between components (add nginx/caddy reverse proxy for HTTPS)
- Threat intel API keys stored in .env (use a secrets manager for production)
- Ollama runs unauthenticated on localhost (do not expose to network)
- File-based checkpointing (not crash-consistent)

## Validation & Testing

### Configuration Check
```bash
poetry run python scripts/validate_config.py
```

### Run Attack Simulation
```bash
poetry run python scripts/generate_attack_data.py --scenario all
```

### Verify Data Flow
```bash
# Check osquery logs are being generated
wc -l /var/log/osquery/osqueryd.results.log

# Check events are in database
psql scarletai -c "SELECT COUNT(*) FROM logs;"

# Check alerts are being created
psql scarletai -c "SELECT * FROM alerts ORDER BY time DESC LIMIT 5;"
```

## Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f api
```

## License

Private — for educational use only.
