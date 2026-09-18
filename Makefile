# SecurityScarletAI — Makefile
#
# Common dev/demo targets. Run `make help` to list them.
# Requires Docker + Poetry (with `poetry install` already run).

.PHONY: help install build prod up down logs migrate demo demo-refresh test lint lint-tests format mypy clean posture-check

PYTHON := poetry run python3
SCHEMA := src/db/schema.sql

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install Python dependencies via Poetry
	poetry install

GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

build: ## Build api+dashboard+mcp images STAMPED with the current git sha (always fresh -- kills stale-image drift)
	GIT_SHA=$(GIT_SHA) docker compose build api dashboard mcp

prod: ## Guarded local-prod boot: posture check -> sha-stamped build -> prod overlay (see docs/PRODUCTION.md)
	@if ! grep -qE '^(PASSWORD_PEPPER|DATABASE_SUPERUSER_URL)=..' .env 2>/dev/null; then \
		echo "prod: .env lacks the local-prod markers (PASSWORD_PEPPER / DATABASE_SUPERUSER_URL) -- this is not a prod host."; exit 1; fi
	@if grep -qE '^DEMO_SEED_ENABLED=true' .env 2>/dev/null; then \
		echo "DEMO_SEED_ENABLED=true in .env -- refusing to boot PROD with the demo seed flag (one mode per volume)."; exit 1; fi
	GIT_SHA=$(GIT_SHA) docker compose -f docker-compose.yml -f docker-compose.local-prod.yml build api dashboard mcp
	GIT_SHA=$(GIT_SHA) docker compose -f docker-compose.yml -f docker-compose.local-prod.yml up -d
	@echo "Prod stack up (build $(GIT_SHA)). Posture verified by the entrypoint (fail-closed)."

posture-check: ## Run the mode-isolation posture check (no boot)
	poetry run python -m scripts.posture_check

up: ## Start Postgres + Redis (+ API + dashboard via compose profiles)
	docker compose up -d

down: ## Stop the Docker stack
	docker compose down

logs: ## Tail compose logs
	docker compose logs -f --tail=100

migrate: ## Apply the canonical schema (src/db/schema.sql) to the running Postgres
	@echo "Applying $(SCHEMA)..."
	@docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U scarletai -d scarletai -f /dev/stdin < $(SCHEMA) \
	  || (echo "docker exec path failed. NOTE: under the two-role deploy the app role\n\
	       cannot CREATE tables (by design) — apply as the OWNER, e.g. via\n\
	       DATABASE_SUPERUSER_URL (see docs/DEPLOYMENT.md / docs/PRODUCTION.md)."; exit 1)

demo: ## Live telemetry demo: osquery log -> shipper -> Sigma -> alert (needs Docker + .env)
	@if [ -n "$$(docker ps --filter name=scarletai-api --filter status=running -q 2>/dev/null)" ]; then \
		echo "scarletai-api container is RUNNING (prod/local-prod posture). make demo STOPS that container by design — refusing."; \
		echo "Run 'docker compose down' first if you really mean to replace the standing stack (HITL)."; exit 1; fi
	./scripts/run_osquery_demo.sh

demo-refresh: ## Slide demo-data timestamps to now (see docs/DEMO.md — fixes stale/empty demo pages)
	docker compose exec -T api python -m scripts.refresh_demo_timestamps

test: ## Run the unit test suite
	poetry run pytest tests/unit/ -q

lint: ## Ruff lint the product code (matches the CI gate: src + dashboard)
	poetry run ruff check src/ dashboard/

lint-tests: ## Ruff lint the tests (informational — not gated by CI)
	poetry run ruff check tests/

format: ## Ruff format the product code (AUD-015: dashboard/ included — same scope the lint + CI format gate checks)
	poetry run ruff format src/ tests/ scripts/ dashboard/

mypy: ## Type-check the product code
	poetry run mypy src

clean: ## Remove build/test caches
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +