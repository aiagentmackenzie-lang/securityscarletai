# SecurityScarletAI — Makefile
#
# Common dev/demo targets. Run `make help` to list them.
# Requires Docker + Poetry (with `poetry install` already run).

.PHONY: help install up down logs migrate demo test lint lint-tests format mypy clean

PYTHON := poetry run python3
SCHEMA := src/db/schema.sql

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install Python dependencies via Poetry
	poetry install

up: ## Start Postgres + Redis (+ API + dashboard via compose profiles)
	docker compose up -d

down: ## Stop the Docker stack
	docker compose down

logs: ## Tail compose logs
	docker compose logs -f --tail=100

migrate: ## Apply the canonical schema (src/db/schema.sql) to the running Postgres
	@echo "Applying $(SCHEMA)..."
	@docker compose exec -T postgres psql -U scarletai -d scarletai -f /dev/stdin < $(SCHEMA) \
	  || psql "$$DATABASE_URL" -f $(SCHEMA)

demo: ## Live telemetry demo: osquery log -> shipper -> Sigma -> alert (needs Docker + .env)
	./scripts/run_osquery_demo.sh

test: ## Run the unit test suite
	poetry run pytest tests/unit/ -q

lint: ## Ruff lint the product code (matches the CI gate: src + dashboard)
	poetry run ruff check src/ dashboard/

lint-tests: ## Ruff lint the tests (informational — not gated by CI)
	poetry run ruff check tests/

format: ## Ruff format the product code
	poetry run ruff format src/ tests/ scripts/

mypy: ## Type-check the product code
	poetry run mypy src

clean: ## Remove build/test caches
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +