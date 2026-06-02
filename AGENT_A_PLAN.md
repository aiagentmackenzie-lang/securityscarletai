# Agent A Working Plan

## Branch: agent-a-ai-data

## Zone (read/write):
- src/ai/**  (all files)
- src/detection/**  (all files)
- src/db/schema.sql  (APPEND ONLY)
- src/api/correlation.py  (full ownership)
- src/api/ai.py  (status endpoint only, careful)
- src/api/health.py  (add ollama_status field if not present)
- scripts/generate_training_data.py  (NEW)
- tests/test_ai_*  (new)
- tests/test_correlation_*  (new)

## Do NOT touch:
- src/api/main.py, auth.py, middleware.py, audit.py
- src/config/settings.py
- src/enrichment/*
- src/ingestion/*
- docker-compose.yml, Dockerfile
- dashboard/
- src/api/websocket.py

## Plan

### Epic 1 — LLM Contract
1. Add `LLMResult` dataclass + rewrite `query_llm()` in src/ai/ollama_client.py
2. Make `validate_ollama_model()` return tuple
3. Update src/api/health.py to add `ollama_status` field
4. Update src/ai/alert_explanation.py to return dict with `source`, `fallback_used`, `warning`, `prompt_version`
5. Update src/ai/chat.py same treatment
6. NEW: src/ai/prompts.py — Jinja2 templates with version constants
7. NEW: src/ai/cost_tracker.py — insert into ai_usage table
8. APPEND: src/db/schema.sql — ai_usage + triage_model_provenance tables
9. Tests: test_ai_ollama_contract.py, test_ai_cost_tracker.py

### Epic 2 — Event-Driven Correlation
1. APPEND: src/db/schema.sql — correlation_matches table
2. Rewrite src/detection/correlation.py:
   - as_of parameter, $1::timestamptz bound, no NOW() in queries
   - persist=True writes to correlation_matches
   - correlation_id uuid per match
3. Update src/api/correlation.py:
   - POST /correlation/run with as_of + persist
   - GET /correlation/matches with filters
   - POST /correlation/matches/{id}/seen
4. Tests: test_correlation_persist.py, test_correlation_api.py

### Epic 3 — Triage Model
1. NEW: scripts/generate_training_data.py (1000 synthetic alerts, 40/30/30 split)
2. Append: alert_labels table to schema (since resolution_status/labeled_at columns don't exist)
3. Rewrite train() in src/ai/alert_triage.py:
   - StratifiedKFold(5) + CalibratedClassifierCV
   - TriageModelProvenance dataclass
   - Persist provenance to triage_model_provenance table
4. Update check_auto_train() — triggers on >20% new labels OR >7d old
5. Update src/api/ai.py status endpoint to include triage cv_accuracy/calibrated/features
6. Tests: test_triage_provenance.py, test_training_data.py

## Workflow rules
- git status --short before every commit
- pytest tests/ -q after every epic
- Notify via cmux notify after each epic
- No pushes

## Cross-agent notes (added during work)

### 2026-06-01 — Pre-existing test failures (NOT Agent A's work)
9 tests in `tests/unit/test_auth_revocation.py` are failing with
`AttributeError: 'str' object has no attribute 'get_secret_value'` when
calling `settings.api_secret_key.get_secret_value()`.

This file is in Agent B's zone (auth/redis work). The test was added by
Agent B and references `api_secret_key` as a SecretStr, but
`src/config/settings.py` declares it as `str` per the original schema.

**FIXME(agent-b):** Either update the test to call `settings.api_secret_key`
as a plain string, or change the settings field to `SecretStr`. Decision
rests with Agent B.
