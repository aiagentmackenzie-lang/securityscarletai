# SecurityScarletAI — Telemetry Wire-Up Phase Plan

**Branch:** `wire-telemetry-pipe`
**Created:** 2026-06-26
**Lead:** Mackenzie 🔍
**Goal:** Convert the SIEM from "engine that fires on synthetic POSTed events" to
"engine that ingests a real log source and fires detection live" — and close the
related honesty T's (Alembic decision, Makefile, SECURITY.md, tag).

The ingestion module already exists (`src/ingestion/shipper.py` `FileShipper`,
`src/ingestion/parser.py` `parse_osquery_line`) and settings already has
`osquery_log_path`. The shipper is just not started by the app lifecycle. This
plan wires it, demonstrates it, and cleans up the dead Alembic path.

## Phase 0 — Plan (this doc)
Commit the plan. No code change.

## Phase 1 — Wire FileShipper into the app lifespan
- Add `enable_ingestion_shipper: bool = False` to `src/config/settings.py`
  (default OFF → zero behavior change for existing deployments/CI).
- In `src/api/main.py` `lifespan()`, when enabled, start a `FileShipper`
  pointing at `settings.osquery_log_path` using the shared `writer` instance,
  as a background `asyncio.Task`; cancel + await it on shutdown.
- Add `tests/` coverage: a test that enables the flag, points at a temp log,
  appends an osquery-format line, and asserts the event reaches the writer
  buffer (no DB required — mock the writer flush or use the in-memory path).
- Gate: `ruff check src/ tests/` + `mypy src` + `pytest -q` green.

## Phase 2 — osquery live-detection demo script
- `scripts/generate_osquery_events.py`: emits realistic osquery result-log
  JSON lines (one benign, one that matches `rules/sigma/process/reverse_shell.yml`)
  to a target file path.
- `scripts/run_osquery_demo.sh`: starts Postgres via compose, applies
  `src/db/schema.sql`, starts the API with `ENABLE_INGESTION_SHIPPER=true`
  and `OSQUERY_LOG_PATH` pointed at a temp log, runs the generator, waits for
  the detection scheduler tick, and prints the resulting alert.
- README: add a "Live telemetry demo" section pointing at the script.
- Gate: script runs locally (or is at least syntactically valid + dry-checked);
  `pytest` still green.

## Phase 3 — Execute the Alembic decision (delete dead path, own schema.sql)
The decision is already documented in `alembic/README.md`: schema.sql is
canonical, Alembic cannot run (no ORM models, async vs sync engine). Execute it:
- `git rm -r alembic/ alembic.ini`.
- Remove `alembic (>=1.18.4,<2.0.0)` from `pyproject.toml` dependencies.
- Fix `scripts/demo.sh`: replace `poetry run alembic upgrade head` with
  applying `src/db/schema.sql` (the Docker path already does this via
  `scripts/entrypoint.sh`; the local demo script must match).
- Update README if it references Alembic as a runnable migration path.
- Gate: `ruff` + `mypy` + `pytest` green; `poetry install` still resolves.

## Phase 4 — Makefile
Add `Makefile` with targets: `demo`, `test`, `lint`, `format`, `mypy`,
`up` (docker compose up -d), `down`, `migrate` (apply schema.sql), `clean`.
- Gate: `make -n demo` and `make -n test` parse; `make lint` runs.

## Phase 5 — SECURITY.md + v0.1.0 tag
- Add `SECURITY.md` (reporting channel, scope, supported versions).
- Tag `v0.1.0` locally (push is 🟡 external — deferred to Raphael's approval).
- Final gate: full `ruff` + `mypy` + `pytest` green on the branch.

## Definition of done (all phases)
1. `make demo` → osquery events flow → a Sigma rule fires → alert appears.
2. No `alembic/` directory; `schema.sql` is the only schema path; `demo.sh`
   doesn't lie.
3. `Makefile`, `SECURITY.md`, local `v0.1.0` tag exist.
4. `ruff` + `mypy` + `pytest` green on the branch.
5. Portfolio reference doc updated to reflect completed sprint items.