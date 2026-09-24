-- ============================================================
-- SecurityScarletAI Database Schema
-- PostgreSQL 17 (TimescaleDB compatible for future upgrade)
-- ============================================================

-- Severity enum — never use magic integers
-- Wrapped in DO blocks so re-running the schema (idempotent apply) does not
-- crash on already-existing types (asyncpg re-runs, multi-boot containers).
DO $$ BEGIN
    CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE alert_status AS ENUM ('new', 'investigating', 'resolved', 'false_positive', 'closed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE case_status AS ENUM ('open', 'in_progress', 'resolved', 'closed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- LOGS — partitioned by time via table partitioning (TimescaleDB upgrade: use hypertable)
-- ============================================================
CREATE TABLE IF NOT EXISTS logs (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    time           TIMESTAMPTZ NOT NULL,
    host_name      TEXT NOT NULL,
    host_ip        INET,
    source         TEXT NOT NULL,           -- 'osquery', 'api', 'syslog', etc.
    event_category TEXT NOT NULL,           -- ECS: 'process', 'network', 'file', 'authentication'
    event_type     TEXT NOT NULL,           -- ECS: 'start', 'end', 'connection', 'creation'
    event_action   TEXT,                    -- ECS: specific action like 'process_started'
    user_name      TEXT,
    process_name   TEXT,
    process_pid    INTEGER,
    process_cmdline TEXT,                   -- full command line
    process_path   TEXT,                    -- binary path (e.g., /usr/bin/curl)
    source_ip      INET,
    destination_ip INET,
    destination_port INTEGER,
    file_path      TEXT,
    file_hash      TEXT,
    raw_data       JSONB NOT NULL,          -- original event, unmodified
    normalized     JSONB NOT NULL,          -- ECS-mapped fields
    enrichment     JSONB DEFAULT '{}'::jsonb, -- GeoIP, DNS, threat intel hits
    severity       TEXT DEFAULT 'info',        -- info/low/medium/high/critical (event severity)
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_logs_time ON logs (time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_category ON logs (event_category, time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_user ON logs (user_name, time DESC) WHERE user_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs (source_ip, time DESC) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_process ON logs (process_name, time DESC) WHERE process_name IS NOT NULL;
-- Primary key index exists implicitly on id; helper index for severity-filtered
-- correlation/detection queries (e.g. detect_defense_evasion_cleanup).
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs (severity, time DESC) WHERE severity IS NOT NULL;
-- GIN index for JSONB full-text search on raw data
CREATE INDEX IF NOT EXISTS idx_logs_raw_gin ON logs USING GIN (raw_data jsonb_path_ops);
-- GIN index for normalized JSONB column (supports process_cmdline, process_path, etc.)
CREATE INDEX IF NOT EXISTS idx_logs_normalized_gin ON logs USING GIN (normalized jsonb_path_ops);
-- P1-D: BRIN index on time for cheap time-range scans at scale. B-tree
-- idx_logs_time is fine for recent-queries but BRIN is far cheaper (tiny,
-- summary blocks) for large time-series tables — the right index when logs
-- grows into the millions of rows. The b-tree stays for ORDER BY time DESC.
CREATE INDEX IF NOT EXISTS idx_logs_time_brin ON logs USING BRIN (time);
-- NOTE: for very high ingest, upgrade to TimescaleDB:
--   CREATE EXTENSION IF NOT EXISTS timescaledb;
--   SELECT create_hypertable('logs', 'time', chunk_time_interval => INTERVAL '1 day');
-- TimescaleDB compression + retention policies supersede the BRIN index and
-- the src/services/retention.py job (use a drop_chunks policy instead).


-- ============================================================
-- DETECTION RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT,
    sigma_yaml     TEXT NOT NULL,           -- raw Sigma rule YAML
    -- L-01 fix: removed generated_sql column — SQL is generated at runtime by sigma_to_sql()
    severity       alert_severity NOT NULL DEFAULT 'medium',
    mitre_tactics  TEXT[],                  -- e.g., ARRAY['TA0001', 'TA0002']
    mitre_techniques TEXT[],               -- e.g., ARRAY['T1059', 'T1078']
    enabled        BOOLEAN NOT NULL DEFAULT true,
    run_interval   INTERVAL NOT NULL DEFAULT '60 seconds',
    lookback       INTERVAL NOT NULL DEFAULT '5 minutes',
    threshold      INTEGER DEFAULT 1,      -- minimum matches to trigger
    last_run       TIMESTAMPTZ,
    last_match     TIMESTAMPTZ,
    match_count    BIGINT DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- ALERTS
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id             SERIAL PRIMARY KEY,
    time           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_id        INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    rule_name      TEXT NOT NULL,
    severity       alert_severity NOT NULL,
    status         alert_status NOT NULL DEFAULT 'new',
    host_name      TEXT NOT NULL,
    description    TEXT,
    mitre_tactics  TEXT[],
    mitre_techniques TEXT[],
    evidence       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of matching log excerpts
    ai_summary     TEXT,                    -- LLM-generated explanation (filled async)
    ai_verdict     TEXT,                    -- AUD-030: LLM verdict (threat/suspicious/benign/false_positive)
    ai_reasoning   TEXT,                    -- AUD-030: why the verdict was chosen
    ai_response    JSONB,                   -- AUD-030: recommended response steps (array)
    risk_score     FLOAT,
    assigned_to    TEXT,
    resolved_at    TIMESTAMPTZ,
    resolution_note TEXT,                   -- free-text note when resolving
    case_id        INTEGER,                -- FK added after cases table exists
    notes          JSONB DEFAULT '[]'::jsonb, -- M-07 fix: notes column for alert timeline
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts (host_name, time DESC);

-- AUD-030 (2026-09-18): persist the full LLM analysis, not just
-- summary + score. enrich_alert (src/detection/ai_analyzer.py) now writes
-- ai_verdict / ai_reasoning / ai_response; existing deployments get the
-- columns via IF NOT EXISTS (the entrypoint re-runs this file idempotently).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_verdict TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_reasoning TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_response JSONB;

-- Notes column for alert timeline (added by v2)
-- JSONB array of {author, text, timestamp} objects
-- M-07 fix: notes column added directly to alerts table definition

-- ============================================================
-- ALERT SUPPRESSIONS — whitelist known false positives
-- ============================================================
CREATE TABLE IF NOT EXISTS alert_suppressions (
    id             SERIAL PRIMARY KEY,
    rule_name      TEXT,
    host_name      TEXT,
    reason         TEXT NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    created_by     TEXT NOT NULL DEFAULT 'admin',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- ASSETS / SIEM HEALTH — REMOVED (P2-8, 2026-08-26)
--
-- The `assets` and `siem_health` tables were never-populated placeholders
-- (no INSERT path; the schema comments admitted they were not used). Keeping
-- them advertised a feature ("asset criticality" risk scoring) that was never
-- wired. They are removed for honesty. Risk scoring uses the real factors it
-- actually computes (severity, threat-intel match, UEBA anomaly, exposure);
-- see src/ai/risk_scoring.py. Existing deployments that already created these
-- empty tables are unaffected (the schema is append-only / non-destructive).
-- ============================================================


-- ============================================================
-- CASES — group related alerts for investigation
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
    id             SERIAL PRIMARY KEY,
    title          TEXT NOT NULL,
    description    TEXT,
    status         case_status NOT NULL DEFAULT 'open',
    severity       alert_severity NOT NULL,
    assigned_to    TEXT,
    alert_ids      INTEGER[],
    notes          JSONB DEFAULT '[]'::jsonb,  -- array of {author, text, timestamp}
    lessons_learned TEXT,                    -- post-incident lessons
    resolution_note TEXT,                    -- resolution summary
    resolved_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add FK from alerts to cases
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_alerts_case'
    ) THEN
        ALTER TABLE alerts ADD CONSTRAINT fk_alerts_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL;
    END IF;
END $$;


-- ============================================================
-- USERS — SIEM operators (not endpoint users)
-- ============================================================
CREATE TABLE IF NOT EXISTS siem_users (
    id                    SERIAL PRIMARY KEY,
    username               TEXT NOT NULL UNIQUE,
    email                 TEXT UNIQUE,
    password_hash         TEXT NOT NULL,           -- bcrypt(SHA-256(password)) — M-10 fix
    role                  TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active             BOOLEAN NOT NULL DEFAULT true,
    must_change_password  BOOLEAN NOT NULL DEFAULT false,  -- M-10 migration: force reset on first login
    failed_login_attempts  INTEGER NOT NULL DEFAULT 0,   -- C-02: brute-force lockout counter
    locked_until          TIMESTAMPTZ,                -- C-02: account lock timeout
    last_login            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- AUDIT LOG — every state-changing action is recorded
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id             SERIAL PRIMARY KEY,
    actor          TEXT NOT NULL,               -- username or 'system'
    action         TEXT NOT NULL,               -- 'rule.create', 'alert.update', 'case.create', 'user.login'
    target_type    TEXT,                        -- 'rule', 'alert', 'case', 'user'
    target_id      INTEGER,
    old_values     JSONB,                       -- state before change
    new_values     JSONB,                       -- state after change
    ip_address     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log (target_type, target_id);


-- ============================================================
-- THREAT INTEL — cached IOCs from external feeds
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_intel (
    id             SERIAL PRIMARY KEY,
    ioc_type       TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash_md5', 'hash_sha256', 'url')),
    ioc_value      TEXT NOT NULL,
    source         TEXT NOT NULL,           -- 'abuseipdb', 'otx', 'urlhaus'
    threat_type    TEXT,                    -- 'c2', 'malware', 'phishing', 'botnet'
    confidence     INTEGER CHECK (confidence BETWEEN 0 AND 100),
    first_seen     TIMESTAMPTZ,
    last_seen      TIMESTAMPTZ,
    metadata       JSONB DEFAULT '{}'::jsonb,
    fetched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value, source)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup ON threat_intel (ioc_type, ioc_value);


-- ============================================================
-- SIEM HEALTH — REMOVED (P2-8, 2026-08-26)
-- The `siem_health` table was a placeholder never written to. Removed for
-- honesty (see the ASSETS comment above). Self-observability metrics, when
-- added, should land in a table that is actually populated.
-- ============================================================

-- NOTE: To upgrade to TimescaleDB later, run:
-- CREATE EXTENSION timescaledb;
-- SELECT create_hypertable('logs', 'time', chunk_time_interval => INTERVAL '1 day');
-- TimescaleDB compression + retention policies supersede the BRIN index and
-- the src/services/retention.py job (use a drop_chunks policy instead).


-- ============================================================
-- AI USAGE — per-LLM-call cost and latency tracking (Agent A, Epic 1)
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_usage (
    id SERIAL PRIMARY KEY,
    user_id TEXT,
    endpoint TEXT NOT NULL,
    model TEXT NOT NULL,
    tokens_in INT NOT NULL DEFAULT 0,
    tokens_out INT NOT NULL DEFAULT 0,
    latency_ms INT NOT NULL DEFAULT 0,
    prompt_version TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_usage_user_day ON ai_usage(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_usage_endpoint ON ai_usage(endpoint, created_at DESC);

-- W2-I(b): record_usage() accepts source / fallback_used / warning — they
-- were previously dropped (log-only). Persisted now; existing deployments get
-- the columns via IF NOT EXISTS (the entrypoint re-runs this file
-- idempotently — the AUD-030 pattern). fallback_used is deliberately
-- NULLABLE: historical rows have unknown fallback state, and
-- get_usage_summary's model-name heuristic remains the path for those rows.
ALTER TABLE ai_usage ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE ai_usage ADD COLUMN IF NOT EXISTS fallback_used BOOLEAN;
ALTER TABLE ai_usage ADD COLUMN IF NOT EXISTS warning TEXT;

-- ============================================================
-- SSF SEEN SETS — (issuer, jti) replay guard (W5-F)
-- ============================================================
-- SSF SETs carry no exp by design (RFC 8935), so a captured valid SET
-- re-delivers forever unless the receiver remembers its jti. This table is
-- the receiver's memory: one row per accepted (issuer, jti); a redelivery
-- INSERTs nothing (PK conflict, ON CONFLICT DO NOTHING) and is refused as
-- a replay. Pruned by the retention sweep (SSF_RETENTION_DAYS — bounded
-- memory by design; losing old jti rows only re-opens that bounded window
-- to replays, it never affects stored telemetry).
CREATE TABLE IF NOT EXISTS ssf_seen_sets (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer, jti)
);

CREATE INDEX IF NOT EXISTS idx_ssf_seen_sets_seen_at ON ssf_seen_sets (seen_at);

-- ============================================================
-- TRIAGE MODEL PROVENANCE — ML training audit trail (Agent A, Epic 3)
-- ============================================================
CREATE TABLE IF NOT EXISTS triage_model_provenance (
    id SERIAL PRIMARY KEY,
    model_hash TEXT NOT NULL,
    training_samples INT NOT NULL,
    cv_accuracy FLOAT NOT NULL,
    cv_std FLOAT,
    precision_score FLOAT,
    recall_score FLOAT,
    f1_score FLOAT,
    calibrated BOOLEAN DEFAULT FALSE,
    feature_importances JSONB,
    features JSONB,
    trained_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_triage_provenance_trained_at ON triage_model_provenance(trained_at DESC);


-- ============================================================
-- CORRELATION MATCHES — persisted correlation rule hits (Agent A, Epic 2)
-- ============================================================
CREATE TABLE IF NOT EXISTS correlation_matches (
    id SERIAL PRIMARY KEY,
    correlation_rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    match_data JSONB NOT NULL,
    trigger_event_id BIGINT REFERENCES logs(id),
    seen BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_correlation_matches_rule ON correlation_matches(correlation_rule);
CREATE INDEX IF NOT EXISTS idx_correlation_matches_severity ON correlation_matches(severity);
CREATE INDEX IF NOT EXISTS idx_correlation_matches_created ON correlation_matches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_correlation_matches_seen ON correlation_matches(seen, created_at DESC);


-- ============================================================
-- ALERT LABELS — analyst-provided ground truth for triage training (Agent A, Epic 3)
-- Separate from alerts table to respect Agent A's APPEND-ONLY rule on schema.sql
-- ============================================================
CREATE TABLE IF NOT EXISTS alert_labels (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (label IN ('true_positive', 'false_positive', 'needs_review')),
    labeled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    labeled_by TEXT DEFAULT 'training_data_generator',
    UNIQUE (alert_id, label)
);

CREATE INDEX IF NOT EXISTS idx_alert_labels_label ON alert_labels(label);
CREATE INDEX IF NOT EXISTS idx_alert_labels_alert_id ON alert_labels(alert_id);


-- ============================================================
-- TRIAGE_MODEL_PROVENANCE — modern audit columns (Agent A, Epic 3 follow-up)
-- The original table (created in 391e7d1) has: id, model_hash, training_samples,
-- cv_accuracy, cv_std, precision_score, recall_score, f1_score, calibrated,
-- feature_importances, features, trained_at.
-- Agent A's train_v2() writes a richer provenance row (run_id, model_type,
-- source_csv, n_samples, accuracy_score, model_path, run_metadata). These
-- columns are appended nullable so legacy rows keep working and re-running
-- the schema is idempotent.
-- ============================================================
ALTER TABLE triage_model_provenance
    ADD COLUMN IF NOT EXISTS run_id TEXT,
    ADD COLUMN IF NOT EXISTS model_version TEXT,
    ADD COLUMN IF NOT EXISTS model_type TEXT,
    ADD COLUMN IF NOT EXISTS source_csv TEXT,
    ADD COLUMN IF NOT EXISTS n_samples INT,
    ADD COLUMN IF NOT EXISTS n_positive INT,
    ADD COLUMN IF NOT EXISTS n_negative INT,
    ADD COLUMN IF NOT EXISTS accuracy_score FLOAT,
    ADD COLUMN IF NOT EXISTS model_path TEXT,
    ADD COLUMN IF NOT EXISTS run_metadata JSONB;


-- ============================================================
-- AUDIT LOGS — HTTP request-level audit (Agent B, Epic 6)
-- Separate table from the action-level audit_log above. This table
-- captures every state-changing HTTP request (POST/PUT/PATCH/DELETE)
-- with method, path, IP, user, status code, and request duration.
-- ============================================================
-- Permission hardening is NOT applied by this schema (the app role that
-- applies this file owns the tables, and owners bypass REVOKE). To enforce
-- append-only audit, run scripts/harden_audit.sql as a superuser with a
-- separate non-owner app role, then verify with
-- `python -m scripts.check_audit_grants --strict`. See docs/DEPLOYMENT.md
-- -> Audit immutability. Without that two-role setup, audit_logs is
-- append-only BY CONVENTION (the app only INSERTs/SELECTs it).
CREATE TABLE IF NOT EXISTS audit_logs (
    id                BIGSERIAL PRIMARY KEY,
    timestamp         TIMESTAMPTZ DEFAULT NOW(),
    "user"            TEXT,
    role              TEXT,
    method            TEXT NOT NULL,
    path              TEXT NOT NULL,
    ip                TEXT,
    status_code       INT,
    request_body_hash TEXT,
    duration_ms       INT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs ("user");
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_method_path ON audit_logs (method, path);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs (status_code) WHERE status_code >= 400;


-- ============================================================
-- CASE EVENTS — the durable case timeline (V0.4 "Trusted Loop")
-- Append-only: the API exposes INSERT + SELECT only. Every case state
-- change (evidence, verdicts, notes, status transitions, and later
-- response actions) is a typed event with an actor, so a case answers
-- "what happened, who decided it, on what evidence" at any point.
-- event_type is a CLOSED vocabulary (CHECK-enforced), mirroring the
-- closed event_action vocabulary at ingestion: producers map into it,
-- never fake tokens. action_id is nullable until Phase B adds the
-- response_actions table (no FK here to keep this phase independent).
-- ============================================================
DO $$ BEGIN
    CREATE TYPE case_event_type AS ENUM (
        'created', 'evidence_linked', 'evidence_unlinked', 'verdict', 'note',
        'status_change', 'action_requested', 'action_approved',
        'action_rejected', 'action_executed', 'action_failed',
        'action_verified', 'closed'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS case_events (
    id          BIGSERIAL PRIMARY KEY,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_type  case_event_type NOT NULL,
    actor       TEXT NOT NULL,               -- username, 'system', or 'ai:<model>'
    actor_kind  TEXT NOT NULL DEFAULT 'human'
                CHECK (actor_kind IN ('human', 'system', 'ai')),
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    alert_id    INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    action_id   INTEGER,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events (case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_case_events_type ON case_events (event_type);
CREATE INDEX IF NOT EXISTS idx_case_events_alert ON case_events (alert_id) WHERE alert_id IS NOT NULL;


-- ============================================================
-- RESPONSE ACTIONS -- bounded response authority (V0.4 "Trusted Loop")
-- Every proposed containment action lives here with its policy decision,
-- approval trail, execution record, and post-action RE-QUERY verification
-- (the before/after proof that the intended state change happened).
-- action_type is a CLOSED vocabulary (enum, CHECK-enforced); the policy
-- engine (src/response/policy.py) decides allow / approval_required /
-- never from config/response_policy.yaml and fails closed on anything
-- unknown. Containment actions NEVER auto-execute: HITL approval with
-- the requester != approver (four-eyes) is enforced at the API layer.
-- ============================================================
DO $$ BEGIN
    CREATE TYPE response_action_type AS ENUM (
        'notify_slack', 'disable_siem_user', 'quarantine_host',
        'pf_block_ip', 'disable_macos_user', 'isolate_host_fleet'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE response_action_status AS ENUM (
        'requested', 'approved', 'rejected', 'executing', 'executed',
        'verified', 'execution_failed', 'verification_failed'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS response_actions (
    id               BIGSERIAL PRIMARY KEY,
    case_id          INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    action_type      response_action_type NOT NULL,
    params           JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_effect    TEXT NOT NULL,
    status           response_action_status NOT NULL DEFAULT 'requested',
    requested_by     TEXT NOT NULL,
    justification    TEXT,
    approved_by      TEXT,
    approval_note    TEXT,
    rejection_reason TEXT,
    executed_at      TIMESTAMPTZ,
    verified_at      TIMESTAMPTZ,
    evidence         JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_note    TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_actions_case ON response_actions (case_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_actions_type ON response_actions (action_type, created_at DESC);

-- Phase B: case_events.action_id now references response_actions
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_case_events_action'
    ) THEN
        ALTER TABLE case_events
            ADD CONSTRAINT fk_case_events_action
            FOREIGN KEY (action_id) REFERENCES response_actions(id) ON DELETE SET NULL;
    END IF;
END $$;


-- ============================================================
-- QUARANTINED HOSTS -- enforcement state for the quarantine_host action
-- The ingest endpoint refuses events from hosts listed here (fail-closed:
-- a quarantined host's telemetry does not enter the pipeline). Re-enabled
-- by deleting the row; the action's verification re-queries this table.
-- ============================================================
CREATE TABLE IF NOT EXISTS quarantined_hosts (
    host_name      TEXT PRIMARY KEY,
    reason         TEXT,
    quarantined_by TEXT NOT NULL,
    action_id      BIGINT,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quarantined_hosts_at ON quarantined_hosts (quarantined_at DESC);


-- ============================================================
-- AGENT INVESTIGATIONS (V0.4/5 "Agentic SOC") -- durable record of every
-- read-only agentic investigation run.
--
-- Trust boundary: the agent has NO write tools. It reads (NL->SQL SELECT
-- allowlist + parameterized correlation reads) and PROPOSES; it never
-- mutates SIEM state. The SYSTEM writes this run record (and the audit
-- chain rows for every step); the AI verdict is always a DRAFT and the
-- run is born with hitl_state='required' -- only a human (POST
-- /agent/runs/{id}/hitl) moves it to confirmed/rejected. Committing a
-- verdict to a case stays the existing human-only case-verdict path.
--
-- Tamper story: this row is the convenience object; the audit chain
-- (audit_log, DB-enforced append-only in the two-role posture) is the
-- source of truth for what the agent actually did and decided.
-- ============================================================
DO $$ BEGIN
    CREATE TYPE agent_run_status AS ENUM (
        'running', 'completed', 'failed', 'refused'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_investigations (
    id             BIGSERIAL PRIMARY KEY,
    objective      TEXT NOT NULL,
    alert_id       INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    status         agent_run_status NOT NULL DEFAULT 'running',
    actor          TEXT NOT NULL,               -- 'ai:<model>' (executor)
    requested_by   TEXT NOT NULL,               -- human analyst or 'mcp:<client>'
    plan           JSONB NOT NULL DEFAULT '{}'::jsonb,
    steps          JSONB NOT NULL DEFAULT '[]'::jsonb,
    verdict_draft  JSONB,                       -- draft only; never a committed verdict
    hitl_state     TEXT NOT NULL DEFAULT 'not_applicable'
                   CHECK (hitl_state IN ('required', 'confirmed', 'rejected', 'not_applicable')),
    hitl_actor     TEXT,
    hitl_note      TEXT,
    error          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_status ON agent_investigations (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_runs_alert ON agent_investigations (alert_id) WHERE alert_id IS NOT NULL;

-- Controlled-mutation convention: after the executor finalizes a run
-- (status/plan/steps/verdict_draft written once), only hitl_state/hitl_actor/
-- hitl_note/updated_at may change, and only via the HITL endpoint; every
-- transition writes an audit row. Not DB-enforced for this table -- the
-- audit chain is the tamper-evident record (see table header).

-- ============================================================
-- FLEET ENROLLMENTS (V0.5a "Fleet & Scale") -- per-host ingest identity.
--
-- Trust model: each enrolled host holds ONE bearer token. The token maps
-- to exactly one host_name, and the ingest endpoint ENFORCES that every
-- event a fleet token delivers declares THAT host_name -- a stolen fleet
-- token cannot spoof another host (the classic fleet-ingest spoof).
-- Plaintext tokens are never stored: sha256(token) at rest; the plaintext
-- is returned ONCE in the enrollment response. Revocation is immediate
-- (resolved per ingest call) and lands in the audit chain; this row is
-- the convenience object, the audit chain the tamper-evident record.
-- Re-enrollment of an existing host = token rotation (hash replaced,
-- audited) so operators can rotate a suspected token without a 409 dance.
-- ============================================================
CREATE TABLE IF NOT EXISTS fleet_enrollments (
    host_name    TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL,             -- sha256 hex of the bearer token
    enrolled_by  TEXT NOT NULL,             -- admin username that enrolled
    enrolled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,               -- fleet-token ingest activity
    revoked_at   TIMESTAMPTZ,               -- set = token dead immediately
    notes        TEXT
);

-- V0.6a cross-platform fleet: the host's OS family, captured at enrollment
-- (darwin|linux|windows|unknown). Fleet inventory truth + the deploy kit's
-- osquery-config selection input; the server never pushes configs.
-- Idempotent for standing volumes: pre-V0.6a rows carry NULL = unknown.
ALTER TABLE fleet_enrollments ADD COLUMN IF NOT EXISTS platform TEXT;

CREATE INDEX IF NOT EXISTS idx_fleet_enrollments_last_seen
    ON fleet_enrollments (last_seen_at DESC);

-- ============================================================
-- TIMESCALEDB (V0.5c "Fleet & Scale") -- idempotent upgrade block
-- ============================================================
-- W5-E: the logs retention window comes from CONFIG (LOGS_RETENTION_DAYS,
-- default 30), not a hardcoded literal. psql variables are interpolated
-- HERE (outside dollar-quoted blocks — psql cannot interpolate inside
-- them), into a session-level custom GUC the DO block below reads. The
-- entrypoint always passes -v logs_retention_days=<window>; operators
-- applying schema.sql manually must pass the same -v.
-- EMPIRICAL (psql 17, verified 2026-09-24): an UNDEFINED variable is passed
-- through LITERALLY — the server receives the raw :'logs_retention_days'
-- text and errors with "syntax error at or near :" (this broke CI's
-- schema-apply from 541668b). Every caller MUST define the variable.
-- A DEFINED-BUT-EMPTY value (-v logs_retention_days=) does substitute an
-- empty string; the NULLIF+COALESCE guard inside the block converges that
-- to the default rather than crashing the apply.
SET app.logs_retention_days = :'logs_retention_days';

-- No-op on vanilla PostgreSQL (the extension is not available there, so CI's
-- plain postgres service and dev volumes are untouched). When the timescaledb
-- library IS preloaded (docker-compose sets shared_preload_libraries), this
-- block, applied by the OWNER:
--   1. creates the extension,
--   2. converts logs into a 1-day-chunk hypertable (migrate_data => true
--      absorbs the standing volume's existing rows),
--   3. replaces the primary key with (time, id) -- a hypertable's unique
--      constraints must contain the partition key. The identity column keeps
--      generating ids; INSERTs never specify id, so no writer change,
--   4. drops the BRIN index (superseded by chunk exclusion pruning),
--   5. drops the correlation_matches -> logs FK (regular tables cannot
--      reference a hypertable) and replaces it with a plain index,
--   6. adds compression (chunks older than 7 days, segmented per host) and
--      retention (config-driven logs window) policies -- they supersede the
--      BRIN index and the retention job's logs sweep (the job still owns
--      alerts/correlation/ai_usage retention and stays as a fallback).
-- Failures here are LOUD on purpose (no catch-all handler): schema apply
-- runs under ON_ERROR_STOP=1, so a real upgrade failure must stop the boot.
DO $tsdb$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        RAISE NOTICE 'timescaledb not available -- skipping hypertable upgrade (vanilla PostgreSQL)';
        RETURN;
    END IF;
    CREATE EXTENSION IF NOT EXISTS timescaledb;

    -- FKs from regular tables to hypertables are unsupported: drop BEFORE
    -- conversion, replace with a plain index (soft reference).
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'correlation_matches_trigger_event_id_fkey') THEN
        ALTER TABLE correlation_matches
            DROP CONSTRAINT correlation_matches_trigger_event_id_fkey;
    END IF;
    CREATE INDEX IF NOT EXISTS idx_corr_matches_trigger
        ON correlation_matches (trigger_event_id);

    -- PK restructure: (id) -> (time, id)
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'logs_pkey' AND conrelid = 'logs'::regclass) THEN
        ALTER TABLE logs DROP CONSTRAINT logs_pkey;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'logs_time_id_pkey') THEN
        ALTER TABLE logs ADD CONSTRAINT logs_time_id_pkey PRIMARY KEY (time, id);
    END IF;

    -- Convert (migrate_data => true rewrites existing rows into chunks;
    -- on an empty fresh-volume table this is instant; idempotent re-runs
    -- no-op via if_not_exists => true).
    PERFORM create_hypertable('logs', 'time',
        chunk_time_interval => INTERVAL '1 day',
        migrate_data => true,
        if_not_exists => true);

    -- BRIN is superseded by chunk exclusion pruning.
    DROP INDEX IF EXISTS idx_logs_time_brin;

    -- Compression (TimescaleDB 2.30 columnstore API: segmentby/orderby live
    -- on the table reloptions, the policy only schedules it), then policies
    -- (both idempotent via if_not_exists):
    ALTER TABLE logs SET (
        timescaledb.compress = true,
        timescaledb.segmentby = 'host_name',
        timescaledb.orderby = 'time DESC'
    );
    PERFORM add_compression_policy('logs', INTERVAL '7 days', if_not_exists => true);
    -- W5-E: converge the retention policy to the CONFIGURED window on every
    -- boot. add_retention_policy's if_not_exists alone would keep a stale
    -- 30-day policy forever even after LOGS_RETENTION_DAYS changes (the
    -- standing config-drift bug); remove + re-add converges it. The window
    -- is read from the session GUC set above; a missing/empty setting
    -- (manual psql apply without -v) falls back to the documented 30 days.
    PERFORM remove_retention_policy('logs', if_exists => TRUE);
    PERFORM add_retention_policy(
        'logs',
        INTERVAL '1 day' * COALESCE(
            NULLIF(current_setting('app.logs_retention_days', true), '')::int,
            30
        ),
        if_not_exists => true
    );
END
$tsdb$;
