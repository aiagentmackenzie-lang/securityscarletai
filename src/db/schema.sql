-- ============================================================
-- SecurityScarletAI Database Schema
-- PostgreSQL 17 (TimescaleDB compatible for future upgrade)
-- ============================================================

-- Severity enum — never use magic integers
CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE alert_status AS ENUM ('new', 'investigating', 'resolved', 'false_positive', 'closed');
CREATE TYPE case_status AS ENUM ('open', 'in_progress', 'resolved', 'closed');

-- ============================================================
-- LOGS — partitioned by time via table partitioning (TimescaleDB upgrade: use hypertable)
-- ============================================================
CREATE TABLE IF NOT EXISTS logs (
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
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_logs_time ON logs (time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_category ON logs (event_category, time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_user ON logs (user_name, time DESC) WHERE user_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs (source_ip, time DESC) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_process ON logs (process_name, time DESC) WHERE process_name IS NOT NULL;
-- GIN index for JSONB full-text search on raw data
CREATE INDEX IF NOT EXISTS idx_logs_raw_gin ON logs USING GIN (raw_data jsonb_path_ops);
-- GIN index for normalized JSONB column (supports process_cmdline, process_path, etc.)
CREATE INDEX IF NOT EXISTS idx_logs_normalized_gin ON logs USING GIN (normalized jsonb_path_ops);


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
-- ASSETS — discovered endpoints (L-07: placeholder, not yet used in code)
-- ============================================================
CREATE TABLE IF NOT EXISTS assets (
    id             SERIAL PRIMARY KEY,
    hostname       TEXT NOT NULL UNIQUE,
    ip_addresses   INET[],
    os_type        TEXT,                    -- 'macOS', 'Linux', 'Windows'
    os_version     TEXT,
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score     FLOAT DEFAULT 0.0,
    alert_count    INTEGER DEFAULT 0,
    tags           TEXT[],
    metadata       JSONB DEFAULT '{}'::jsonb
);


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
-- SIEM HEALTH — self-observability (L-08: placeholder, not yet written to in code)
-- Who watches the watchers? This table is for future health metrics collection.
-- ============================================================
CREATE TABLE IF NOT EXISTS siem_health (
    time              TIMESTAMPTZ NOT NULL,
    component         TEXT NOT NULL,        -- 'shipper', 'detection', 'api', 'enrichment'
    status            TEXT NOT NULL,        -- 'healthy', 'degraded', 'down'
    events_per_second FLOAT,
    queue_depth       INTEGER,
    error_count       INTEGER DEFAULT 0,
    details           JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_health_time ON siem_health (time DESC);
CREATE INDEX IF NOT EXISTS idx_health_component ON siem_health (component, time DESC);

-- NOTE: To upgrade to TimescaleDB later, run:
-- CREATE EXTENSION timescaledb;
-- SELECT create_hypertable('logs', 'time', chunk_time_interval => INTERVAL '1 day');
-- SELECT create_hypertable('siem_health', 'time', chunk_time_interval => INTERVAL '1 day');


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
    trigger_event_id INT REFERENCES logs(id),
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
-- Permission hardening (run as superuser, NOT as the app role):
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM scarletai;
--   GRANT  INSERT, SELECT            ON audit_logs TO   scarletai;
-- This prevents a compromised app from rewriting or deleting its own
-- audit trail. Documented here because the table is append-only by design.
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
