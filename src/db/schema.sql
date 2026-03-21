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


-- ============================================================
-- DETECTION RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT,
    sigma_yaml     TEXT NOT NULL,           -- raw Sigma rule YAML
    generated_sql  TEXT,                    -- compiled SQL query
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
    case_id        INTEGER,                -- FK added after cases table exists
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts (host_name, time DESC);


-- ============================================================
-- ASSETS — discovered endpoints
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
    id             SERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT UNIQUE,
    password_hash  TEXT NOT NULL,           -- bcrypt with 12 rounds minimum
    role           TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active      BOOLEAN NOT NULL DEFAULT true,
    last_login     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


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
-- SIEM HEALTH — self-observability (who watches the watchers?)
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
