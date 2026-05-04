"""initial_schema_from_sql

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-05-04 00:00:00.000000

H-21 fix: Initial migration from schema.sql.
Previously, Phase 2 migration had down_revision=None which meant
fresh DB setups skipped all base tables. This migration creates them.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial schema from schema.sql."""

    # Enums
    op.execute("CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE alert_status AS ENUM ('new', 'investigating', 'resolved', 'false_positive', 'closed')")
    op.execute("CREATE TYPE case_status AS ENUM ('open', 'in_progress', 'resolved', 'closed')")

    # Logs table
    op.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            time           TIMESTAMPTZ NOT NULL,
            host_name      TEXT NOT NULL,
            host_ip        INET,
            source         TEXT NOT NULL,
            event_category TEXT NOT NULL,
            event_type     TEXT NOT NULL,
            event_action   TEXT,
            user_name      TEXT,
            process_name   TEXT,
            process_pid    INTEGER,
            process_cmdline TEXT,
            process_path   TEXT,
            source_ip      INET,
            destination_ip INET,
            destination_port INTEGER,
            file_path      TEXT,
            file_hash      TEXT,
            raw_data       JSONB NOT NULL,
            normalized     JSONB NOT NULL,
            enrichment     JSONB DEFAULT '{}'::jsonb,
            ingested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # Log indexes
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON logs (time DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host_name, time DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_category ON logs (event_category, time DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON logs (user_name, time DESC) WHERE user_name IS NOT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs (source_ip, time DESC) WHERE source_ip IS NOT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_process ON logs (process_name, time DESC) WHERE process_name IS NOT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_raw_gin ON logs USING GIN (raw_data jsonb_path_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_logs_normalized_gin ON logs USING GIN (normalized jsonb_path_ops)")

    # Rules table
    op.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id             SERIAL PRIMARY KEY,
            name           TEXT NOT NULL UNIQUE,
            description    TEXT,
            sigma_yaml     TEXT NOT NULL,
            generated_sql  TEXT,
            severity       alert_severity NOT NULL DEFAULT 'medium',
            mitre_tactics  TEXT[],
            mitre_techniques TEXT[],
            enabled        BOOLEAN NOT NULL DEFAULT true,
            run_interval   INTERVAL NOT NULL DEFAULT '60 seconds',
            lookback       INTERVAL NOT NULL DEFAULT '5 minutes',
            threshold      INTEGER DEFAULT 1,
            last_run       TIMESTAMPTZ,
            last_match     TIMESTAMPTZ,
            match_count    BIGINT DEFAULT 0,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # Alerts table
    op.execute("""
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
            evidence       JSONB NOT NULL DEFAULT '[]'::jsonb,
            ai_summary     TEXT,
            risk_score     FLOAT,
            assigned_to    TEXT,
            resolved_at    TIMESTAMPTZ,
            case_id        INTEGER,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, severity, time DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts (host_name, time DESC)")

    # Assets table
    op.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id             SERIAL PRIMARY KEY,
            hostname       TEXT NOT NULL UNIQUE,
            ip_addresses   INET[],
            os_type        TEXT,
            os_version     TEXT,
            last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            risk_score     FLOAT DEFAULT 0.0,
            alert_count    INTEGER DEFAULT 0,
            tags           TEXT[],
            metadata       JSONB DEFAULT '{}'::jsonb
        )
    """)

    # Cases table
    op.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id             SERIAL PRIMARY KEY,
            title          TEXT NOT NULL,
            description    TEXT,
            status         case_status NOT NULL DEFAULT 'open',
            severity       alert_severity NOT NULL,
            assigned_to    TEXT,
            alert_ids      INTEGER[],
            notes          JSONB DEFAULT '[]'::jsonb,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # FK: alerts → cases
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'fk_alerts_case'
            ) THEN
                ALTER TABLE alerts ADD CONSTRAINT fk_alerts_case
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL;
            END IF;
        END $$;
    """)

    # SIEM users table
    op.execute("""
        CREATE TABLE IF NOT EXISTS siem_users (
            id             SERIAL PRIMARY KEY,
            username       TEXT NOT NULL UNIQUE,
            email          TEXT UNIQUE,
            password_hash  TEXT NOT NULL,
            role           TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
            is_active      BOOLEAN NOT NULL DEFAULT true,
            last_login     TIMESTAMPTZ,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # Audit log table
    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id             SERIAL PRIMARY KEY,
            actor          TEXT NOT NULL,
            action         TEXT NOT NULL,
            target_type    TEXT,
            target_id      INTEGER,
            old_values     JSONB,
            new_values     JSONB,
            ip_address     TEXT,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor, created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log (target_type, target_id)")

    # Threat intel table
    op.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id             SERIAL PRIMARY KEY,
            ioc_type       TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash_md5', 'hash_sha256', 'url')),
            ioc_value      TEXT NOT NULL,
            source         TEXT NOT NULL,
            threat_type    TEXT,
            confidence     INTEGER CHECK (confidence BETWEEN 0 AND 100),
            first_seen     TIMESTAMPTZ,
            last_seen      TIMESTAMPTZ,
            metadata       JSONB DEFAULT '{}'::jsonb,
            fetched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (ioc_type, ioc_value, source)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup ON threat_intel (ioc_type, ioc_value)")

    # SIEM health table
    op.execute("""
        CREATE TABLE IF NOT EXISTS siem_health (
            time              TIMESTAMPTZ NOT NULL,
            component         TEXT NOT NULL,
            status            TEXT NOT NULL,
            events_per_second FLOAT,
            queue_depth       INTEGER,
            error_count       INTEGER DEFAULT 0,
            details           JSONB DEFAULT '{}'::jsonb
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_health_time ON siem_health (time DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_health_component ON siem_health (component, time DESC)")


def downgrade() -> None:
    """Drop all tables (destructive — only for complete reset)."""
    op.execute("DROP TABLE IF EXISTS siem_health")
    op.execute("DROP TABLE IF EXISTS threat_intel")
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS siem_users")
    op.execute("DROP TABLE IF EXISTS alerts")
    op.execute("DROP TABLE IF EXISTS cases")
    op.execute("DROP TABLE IF EXISTS assets")
    op.execute("DROP TABLE IF EXISTS rules")
    op.execute("DROP TABLE IF EXISTS logs")
    op.execute("DROP TYPE IF EXISTS alert_severity")
    op.execute("DROP TYPE IF EXISTS alert_status")
    op.execute("DROP TYPE IF EXISTS case_status")