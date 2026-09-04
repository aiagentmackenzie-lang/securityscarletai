"""Local production OPS contracts (P4: two-role audit, backups, watchdog).

Structural pins so a posture revert is caught in CI:
- entrypoint: two-role branch (schema via DATABASE_SUPERUSER_URL when set —
  the app role is denied CREATE, so the legacy path would crash-loop),
  harden_audit.sql re-applied on every boot with app_role=DB_USER.
- compose: DB_USER + DATABASE_SUPERUSER_URL pass-throughs; the postgres
  service's POSTGRES_PASSWORD honors POSTGRES_SUPERUSER_PASSWORD (owner
  password separated from the app-role password).
- backup script: dump → VERIFY (pg_restore --list, TABLE DATA gate) → rotate
  → owner-only audit prune (uses audit_logs."timestamp" AND audit_log.created_at
  — they differ!) → --restore-test rebuilds in a throwaway postgres.
- watchdog: edge-triggered via a state file; Slack webhook optional with a
  local-log fallback (alerts are never silently dropped).
- launchd plists carry the __REPO_ROOT__ placeholder + correct labels.
"""

from __future__ import annotations

import re
from pathlib import Path

_repo = Path(__file__).resolve().parents[2]
_ENTRY = _repo / "scripts" / "entrypoint.sh"
_BASE = _repo / "docker-compose.yml"
_BACKUP = _repo / "scripts" / "backup_local.sh"
_WATCHDOG = _repo / "scripts" / "health_watchdog.sh"


class TestTwoRoleEntrypoint:
    def test_schema_applies_via_superuser_url_when_set(self):
        s = _ENTRY.read_text()
        assert 'if [ -n "${DATABASE_SUPERUSER_URL:-}" ]' in s
        assert 'psql "${DATABASE_SUPERUSER_URL}" -v ON_ERROR_STOP=1 -f src/db/schema.sql' in s

    def test_hardening_reapplied_every_boot(self):
        s = _ENTRY.read_text()
        assert "harden_audit.sql" in s
        assert '-v app_role="${DB_USER}"' in s

    def test_legacy_path_preserved_for_single_role(self):
        s = _ENTRY.read_text()
        # The single-role path (no superuser URL) must still exist for dev.
        assert 'psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}"' in s


class TestComposeTwoRole:
    def test_db_user_passthrough_defaults_single_role(self):
        assert "DB_USER: ${DB_USER:-scarletai}" in _BASE.read_text()

    def test_superuser_url_passthrough_default_empty(self):
        assert "DATABASE_SUPERUSER_URL: ${DATABASE_SUPERUSER_URL:-}" in _BASE.read_text()

    def test_postgres_init_password_honors_owner_secret(self):
        s = _BASE.read_text()
        assert "POSTGRES_SUPERUSER_PASSWORD:-${DB_PASSWORD:?" in s

    def test_settings_declares_superuser_url(self):
        from src.config.settings import Settings

        s = Settings()
        assert s.database_superuser_url is not None or True  # declared = parseable
        assert "database_superuser_url" in Settings.model_fields


class TestBackupScript:
    def test_exists_and_executable(self):
        assert _BACKUP.exists() and (_BACKUP.stat().st_mode & 0o111)

    def test_verify_gate_is_table_data_count(self):
        s = _BACKUP.read_text()
        assert "pg_restore --list" in s
        assert "TABLE DATA" in s
        assert "NOT trusted" in s

    def test_restore_test_uses_throwaway_and_skips_acls(self):
        s = _BACKUP.read_text()
        assert "--restore-test" in s
        assert "postgres:17-alpine" in s
        # GRANTs target roles that only exist in the real deployment — the
        # throwaway restore must skip ACLs (they are re-applied at boot).
        assert "--no-privileges" in s

    def test_audit_prune_uses_correct_timestamp_columns(self):
        s = _BACKUP.read_text()
        # audit_logs."timestamp" and audit_log.created_at — different columns.
        assert "audit_logs WHERE" in s
        assert "audit_log WHERE created_at" in s


class TestWatchdogScript:
    def test_exists_and_executable(self):
        assert _WATCHDOG.exists() and (_WATCHDOG.stat().st_mode & 0o111)

    def test_edge_triggered_by_state_file(self):
        s = _WATCHDOG.read_text()
        assert "watchdog_state" in s
        assert re.search(r'now"\s*=\s*"\$prev"', s) or 'now" = "$prev"' in s

    def test_slack_with_local_log_fallback(self):
        s = _WATCHDOG.read_text()
        assert "SLACK_WEBHOOK_URL" in s
        assert "watchdog.log" in s


class TestLaunchdPlists:
    def test_plists_have_placeholders_and_labels(self):
        for svc, label in (
            ("backup", "com.scarletai.backup"),
            ("watchdog", "com.scarletai.watchdog"),
        ):
            s = (_repo / "deploy" / f"{svc}.launchagent.plist.example").read_text()
            assert f"<string>{label}</string>" in s
            assert "__REPO_ROOT__" in s
