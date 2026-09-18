"""Local production telemetry wiring (P4 phase 1, 2026-09-04).

Pins the real-telemetry pipe so a revert is caught in CI:
- compose api service: shipper env pass-through + read-only osquery mount
- config/osquery.conf: valid JSON; every schedule name is ECS-mapped or a
  documented compliance table; no root-only paths baked into the conf
- settings: shipper checkpoint defaults to the persistent data/ path
"""

from __future__ import annotations

import json
from pathlib import Path

from src.ingestion.schemas import OSQUERY_ECS_MAP

_repo = Path(__file__).resolve().parents[2]
_COMPOSE = _repo / "docker-compose.yml"
_OSCONF = _repo / "config" / "osquery.conf"
_OSLINUX = _repo / "config" / "osquery.linux.conf"
_FIMCONF = _repo / "config" / "osquery-fim.conf"


def _api_section() -> str:
    s = _COMPOSE.read_text()
    return s.split("  api:")[1].split("\n  dashboard:")[0]


class TestComposeTelemetryPipe:
    """The API service must carry the full shipper wiring (file-content pins,
    matching the test_prod_deploy_hardening house style)."""

    def test_shipper_env_passthrough_default_off(self):
        s = _api_section()
        assert "ENABLE_INGESTION_SHIPPER: ${ENABLE_INGESTION_SHIPPER:-false}" in s

    def test_container_osquery_log_path_set(self):
        s = _api_section()
        assert "OSQUERY_LOG_PATH: /app/osquery/osqueryd.results.log" in s

    def test_osquery_mount_is_read_only(self):
        s = _api_section()
        assert "${OSQUERY_LOG_DIR:-./data/osquery}:/app/osquery:ro" in s

    def test_ingest_and_metrics_token_passthroughs(self):
        s = _api_section()
        assert "INGEST_BEARER_TOKEN: ${INGEST_BEARER_TOKEN:-}" in s
        assert "METRICS_BEARER_TOKEN: ${METRICS_BEARER_TOKEN:-}" in s

    def test_retention_passthroughs(self):
        s = _api_section()
        for var in (
            "LOGS_RETENTION_DAYS",
            "ALERTS_RETENTION_DAYS",
            "AUDIT_RETENTION_DAYS",
            "CORRELATION_RETENTION_DAYS",
            "AI_USAGE_RETENTION_DAYS",
        ):
            assert f"{var}: ${{{var}:-" in s


class TestOsqueryConf:
    """Every scheduled query name must survive the parser; every path must be
    launch-flag owned (the conf is machine-independent)."""

    def test_conf_is_valid_json_with_schedule(self):
        conf = json.loads(_OSCONF.read_text())
        assert conf.get("schedule")

    def test_every_schedule_name_reaches_the_parser(self):
        conf = json.loads(_OSCONF.read_text())
        # P2-37: compliance tables are scheduled but intentionally unmapped —
        # dropped by parse_osquery_line as unmapped_table, never force-cast.
        # browser_plugins was REMOVED from the schedule entirely (empty and
        # deprecated on modern macOS — verified live, 2026-09-04).
        unmapped_ok = {"disk_encryption"}
        for name in conf["schedule"]:
            assert name in OSQUERY_ECS_MAP or name in unmapped_ok, name

    def test_no_root_only_paths_in_conf(self):
        conf = json.loads(_OSCONF.read_text())
        opts = conf.get("options", {})
        # These are LaunchAgent CLI flags (machine-specific, user-writable):
        # baking them into the conf broke the user-agent boot (pidfile check
        # failed against /var/osquery — root-only).
        for forbidden in (
            "logger_path",
            "database_path",
            "pidfile",
            "extensions_socket",
            "logger_mode",
        ):
            assert forbidden not in opts, forbidden
        s = _OSCONF.read_text()
        assert "/var/osquery" not in s

    def test_launchagent_example_has_required_flags(self):
        s = (_repo / "deploy" / "osqueryd.launchagent.plist.example").read_text()
        for flag in (
            "--config_path=",
            "--logger_path=",
            "--database_path=",
            "--pidfile=",
            "--logger_mode=0644",
            "--extensions_socket=",
        ):
            assert flag in s
        # The bare-binary copy trap: osqueryd must run from inside its .app
        # bundle (signature covers bundle resources; a standalone copy is
        # killed at exec by macOS).
        assert "osquery.app/Contents/MacOS/osqueryd" in s
        assert "__REPO_ROOT__" in s and "__HOME__" in s  # placeholders intact


class TestShipperCheckpointPath:
    def test_default_checkpoint_is_persistent_data_path(self):
        from src.config.settings import Settings

        s = Settings()
        assert s.shipper_checkpoint_path == "data/shipper_checkpoint"


class TestOsqueryConfQueryHygiene:
    """AUD-075: scheduled SELECTs must not list the same column twice (the
    disk_encryption tables carried `encrypted` twice in both configs —
    harmless in SQLite output, sloppy everywhere else)."""

    @staticmethod
    def _duplicate_columns(query: str) -> set[str]:
        select_clause = query.split("FROM")[0].upper()
        cols = [c.strip() for c in select_clause.replace("SELECT", "").split(",")]
        return {c for c in cols if cols.count(c) > 1}

    def test_mac_conf_no_duplicate_select_columns(self):
        conf = json.loads(_OSCONF.read_text())
        for name, sched in conf["schedule"].items():
            assert not self._duplicate_columns(sched["query"]), f"{name}: duplicate column"

    def test_linux_conf_no_duplicate_select_columns(self):
        conf = json.loads(_OSLINUX.read_text())
        for name, sched in conf["schedule"].items():
            assert not self._duplicate_columns(sched["query"]), f"{name}: duplicate column"


class TestFimOverlayCommentHonesty:
    """AUD-073: the FIM overlay's validation comment claimed es_process_events
    is 'NOT parsed by the SIEM yet (backlog)' — stale: schemas.py maps it and
    the promoted osquery.conf schedules it. Its file_events description also
    pointed at 'file_events.files above', which the same comment says is wrong.
    """

    def test_no_stale_es_process_events_claim(self):
        s = _FIMCONF.read_text()
        assert "es_process_events is NOT parsed by the SIEM yet" not in s
        # The corrected comment states the mapping landed.
        assert "IS parsed by the SIEM now" in s

    def test_file_events_description_points_at_real_keys(self):
        s = _FIMCONF.read_text()
        conf = json.loads(s)
        description = conf["schedule"]["file_events"]["description"]
        assert "file_events.files" not in description
        assert "file_paths/exclude_paths below" in description
