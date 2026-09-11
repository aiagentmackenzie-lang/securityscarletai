"""Unit tests -- V0.3 identity/auth telemetry + normalized shipper format."""

import json

import pytest

from scripts.auth_log_shipper import parse_sshd_message, ship_events
from src.ingestion.auth_source import (
    AUTH_ACTIONS,
    build_auth_event,
    event_to_shipper_line,
)
from src.ingestion.schemas import parse_normalized_line


class TestAuthEventContract:
    """The closed auth-vocabulary contract (src/ingestion/auth_source.py)."""

    def test_failed_outcome_maps_to_auth_failed(self):
        ev = build_auth_event(
            timestamp="2026-09-11T12:00:00+00:00",
            host_name="mac.local",
            outcome="failed",
            user_name="admin",
            source_ip="185.10.1.2",
            raw_message="Failed password for admin from 185.10.1.2 port 51234 ssh2",
        )
        assert ev.event_action == "auth_failed"
        assert ev.event_category == "authentication"
        assert ev.user_name == "admin"
        assert ev.source_ip == "185.10.1.2"
        assert ev.raw_data["shipper"] == "auth_shipper"

    def test_success_outcome_maps_to_auth_success(self):
        ev = build_auth_event(
            timestamp="2026-09-11T12:00:00+00:00",
            host_name="mac.local",
            outcome="success",
            user_name="admin",
            source_ip="185.10.1.2",
        )
        assert ev.event_action == "auth_success"

    def test_unknown_outcome_fail_closed(self):
        with pytest.raises(ValueError):
            build_auth_event(
                timestamp="2026-09-11T12:00:00+00:00",
                host_name="mac.local",
                outcome="denied",  # not in the contract
            )

    def test_vocabulary_is_closed(self):
        assert set(AUTH_ACTIONS) == {"auth_failed", "auth_success"}

    def test_shipper_line_roundtrip(self):
        ev = build_auth_event(
            timestamp="2026-09-11T12:00:00+00:00",
            host_name="mac.local",
            outcome="failed",
            user_name="root",
            source_ip="10.0.0.9",
        )
        line = event_to_shipper_line(ev)
        parsed = parse_normalized_line(line)
        assert parsed is not None
        assert parsed.event_action == "auth_failed"
        assert parsed.user_name == "root"
        assert parsed.source_ip == "10.0.0.9"
        assert parsed.raw_data["shipper"] == "auth_shipper"


class TestParseNormalizedLine:
    """Normalized NDJSON parser (FileShipper format=\"normalized\")."""

    BASE = {
        "@timestamp": "2026-09-11T12:00:00Z",
        "host_name": "h",
        "event_category": "authentication",
        "event_type": "start",
        "event_action": "auth_failed",
        "source": "auth_shipper",
        "user_name": "admin",
        "source_ip": "1.2.3.4",
    }

    def _line(self, **overrides):
        data = {**self.BASE, **overrides}
        return json.dumps(data)

    def test_valid_line_parses(self):
        ev = parse_normalized_line(self._line())
        assert ev is not None
        assert ev.event_action == "auth_failed"
        assert ev.source_ip == "1.2.3.4"

    def test_missing_required_field_is_skipped(self):
        for field in ("host_name", "event_category", "event_type", "source"):
            line = self._line(**{field: ""})
            assert parse_normalized_line(line) is None, f"missing {field} must skip"

    def test_garbage_is_skipped_never_raises(self):
        assert parse_normalized_line("not json") is None
        assert parse_normalized_line('["array","not","object"]') is None

    def test_timestamp_defaults_to_now_when_absent(self):
        ev = parse_normalized_line(self._line(**{"@timestamp": None}))
        assert ev is not None
        assert ev.timestamp.year >= 2026

    def test_non_dict_raw_data_wrapped(self):
        line = self._line(raw_data="not a dict")
        ev = parse_normalized_line(line)
        assert ev is not None
        assert isinstance(ev.raw_data, dict)


class TestSshdMessageParser:
    """Real sshd unified-log message shapes."""

    def test_failed_password(self):
        assert parse_sshd_message("Failed password for admin from 185.10.1.2 port 51234 ssh2") == (
            "failed",
            "admin",
            "185.10.1.2",
        )

    def test_failed_password_invalid_user(self):
        assert parse_sshd_message(
            "Failed password for invalid user oracle from 185.10.1.2 port 40222 ssh2"
        ) == ("failed", "oracle", "185.10.1.2")

    def test_invalid_user_preauth(self):
        assert parse_sshd_message("Invalid user nagios from 198.51.100.7 port 33090") == (
            "failed",
            "nagios",
            "198.51.100.7",
        )

    def test_accepted_publickey(self):
        assert parse_sshd_message(
            "Accepted publickey for mackenzie from 192.168.1.4 port 51000 ssh2: ED25519 SHA256:xyz"
        ) == ("success", "mackenzie", "192.168.1.4")

    def test_noise_returns_none(self):
        assert parse_sshd_message("Connection closed by 10.0.0.2 port 51000") is None
        assert parse_sshd_message("subsystem request for sftp") is None


class TestWatermarkDedup:
    """Overlapping launchd windows must not double-ship events."""

    def _entry(self, ts: str, message: str):
        return {"timestamp": ts, "eventMessage": message}

    def test_events_strictly_newer_than_watermark_only(self, tmp_path):
        entries = [
            self._entry("2026-09-11T12:00:00Z", "Failed password for a from 1.2.3.4 port 1 ssh2"),
            self._entry("2026-09-11T12:01:00Z", "Failed password for a from 1.2.3.4 port 2 ssh2"),
        ]
        out = str(tmp_path / "auth_events.log")
        count, wm = ship_events(entries, "h", watermark=None, output_path=out)
        assert count == 2
        # Second run, same window overlapped: watermark at 12:01 -- both rows
        # are <= watermark, nothing re-emitted.
        count2, wm2 = ship_events(entries, "h", watermark=wm, output_path=out)
        assert count2 == 0
        assert wm2 == wm

    def test_newer_event_passes_watermark(self, tmp_path):
        entries = [
            self._entry("2026-09-11T12:02:00Z", "Accepted password for a from 1.2.3.4 port 3 ssh2"),
        ]
        out = str(tmp_path / "auth_events.log")
        count, _ = ship_events(entries, "h", watermark=1760182800.0, output_path=out)
        assert count == 1

    def test_brute_force_sequence_emits_correct_actions(self, tmp_path):
        """The exact true/false event matrix shape for brute_force_success."""
        entries = [
            self._entry(
                f"2026-09-11T12:0{i}:00Z",
                "Failed password for admin from 185.10.1.2 port 5%d ssh2" % i,
            )
            for i in range(3)
        ] + [
            self._entry(
                "2026-09-11T12:03:00Z",
                "Accepted password for admin from 185.10.1.2 port 53 ssh2",
            )
        ]
        out = str(tmp_path / "auth_events.log")
        count, _ = ship_events(entries, "mac.local", watermark=None, output_path=out)
        assert count == 4
        lines = open(out).read().strip().splitlines()
        actions = [json.loads(ln)["event_action"] for ln in lines]
        assert actions == ["auth_failed"] * 3 + ["auth_success"]
