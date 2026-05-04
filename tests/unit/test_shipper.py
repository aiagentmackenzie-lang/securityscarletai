"""
Tests for ingestion shipper and schemas.

Covers:
- LogWriter initialization
- NormalizedEvent validation
- FileShipper checkpoint handling
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.ingestion.schemas import NormalizedEvent
from src.db.writer import LogWriter


class TestLogWriter:
    """Test LogWriter class (from src.db.writer)."""

    def test_init(self):
        """LogWriter should initialize with default values."""
        writer = LogWriter()
        assert writer is not None


class TestNormalizedEvent:
    """Test NormalizedEvent schema."""

    def test_create_minimal_event(self):
        """Should create a minimal event with required fields."""
        event = NormalizedEvent(
            timestamp=datetime.now(tz=timezone.utc),
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
            raw_data={"original": "data"},
        )
        assert event.host_name == "server01"
        assert event.source == "syslog"

    def test_create_full_event(self):
        """Should create an event with all fields."""
        now = datetime.now(tz=timezone.utc)
        event = NormalizedEvent(
            timestamp=now,
            host_name="server01",
            source="syslog",
            event_category="authentication",
            event_type="login",
            event_action="logon",
            user_name="admin",
            process_name="sshd",
            process_pid=1234,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            destination_port=22,
            file_path="/var/log/auth.log",
            file_hash="abc123def456",
            severity="high",
            raw_data={"key": "value"},
            enrichment={"threat_intel": {"match": True}},
        )
        assert event.user_name == "admin"
        assert event.source_ip == "10.0.0.1"
        assert event.enrichment["threat_intel"]["match"] is True

    def test_optional_fields_default_none(self):
        """Optional fields should default to None."""
        event = NormalizedEvent(
            timestamp=datetime.now(tz=timezone.utc),
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
            raw_data={},
        )
        assert event.user_name is None
        assert event.source_ip is None
        assert event.destination_ip is None
        assert event.process_name is None
        assert event.file_path is None

    def test_enrichment_default(self):
        """Enrichment should default to empty dict."""
        event = NormalizedEvent(
            timestamp=datetime.now(tz=timezone.utc),
            host_name="server",
            source="syslog",
            event_category="process",
            event_type="start",
            raw_data={},
        )
        assert event.enrichment == {}

    def test_raw_data_required(self):
        """raw_data should be required."""
        with pytest.raises(Exception):
            NormalizedEvent(
                timestamp=datetime.now(tz=timezone.utc),
                host_name="server",
                source="syslog",
                event_category="process",
                event_type="start",
            )

    def test_severity_optional(self):
        """Severity should be optional."""
        event = NormalizedEvent(
            timestamp=datetime.now(tz=timezone.utc),
            host_name="server",
            source="syslog",
            event_category="process",
            event_type="start",
            raw_data={},
        )
        assert event.severity is None


class TestFileShipper:
    """Test FileShipper checkpoint handling."""

    def test_checkpoint_load_handles_missing_file(self):
        """Should return 0 if checkpoint file missing."""
        from src.ingestion.shipper import FileShipper
        writer = LogWriter()
        shipper = FileShipper("/nonexistent/path.log", writer)
        assert shipper._offset == 0

    def test_checkpoint_load_handles_invalid_content(self, tmp_path):
        """Should return 0 if checkpoint content is invalid."""
        from src.ingestion.shipper import FileShipper, CHECKPOINT_FILE
        writer = LogWriter()
        # Write invalid checkpoint
        invalid_file = tmp_path / "checkpoint"
        invalid_file.write_text("not_a_number")

        with patch("src.ingestion.shipper.CHECKPOINT_FILE", invalid_file):
            shipper = FileShipper("/tmp/fake.log", writer)
            assert shipper._offset == 0

    def test_checkpoint_load_valid(self, tmp_path):
        """Should load valid checkpoint."""
        from src.ingestion.shipper import FileShipper
        writer = LogWriter()
        checkpoint = tmp_path / "checkpoint"
        checkpoint.write_text("12345")

        with patch("src.ingestion.shipper.CHECKPOINT_FILE", checkpoint):
            shipper = FileShipper("/tmp/fake.log", writer)
            assert shipper._offset == 12345

    def test_checkpoint_save(self, tmp_path):
        """Should save checkpoint."""
        from src.ingestion.shipper import FileShipper
        writer = LogWriter()
        checkpoint = tmp_path / "checkpoint"

        with patch("src.ingestion.shipper.CHECKPOINT_FILE", checkpoint):
            shipper = FileShipper("/tmp/fake.log", writer)
            shipper._offset = 9999
            shipper._save_checkpoint()
            assert checkpoint.read_text() == "9999"