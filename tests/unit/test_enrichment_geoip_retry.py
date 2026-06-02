"""
Tests for Epic 9 GeoIP singleton retry behavior.

The pre-Epic-9 implementation set ``_geoip_loaded = True`` BEFORE the
try/except, so a single init failure (missing DB file, perms, etc.)
permanently marked the singleton as loaded and we'd never retry. These
tests pin the new behavior: failed init must NOT set the flag, and a
subsequent call (after the retry interval) must re-attempt.

Implementation note: we deliberately do NOT call ``importlib.reload`` or
delete ``sys.modules`` to reset state — doing so would invalidate
patches that other test modules (e.g. test_enrichment_pipeline.py) have
applied to the pipeline module. Instead we manipulate the module-level
flags directly, which is safe because we restore them in a fixture.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

import src.enrichment.pipeline as pipeline


@pytest.fixture
def _reset_geoip_state():
    """Snapshot and restore the module-level GeoIP singleton state
    so tests don't leak into each other (or into other test modules
    that share this module's namespace).
    """
    saved_reader = pipeline._geoip_reader
    saved_loaded = pipeline._geoip_loaded
    saved_last = pipeline._geoip_last_attempt
    pipeline._geoip_reader = None
    pipeline._geoip_loaded = False
    pipeline._geoip_last_attempt = 0.0
    try:
        yield
    finally:
        pipeline._geoip_reader = saved_reader
        pipeline._geoip_loaded = saved_loaded
        pipeline._geoip_last_attempt = saved_last


class TestGeoipRetryOnMissingDb:
    def test_missing_db_does_not_permanently_mark_loaded(self, _reset_geoip_state):
        """If the .mmdb is missing, the next call (after the retry
        interval) must retry, not silently return None forever.
        """
        # Patch the reader constructor to raise FileNotFoundError every
        # time, simulating a permanently-missing DB.
        fake_reader_mod = MagicMock()
        fake_reader_mod.database.Reader.side_effect = FileNotFoundError(
            "data/GeoLite2-City.mmdb"
        )
        with patch.dict(sys.modules, {"geoip2": fake_reader_mod, "geoip2.database": fake_reader_mod.database}):
            # First call: tries to open, fails, returns None.
            assert pipeline._get_geoip_reader() is None
            assert pipeline._geoip_loaded is False, (
                "After init failure, _geoip_loaded must remain False so "
                "future calls can retry"
            )

            # Force the throttle to expire so the next call actually retries.
            pipeline._geoip_last_attempt = 0.0
            # Second call: must attempt the init again, not short-circuit.
            assert pipeline._get_geoip_reader() is None
            assert fake_reader_mod.database.Reader.call_count == 2

    def test_successful_init_sets_loaded(self, _reset_geoip_state):
        """If the .mmdb opens cleanly, _geoip_loaded must be True so we
        don't re-open on every event."""
        fake_reader = MagicMock()
        fake_reader_mod = MagicMock()
        fake_reader_mod.database.Reader.return_value = fake_reader
        with patch.dict(sys.modules, {"geoip2": fake_reader_mod, "geoip2.database": fake_reader_mod.database}):
            reader = pipeline._get_geoip_reader()
            assert reader is fake_reader
            assert pipeline._geoip_loaded is True

            # Second call should be a no-op (no new Reader() invocation).
            pipeline._get_geoip_reader()
            assert fake_reader_mod.database.Reader.call_count == 1

    def test_retry_throttled_within_interval(self, _reset_geoip_state):
        """Two back-to-back failed calls within the retry interval must
        only hit the FS once — the second is throttled."""
        fake_reader_mod = MagicMock()
        fake_reader_mod.database.Reader.side_effect = FileNotFoundError("nope")
        with patch.dict(sys.modules, {"geoip2": fake_reader_mod, "geoip2.database": fake_reader_mod.database}):
            pipeline._get_geoip_reader()  # First attempt
            # Second attempt within window — must be throttled
            pipeline._get_geoip_reader()
            assert fake_reader_mod.database.Reader.call_count == 1

    def test_close_resets_state(self, _reset_geoip_state):
        """close_geoip_reader() must clear _geoip_loaded and the retry
        timestamp so a subsequent call can re-open a fresh reader.
        """
        fake_reader = MagicMock()
        fake_reader_mod = MagicMock()
        fake_reader_mod.database.Reader.return_value = fake_reader
        with patch.dict(sys.modules, {"geoip2": fake_reader_mod, "geoip2.database": fake_reader_mod.database}):
            pipeline._get_geoip_reader()
            assert pipeline._geoip_loaded is True

            pipeline.close_geoip_reader()
            assert pipeline._geoip_loaded is False
            assert pipeline._geoip_last_attempt == 0.0
            assert pipeline._geoip_reader is None

            fake_reader.close.assert_called_once()
