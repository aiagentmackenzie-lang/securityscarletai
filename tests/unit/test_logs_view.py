"""Contract tests for the Log Viewer time-range options (feat/logs-viewer-time-ranges).

The view's selectbox options and the minutes lookup were previously two
independent literals inside render_log_viewer() — a drifted pair silently
fell back to 60 minutes via `.get(time_range, 60)`. Both are now module-level
constants with a consistency contract.
"""

from dashboard.logs_view import LOG_TIME_MINUTES, LOG_TIME_RANGES


class TestLogTimeRanges:
    """Every selectbox option must have exactly one lookup entry."""

    def test_options_and_map_are_in_sync(self):
        assert sorted(LOG_TIME_RANGES) == sorted(LOG_TIME_MINUTES.keys())
        assert len(LOG_TIME_RANGES) == len(set(LOG_TIME_RANGES))

    def test_widened_ranges_present(self):
        """3d / 7d / All time exist — seeded data older than 24h is visible."""
        assert "Last 3 days" in LOG_TIME_RANGES
        assert "Last 7 days" in LOG_TIME_RANGES
        assert "All time" in LOG_TIME_RANGES

    def test_minute_values(self):
        assert LOG_TIME_MINUTES["Last 15 minutes"] == 15
        assert LOG_TIME_MINUTES["Last 1 hour"] == 60
        assert LOG_TIME_MINUTES["Last 6 hours"] == 360
        assert LOG_TIME_MINUTES["Last 24 hours"] == 1440
        assert LOG_TIME_MINUTES["Last 3 days"] == 4320
        assert LOG_TIME_MINUTES["Last 7 days"] == 10080

    def test_all_time_maps_to_none(self):
        """None → get_logs omits time_minutes → API returns most recent rows
        overall (bounded by limit), no 24h-style cap."""
        assert LOG_TIME_MINUTES["All time"] is None

    def test_no_hidden_fallback(self):
        """Every option has a mapping — .get() default can never mask a typo."""
        for option in LOG_TIME_RANGES:
            assert option in LOG_TIME_MINUTES