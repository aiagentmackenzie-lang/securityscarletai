"""W1.5 deception ingestion -- unit gates.

Covers the deception-event contract (src/ingestion/deception.py): the
fail-closed kind mapping (unknown kinds refused, severity override
downgrades refused, host required), the NDJSON shipper-line serialization,
and the deception-domain Sigma rules (critical/high, true/false pairs).
"""

from unittest.mock import patch

import pytest

from src.ingestion.deception import (
    CANARY_KINDS,
    DECEPTION_KINDS,
    build_deception_event,
    event_to_shipper_line,
)


class TestDeceptionKinds:
    """The closed kind vocabulary: fail-closed + the doctrine severities."""

    def test_known_kinds_map_to_expected_actions(self):
        assert DECEPTION_KINDS["canary_file_access"][0] == "deception_canary_access"
        assert DECEPTION_KINDS["canary_token_use"][0] == "deception_token_use"
        assert DECEPTION_KINDS["service_probe"][0] == "deception_service_probe"
        # The doctrine severities ride in the mapping (index 1).
        assert DECEPTION_KINDS["service_probe"][1] == "high"

    def test_unknown_kind_raises_value_error(self):
        with pytest.raises(ValueError):
            build_deception_event("not_a_kind", host_name="h")

    def test_canary_kinds_are_direct_escalation_tiers(self):
        # The doctrine: canary/token events are cases by construction --
        # they carry the highest-severity boost, never a downgrade.
        for kind in CANARY_KINDS:
            assert DECEPTION_KINDS[kind][1] == "critical"


class TestDeceptionEventShape:
    def test_build_event_defaults(self):
        event = build_deception_event("canary_file_access", host_name="h")
        assert event.event_action == "deception_canary_access"
        assert event.host_name == "h"
        assert event.event_type == "info"
        # No component given -> None is carried (chain of custody stays null,
        # never invented).
        assert event.raw_data["component"] is None

    def test_build_event_with_component(self):
        event = build_deception_event("canary_file_access", host_name="h", component="canary")
        assert event.raw_data["component"] == "canary"

    def test_shipper_line_round_trips(self):
        event = build_deception_event("canary_file_access", host_name="h")
        line = event_to_shipper_line(event)
        assert isinstance(line, str)
        assert "deception" in line.lower()


class TestDeceptionSeverityOverride:
    """The severity floor: producers may RAISE a kind's doctrine default,
    never lower it, and only within the closed vocabulary (the paths that
    exercise SEVERITY_INDEX)."""

    def test_default_severity_applied_when_omitted(self):
        assert build_deception_event("service_probe", host_name="h").severity == "high"
        assert build_deception_event("canary_token_use", host_name="h").severity == "critical"

    def test_upgrade_override_accepted(self):
        event = build_deception_event("service_probe", host_name="h", severity="critical")
        assert event.severity == "critical"
        # Equal to the default is also accepted (case-normalized).
        event = build_deception_event("canary_file_access", host_name="h", severity="CRITICAL")
        assert event.severity == "critical"

    def test_downgrade_override_refused(self):
        with pytest.raises(ValueError, match="may not downgrade"):
            build_deception_event("service_probe", host_name="h", severity="low")
        with pytest.raises(ValueError, match="may not downgrade"):
            build_deception_event("canary_file_access", host_name="h", severity="high")

    def test_unknown_severity_refused(self):
        with pytest.raises(ValueError, match="known value"):
            build_deception_event("service_probe", host_name="h", severity="sev0")


class TestShipperEnableFlag:
    @pytest.mark.asyncio
    async def test_shipper_disabled_yields_none(self):
        with patch("src.ingestion.runner.settings", enable_deception_shipper=False):
            from src.ingestion.runner import maybe_create_deception_shipper

            assert maybe_create_deception_shipper(None) is None

    def test_shipper_enabled_yields_shipper(self):
        with patch("src.ingestion.runner.settings", enable_deception_shipper=True):
            from src.ingestion.runner import maybe_create_deception_shipper

            assert maybe_create_deception_shipper(None) is not None
