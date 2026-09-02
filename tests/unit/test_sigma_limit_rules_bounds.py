"""P2.8 — Sigma query LIMIT + rules API validation.

- Simple detection queries now carry a bounded LIMIT (MAX_DETECTION_ROWS):
  a broad rule on a chatty host used to fetch unbounded rows per run.
- Rules API bounds: run_interval ≥30s (a 1s interval hammered the DB with
  heavy window queries), lookback ≤24h, threshold ≥1, severity restricted
  to the known enum (off-enum values used to 500 on the DB enum).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.detection.sigma import MAX_DETECTION_ROWS, sigma_to_sql

_SIMPLE_RULE = """
title: Test Simple Rule
logsource:
    category: process_creation
detection:
    selection:
        event_action: "executed"
    condition: selection
"""


class TestSigmaQueryLimit:
    def test_simple_query_carries_limit_param(self):
        sql, params = sigma_to_sql(_SIMPLE_RULE)
        assert "LIMIT" in sql
        # the limit is a BOUND PARAMETER, not an inline literal
        assert MAX_DETECTION_ROWS in params

    def test_limit_value_is_the_module_cap(self):
        sql, params = sigma_to_sql(_SIMPLE_RULE)
        limit_idx = params.index(MAX_DETECTION_ROWS)
        assert limit_idx == len(params) - 1  # appended last
        assert sql.rstrip().endswith(f"LIMIT ${len(params)}")


class TestRuleModelBounds:
    def test_run_interval_below_30_rejected(self):
        with pytest.raises(ValidationError):
            from src.api.rules import RuleCreate

            RuleCreate(
                name="t", sigma_yaml="title: t\ndetection:\n    condition: selection",
                run_interval=1,
            )

    def test_run_interval_at_30_accepted(self):
        from src.api.rules import RuleCreate

        r = RuleCreate(
            name="t",
            sigma_yaml="title: t\ndetection:\n    condition: selection",
            run_interval=30,
        )
        assert r.run_interval == 30

    def test_lookback_over_24h_rejected(self):
        from src.api.rules import RuleCreate

        with pytest.raises(ValidationError):
            RuleCreate(
                name="t",
                sigma_yaml="title: t\ndetection:\n    condition: selection",
                lookback=10**7,
            )

    def test_lookback_at_24h_accepted(self):
        from src.api.rules import RuleCreate

        r = RuleCreate(
            name="t",
            sigma_yaml="title: t\ndetection:\n    condition: selection",
            lookback=86400,
        )
        assert r.lookback == 86400

    def test_threshold_below_1_rejected(self):
        from src.api.rules import RuleCreate

        with pytest.raises(ValidationError):
            RuleCreate(
                name="t",
                sigma_yaml="title: t\ndetection:\n    condition: selection",
                threshold=0,
            )

    def test_bad_severity_rejected(self):
        from src.api.rules import RuleCreate

        with pytest.raises(ValidationError) as exc:
            RuleCreate(
                name="t",
                sigma_yaml="title: t\ndetection:\n    condition: selection",
                severity="catastrophic",
            )
        assert "severity" in str(exc.value)

    def test_patch_bounds(self):
        from src.api.rules import RulePatch

        with pytest.raises(ValidationError):
            RulePatch(run_interval=1)
        with pytest.raises(ValidationError):
            RulePatch(lookback=10**7)
        with pytest.raises(ValidationError):
            RulePatch(threshold=0)
        with pytest.raises(ValidationError):
            RulePatch(severity="apocalyptic")
        # valid patch values pass
        ok = RulePatch(run_interval=60, lookback=600, threshold=2, severity="high")
        assert ok.run_interval == 60 and ok.severity == "high"

    def test_patch_none_fields_still_valid(self):
        """All-optional patch body (empty patch) remains valid."""
        from src.api.rules import RulePatch

        assert RulePatch().severity is None
        assert RulePatch().run_interval is None
