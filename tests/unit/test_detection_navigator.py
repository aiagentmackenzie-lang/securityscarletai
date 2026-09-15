"""W1.9 ATT&CK Navigator layer export -- unit gates.

Covers the layer-file construction against the official v4.5 spec (versions,
domain, required keys), the per-technique score math (armed ratio 0-100),
the FP-ratio aggregate (disposition-weighted, unmeasured excluded -- the
honesty gate), comment hygiene (capped rule names, stable sort), and the
endpoint wiring.
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from src.detection.navigator import (
    ATTACK_VERSION,
    LAYER_FORMAT_VERSION,
    build_navigator_layer,
)

AS_OF = datetime(2026, 9, 15, 12, 0, 0, tzinfo=None) if False else datetime(2026, 9, 15, 12, 0, 0)

COVERAGE = {
    "summary": {"total_rules": 4, "armed": 3, "dormant": 1, "lookback_hours": 168},
    "rules": [
        {
            "name": "Rule A",
            "kind": "sigma",
            "armed": True,
            "mitre_techniques": ["T1059"],
        },
        {
            "name": "Rule B",
            "kind": "sigma",
            "armed": True,
            "mitre_techniques": ["T1059"],
        },
        {
            "name": "Rule C",
            "kind": "sigma",
            "armed": False,
            "mitre_techniques": ["T1059"],
        },
        {
            "name": "Brute Force Success",
            "kind": "correlation",
            "armed": True,
            "mitre_techniques": ["T1110"],
        },
        # A rule mapped to NO technique contributes nothing to the layer.
        {
            "name": "No Tech Rule",
            "kind": "sigma",
            "armed": True,
            "mitre_techniques": [],
        },
    ],
}

SCORECARD = {
    "rules": [
        {
            "name": "Rule A",
            "kind": "sigma",
            "fp_ratio": 0.0,
            "dispositions": 2,
            "false_positives": 0,
        },
        {
            "name": "Rule C",
            "kind": "sigma",
            "fp_ratio": 1.0,
            "dispositions": 3,
            "false_positives": 3,
        },
        {
            "name": "Unmeasured Rule",
            "kind": "sigma",
            "fp_ratio": None,
            "dispositions": 0,
            "false_positives": 0,
        },
    ],
}


class TestLayerStructure:
    @pytest.mark.asyncio
    async def test_layer_matches_v4_5_spec_shape(self):
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value=COVERAGE),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value=SCORECARD),
            ),
        ):
            layer = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        assert layer["versions"]["layer"] == LAYER_FORMAT_VERSION == "4.5"
        assert layer["versions"]["navigator"] >= "4.9.0"
        # Honesty: the layer claims the version our MAPPINGS were built
        # against (the v14-pinned cache), never a fake-current version.
        assert layer["versions"]["attack"] == ATTACK_VERSION == "14"
        assert layer["domain"] == "enterprise-attack"
        assert layer["gradient"]["minValue"] == 0
        assert layer["gradient"]["maxValue"] == 100
        assert len(layer["gradient"]["colors"]) >= 2
        assert isinstance(layer["techniques"], list)
        assert layer["metadata"]

    @pytest.mark.asyncio
    async def test_technique_scores_and_comments(self):
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value=COVERAGE),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value=SCORECARD),
            ),
        ):
            layer = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}

        # T1059: 2/3 armed -> 67; FP aggregate weighted across measured
        # rules: (0 FP + 3 FP) / (2 + 3 dispositions) = 3/5 = 0.60.
        t1059 = by_id["T1059"]
        assert t1059["score"] == 67
        assert "armed 2/3 (67%)" in t1059["comment"]
        assert "FP ratio 0.60 (5 dispositions)" in t1059["comment"]
        assert "Rule A" in t1059["comment"]
        assert "Rule C" in t1059["comment"]
        # T1110: correlation chain, armed, no dispositions -> unmeasured note.
        t1110 = by_id["T1110"]
        assert t1110["score"] == 100
        assert "FP ratio unmeasured" in t1110["comment"]
        # "No Tech Rule" mapped to nothing -> no entry for it.
        assert "T9999" not in by_id

    @pytest.mark.asyncio
    async def test_sorted_stable_by_technique_id(self):
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value=COVERAGE),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value=SCORECARD),
            ),
        ):
            layer = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert ids == sorted(ids)
        # Snapshot stability: two builds produce identical technique blocks.
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value=COVERAGE),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value=SCORECARD),
            ),
        ):
            layer2 = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        assert layer["techniques"] == layer2["techniques"]

    @pytest.mark.asyncio
    async def test_rule_name_list_capped(self):
        rules = {
            "summary": {},
            "rules": [
                {
                    "name": f"Rule {i}",
                    "kind": "sigma",
                    "armed": True,
                    "mitre_techniques": ["T1001"],
                }
                for i in range(10)
            ],
        }
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value=rules),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value={"rules": []}),
            ),
        ):
            layer = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        comment = layer["techniques"][0]["comment"]
        assert "Rule 3" in comment
        assert "Rule 4" not in comment
        assert "+6 more" in comment

    @pytest.mark.asyncio
    async def test_empty_coverage_yields_valid_empty_layer(self):
        with (
            patch(
                "src.detection.navigator.compute_coverage",
                AsyncMock(return_value={"summary": {}, "rules": []}),
            ),
            patch(
                "src.detection.navigator.compute_rule_scorecard",
                AsyncMock(return_value={"rules": []}),
            ),
        ):
            layer = await build_navigator_layer(lookback_hours=48, as_of=AS_OF)
        assert layer["techniques"] == []
        assert layer["domain"] == "enterprise-attack"


class TestEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_wiring(self):
        from src.api.detection import detection_coverage_navigator

        layer = {"name": "x", "techniques": []}
        with patch(
            "src.api.detection.build_navigator_layer", AsyncMock(return_value=layer)
        ) as mock_fn:
            result = await detection_coverage_navigator(lookback_hours=48, user={"sub": "viewer1"})
        assert result == layer
        mock_fn.assert_awaited_once()
        kwargs = mock_fn.await_args.kwargs
        assert kwargs["lookback_hours"] == 48
        assert "as_of" in kwargs
