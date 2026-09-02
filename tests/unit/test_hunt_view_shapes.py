"""Phase 1 (2026-09-01) — hunt_view field-shape regression tests.

dashboard/hunt_view.py drifted from the API's real response shapes in three
places, leaving dead UI paths the green test suite never caught:
  1. MITRE gaps tab read covered_techniques/uncovered_techniques — the API
     (GapAnalysisResponse) returns total_covered / gaps / gap_hunts.
  2. Hunt-from-alert read 'suggested_hunts' — the API returns
     matching_hunts + llm_suggestions.
  3. Template grouping read 'mitre_tactics' — the API returns 'category'
     and 'mitre'.

These tests pin the pure mapping helpers so the view can't silently drift
from the API shape again.
"""

from dashboard.hunt_view import (
    _group_templates,
    _hunts_for_alert,
    _summarize_gaps,
)

# Exact shape mitre_gap_analysis() returns (src/ai/hunting_assistant.py).
GAP_RESPONSE = {
    "total_critical_techniques": 30,
    "covered_by_rules": 10,
    "covered_by_hunts": 5,
    "total_covered": 14,
    "coverage_percentage": 46.7,
    "gaps": ["T1190", "T1204", "T1573"],
    "gap_hunts": [
        {"technique": "T1190", "hunt_id": None, "hunt_name": "Create custom hunt for T1190"},
    ],
    "rule_techniques": ["T1110", "T1059"],
    "hunt_techniques": ["T1071", "T1573"],
}


class TestSummarizeGaps:
    def test_real_api_shape_maps(self):
        summary = _summarize_gaps(GAP_RESPONSE)
        assert summary["covered"] == 14
        assert summary["total"] == 30
        assert summary["pct"] == 46.7
        assert summary["gaps"] == ["T1190", "T1204", "T1573"]
        assert len(summary["gap_hunts"]) == 1

    def test_empty_response(self):
        summary = _summarize_gaps({})
        assert summary["covered"] == 0
        assert summary["total"] == 0
        assert summary["gaps"] == []
        assert summary["gap_hunts"] == []


class TestGroupTemplates:
    TEMPLATES = [
        {"id": "a", "name": "A", "category": "persistence", "mitre": ["T1547"]},
        {"id": "b", "name": "B", "category": "persistence", "mitre": ["T1037"]},
        {"id": "c", "name": "C", "category": "credential_access", "mitre": ["T1003"]},
    ]

    def test_groups_by_category(self):
        grouped = _group_templates(self.TEMPLATES)
        assert set(grouped.keys()) == {"persistence", "credential_access"}
        assert len(grouped["persistence"]) == 2

    def test_missing_category_bucketed(self):
        grouped = _group_templates([{"id": "x", "name": "X", "mitre": []}])
        assert grouped == {"general": [{"id": "x", "name": "X", "mitre": []}]}


class TestHuntsForAlert:
    def test_combines_matching_and_llm_suggestions(self):
        result = {
            "matching_hunts": [{"id": "c2_beaconing_connections", "name": "C2"}],
            "llm_suggestions": [{"name": "Investigate host", "description": "..."}],
        }
        hunts = _hunts_for_alert(result)
        assert len(hunts) == 2
        assert hunts[0]["id"] == "c2_beaconing_connections"
        assert hunts[1]["name"] == "Investigate host"

    def test_missing_fields_yield_empty(self):
        # The old bug: 'suggested_hunts' doesn't exist → always empty.
        assert _hunts_for_alert({}) == []
        assert _hunts_for_alert({"suggested_hunts": [{"name": "x"}]}) == []
