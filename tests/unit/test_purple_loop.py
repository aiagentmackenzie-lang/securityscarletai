"""
Tests for the purple-loop scoring core (pure functions, no DB/stack).
"""

import json
from datetime import datetime, timezone

from scripts.purple_loop import (
    CHAIN_HOSTS,
    build_feedback,
    compute_run_score,
    load_progression,
    render_report_md,
)

_COVERAGE = {
    "summary": {"total_rules": 108, "armed": 86, "lookback_hours": 168},
    "techniques": [
        {"technique": "T1110", "rules": 2, "armed_rules": 2},
        {"technique": "T1059", "rules": 3, "armed_rules": 3},
        {"technique": "T1486", "rules": 1, "armed_rules": 0},  # dormant
        {"technique": "T1547", "rules": 1, "armed_rules": 1},
    ],
}


class TestComputeRunScore:
    def test_full_fire(self):
        score = compute_run_score(
            chains={CHAIN_HOSTS[0]: True, CHAIN_HOSTS[1]: True},
            fired_alerts=[
                {
                    "host_name": CHAIN_HOSTS[0],
                    "rule_name": "Brute Force Pattern",
                    "mitre_techniques": ["T1110"],
                },
                {
                    "host_name": CHAIN_HOSTS[1],
                    "rule_name": "Persistence Activated",
                    "mitre_techniques": ["T1547"],
                },
            ],
            coverage_after=_COVERAGE,
            run_window_start=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
        assert score["chains_fired"] == 2
        assert score["chains_total"] == 2
        assert score["chain_score"] == 1.0
        assert score["distinct_rules_fired"] == 2
        assert score["techniques_hit"] == ["T1110", "T1547"]
        # T1486 is dormant (armed_rules=0) so it is not in the armed set
        assert score["armed_techniques_total"] == 3
        assert score["technique_hit_rate_armed"] == round(2 / 3, 3)
        assert "T1059" in score["armed_techniques_not_hit_by_this_run"]
        # Dormant techniques are not in the armed list at all
        assert "T1486" not in score["armed_techniques_not_hit_by_this_run"]

    def test_partial_fire(self):
        score = compute_run_score(
            chains={CHAIN_HOSTS[0]: True, CHAIN_HOSTS[1]: False},
            fired_alerts=[
                {
                    "host_name": CHAIN_HOSTS[0],
                    "rule_name": "Brute Force Pattern Detected",
                    "mitre_techniques": ["T1110"],
                }
            ],
            coverage_after=_COVERAGE,
            run_window_start=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
        assert score["chain_score"] == 0.5
        assert score["alerts_fired"] == 1

    def test_no_fire_scores_zero(self):
        score = compute_run_score(
            chains={CHAIN_HOSTS[0]: False},
            fired_alerts=[],
            coverage_after=_COVERAGE,
            run_window_start=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
        assert score["chain_score"] == 0.0
        assert score["alerts_fired"] == 0
        assert score["technique_hit_rate_armed"] == 0.0

    def test_all_ten_chain_hosts_present_and_registry_complete(self):
        # CHAIN_HOSTS is DERIVED from the correlation registry (never a
        # hand-maintained list -- the drift that under-scored the V0.6b
        # chains). This pins the derivation itself.
        from src.detection.correlation import CORRELATION_RULES

        assert len(CHAIN_HOSTS) == len(CORRELATION_RULES) == 10
        assert CHAIN_HOSTS == [f"live-matrix-{name}" for name in CORRELATION_RULES]
        assert all(h.startswith("live-matrix-") for h in CHAIN_HOSTS)


class TestRenderReportMd:
    def test_report_contains_scores_and_chains(self):
        score = compute_run_score(
            chains={CHAIN_HOSTS[0]: True, CHAIN_HOSTS[1]: False},
            fired_alerts=[
                {
                    "host_name": CHAIN_HOSTS[0],
                    "rule_name": "Brute Force Pattern Detected",
                    "mitre_techniques": ["T1110"],
                }
            ],
            coverage_after=_COVERAGE,
            run_window_start=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
        score["chains_detail"] = sorted({CHAIN_HOSTS[0]: True, CHAIN_HOSTS[1]: False}.items())
        md = render_report_md(score)
        assert "# Purple-loop run report" in md
        assert "1/2" in md
        assert CHAIN_HOSTS[0] in md
        assert "Armed techniques NOT hit" in md

    def test_report_handles_zero_hits(self):
        score = compute_run_score(
            chains={CHAIN_HOSTS[0]: False},
            fired_alerts=[],
            coverage_after=_COVERAGE,
            run_window_start=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
        score["chains_detail"] = [(CHAIN_HOSTS[0], False)]
        md = render_report_md(score)
        assert "(none)" in md  # honest empty sections, never padded


class TestMergeChainHosts:
    """V0.4/5: chains score from alerts OR persisted correlation matches.
    V0.7 delta: the scorer takes the run's EXPECTED host map
    (run-unique host -> chain) so a re-run's stale hosts can never satisfy
    a fresh run's slots."""

    def test_match_only_chain_counts_as_fired(self):
        from scripts.purple_loop import _merge_chain_hosts

        expected = {CHAIN_HOSTS[0]: "brute_force_success", CHAIN_HOSTS[1]: "payload_callback"}
        chains = _merge_chain_hosts(expected, set(), {CHAIN_HOSTS[0]})
        assert chains["brute_force_success"] is True
        assert chains["payload_callback"] is False

    def test_alert_only_scoring_still_works(self):
        from scripts.purple_loop import _merge_chain_hosts

        expected = {CHAIN_HOSTS[0]: "brute_force_success", CHAIN_HOSTS[1]: "payload_callback"}
        chains = _merge_chain_hosts(expected, {CHAIN_HOSTS[1]}, set())
        assert chains["payload_callback"] is True
        assert chains["brute_force_success"] is False

    def test_unknown_hosts_ignored(self):
        from scripts.purple_loop import _merge_chain_hosts

        expected = {CHAIN_HOSTS[0]: "brute_force_success", CHAIN_HOSTS[1]: "payload_callback"}
        chains = _merge_chain_hosts(expected, {"unrelated-host"}, {"live-matrix-other"})
        assert all(not fired for fired in chains.values())


class TestBuildFeedback:
    """V0.5d+ productization: actionable per-failed-chain feedback.

    V0.7 delta: chains are keyed by the correlation rule name (the
    run-unique host stem by construction)."""

    def test_failed_chain_names_its_rule(self):
        from scripts.purple_loop import build_feedback

        chains = {"brute_force_success": False, "payload_callback": True}
        feedback = build_feedback(chains)
        assert len(feedback) == 1
        item = feedback[0]
        assert item["chain"] == "brute_force_success"
        assert item["correlation_rule"] == "brute_force_success"
        assert item["hint"]

    def test_all_fired_means_empty_feedback(self):
        from scripts.purple_loop import build_feedback

        chains = {c: True for c in CHAIN_HOSTS}
        assert build_feedback(chains) == []

    def test_feedback_is_sorted_deterministic(self):
        from scripts.purple_loop import build_feedback

        chains = {c: False for c in reversed(CHAIN_HOSTS)}
        feedback = build_feedback(chains)
        assert [i["chain"] for i in feedback] == sorted(CHAIN_HOSTS)


class TestLoadProgression:
    """V0.5d+ productization: the compounding series from committed reports."""

    def test_reads_committed_reports_in_order(self, tmp_path):

        for stamp, score, armed in (
            ("purple-20260911T152518Z", 0.75, 58),
            ("purple-20260911T193228Z", 1.0, 90),
        ):
            d = tmp_path / stamp
            d.mkdir()
            (d / "report.json").write_text(
                json.dumps(
                    {
                        "chains_fired": round(8 * score),
                        "chains_total": 8,
                        "chain_score": score,
                        "technique_hit_rate_armed": 0.3,
                        "coverage_summary": {"armed": armed},
                    }
                )
            )
        entries = load_progression(tmp_path)
        assert len(entries) == 2
        assert entries[0]["run"] == "purple-20260911T152518Z"
        assert entries[0]["armed_rules"] == 58
        assert entries[1]["armed_rules"] == 90
        assert entries[0]["chain_score"] == 0.75

    def test_skips_broken_or_incomplete_reports(self, tmp_path):

        (tmp_path / "purple-aaa").mkdir()
        (tmp_path / "purple-aaa" / "report.json").write_text("{not json")
        (tmp_path / "purple-bbb").mkdir()
        (tmp_path / "purple-bbb" / "report.json").write_text(json.dumps({"mode": "matrix"}))
        (tmp_path / "purple-ccc").mkdir()  # no report.json at all
        assert load_progression(tmp_path) == []

    def test_empty_runs_dir(self, tmp_path):

        assert load_progression(tmp_path) == []


class TestReportProgressionAndFeedback:
    """The client-facing report carries the progression table + feedback."""

    def _score(self, fired=None):
        # fired defaults to ALL chains -- "full fire" must track the chain
        # registry length, not a hardcoded count (the 8-vs-10 drift).
        if fired is None:
            fired = len(CHAIN_HOSTS)
        total = len(CHAIN_HOSTS)
        return {
            "run_window_start": "2026-09-12T12:00:00+00:00",
            "chains_fired": fired,
            "chains_total": total,
            "chain_score": round(fired / total, 3),
            "alerts_fired": 10,
            "distinct_rules_fired": 9,
            "techniques_hit": ["T1059"],
            "techniques_hit_armed": ["T1059"],
            "armed_techniques_total": 30,
            "technique_hit_rate_armed": 0.033,
            "armed_techniques_not_hit_by_this_run": [],
            "rules_fired": ["rule-a"],
            "coverage_summary": {"armed": 86, "total_rules": 112, "lookback_hours": 168},
            "chains_detail": [(c, i < fired) for i, c in enumerate(CHAIN_HOSTS)],
            "feedback": build_feedback({c: i < fired for i, c in enumerate(CHAIN_HOSTS)}),
            "progression": [
                {
                    "run": "purple-20260911T152518Z",
                    "chains_fired": 6,
                    "chains_total": 8,
                    "chain_score": 0.75,
                    "armed_rules": 58,
                    "technique_hit_rate_armed": 0.2,
                },
                {
                    "run": "(this run)",
                    "chains_fired": fired,
                    "chains_total": 8,
                    "chain_score": round(fired / 8, 3),
                    "armed_rules": 86,
                    "technique_hit_rate_armed": 0.033,
                },
            ],
        }

    def test_report_shows_progression_table(self):
        md = render_report_md(self._score())
        assert "Detection-gain progression" in md
        assert "purple-20260911T152518Z" in md
        assert "(this run)" in md

    def test_report_lists_feedback_for_failed_chains(self):
        md = render_report_md(self._score(fired=7))
        assert "Detection-engineering feedback" in md
        assert CHAIN_HOSTS[7] in md
        assert "correlation rule" in md

    def test_full_fire_report_has_no_feedback_section(self):
        md = render_report_md(self._score())
        assert "Detection-engineering feedback" not in md
