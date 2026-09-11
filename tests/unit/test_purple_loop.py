"""
Tests for the purple-loop scoring core (pure functions, no DB/stack).
"""

from datetime import datetime, timezone

from scripts.purple_loop import CHAIN_HOSTS, compute_run_score, render_report_md

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

    def test_all_eight_chain_hosts_present(self):
        assert len(CHAIN_HOSTS) == 8
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
