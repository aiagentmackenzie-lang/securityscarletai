"""Tests for the TES-aligned purple scoring (W1.2) — pure functions, no DB.

Golden tests reproduce the PUBLISHED worked examples from the MITRE ATT&CK
Evaluations Enterprise 2026 methodology specification verbatim, so any drift
from the methodology fails CI.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.purple_tes import (
    conclusion_speed,
    dc_tier_for_behavior,
    detection_precision,
    ds_score,
    elements_for_alert,
    load_tes_config,
    render_tes_md,
    score_tes,
    validate_tes_config,
    weighted_dc,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TES_CONFIG_PATH = REPO_ROOT / "config" / "purple_tes.yaml"

_NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)


def _alert(**overrides):
    base = {
        "id": 1,
        "time": _NOW + timedelta(minutes=3),
        "rule_name": "Brute Force -> Successful Login",
        "severity": "critical",
        "host_name": "live-matrix-brute_force_success-123456",
        "description": "Detection: multiple failed logins followed by a successful login",
        "mitre_techniques": ["T1110"],
        "evidence": [
            {
                "host_name": "live-matrix-brute_force_success-123456",
                "host_ip": "10.50.1.22",
                "user_name": "corp\\jsmith",
                "process_name": "sshd",
            }
        ],
        "case_id": None,
        "status": "new",
    }
    base.update(overrides)
    return base


# ───────────────────────────────────────────────────────────────
# Golden tests — the published worked examples, verbatim
# ───────────────────────────────────────────────────────────────


class TestPublishedWorkedExamples:
    def test_acw_weighted_dc_example(self):
        # Published 4-technique example: numerator 6.25, weights 2.5 -> 2.5 -> 0.833
        result = weighted_dc([(3.0, 1.0), (3.0, 0.75), (2.0, 0.5), (0.0, 0.25)])
        assert result["weighted"] == 2.5
        assert result["normalized"] == 0.833

    def test_dp_fragmented_vs_consolidated(self):
        # Vendor A: 50 TP, 0 FP, 50 cases -> 50/(50+0+49) = 0.505
        assert detection_precision(tp=50, fp=0, cases=50)["value"] == 0.505
        # Vendor B: 50 TP, 0 FP, 1 case -> 1.0
        assert detection_precision(tp=50, fp=0, cases=1)["value"] == 1.0

    def test_dqi_final_example(self):
        # Published: (0.833 + 0.700 + 0.708) / 3 = 0.747
        assert round((0.833 + 0.700 + 0.708) / 3.0, 3) == 0.747

    def test_ap_operation_example(self):
        # Published Operation A: 10/(10+0+9) = 0.526
        from scripts.purple_tes import analyst_precision

        assert analyst_precision(tp=10, fp=0, cases=10)["value"] == 0.526

    def test_iqi_final_example(self):
        # Published: (0.833 + 0.750 + 0.500) / 3 = 0.694
        assert round((0.833 + 0.750 + 0.500) / 3.0, 3) == 0.694

    def test_cs_small_band(self):
        assert conclusion_speed(25, techniques_in_scenario=10)["value"] == 1.0
        assert conclusion_speed(45, techniques_in_scenario=10)["value"] == 0.75
        assert conclusion_speed(100, techniques_in_scenario=10)["value"] == 0.5
        assert conclusion_speed(200, techniques_in_scenario=10)["value"] == 0.25
        assert conclusion_speed(300, techniques_in_scenario=10)["value"] == 0.0

    def test_cs_bands_by_complexity(self):
        # 50 min in a MEDIUM scenario (16-40 techniques) = 1.0
        assert conclusion_speed(50, techniques_in_scenario=20)["value"] == 1.0
        # 150 min in a VERY LARGE scenario (81+) = 1.0
        assert conclusion_speed(150, techniques_in_scenario=90)["value"] == 1.0


# ───────────────────────────────────────────────────────────────
# Config validation (fail-closed)
# ───────────────────────────────────────────────────────────────


def _chain_names() -> set[str]:
    from src.detection.correlation import CORRELATION_RULES

    return set(CORRELATION_RULES)


class TestTESConfig:
    def test_shipped_config_loads_and_validates_clean(self):
        cfg = load_tes_config(TES_CONFIG_PATH)
        errors = validate_tes_config(cfg, _chain_names())
        assert errors == [], errors

    def test_weight_outside_vocabulary_rejected(self):
        cfg = {
            "scenarios": {
                "brute_force_success": {
                    "terminal_objective": "The adversary succeeds when it gets in.",
                    "techniques": [
                        {"id": "T1110", "acw": 0.9, "tier": "high", "justification": "x" * 30}
                    ],
                }
            }
        }
        errors = validate_tes_config(cfg, {"brute_force_success"})
        assert any("vocabulary" in e for e in errors)

    def test_tier_label_mismatch_rejected(self):
        cfg = {
            "scenarios": {
                "brute_force_success": {
                    "terminal_objective": "The adversary succeeds when it gets in.",
                    "techniques": [
                        {"id": "T1110", "acw": 1.0, "tier": "high", "justification": "x" * 30}
                    ],
                }
            }
        }
        errors = validate_tes_config(cfg, {"brute_force_success"})
        assert any("does not match weight" in e for e in errors)

    def test_ceiling_without_justification_rejected(self):
        cfg = {
            "scenarios": {
                "credential_theft_exfil": {
                    "terminal_objective": "The adversary succeeds when creds leave.",
                    "techniques": [
                        {"id": "T1552", "acw": 1.0, "tier": "critical", "justification": "x" * 30},
                        {"id": "T1048", "acw": 1.0, "tier": "critical", "justification": "x" * 30},
                        {"id": "T1110", "acw": 0.5, "tier": "medium", "justification": "y" * 30},
                    ],
                }
            }
        }
        errors = validate_tes_config(cfg, {"credential_theft_exfil"})
        assert any("ceiling" in e for e in errors)

    def test_unknown_chain_is_config_drift(self):
        cfg = load_tes_config(TES_CONFIG_PATH)
        errors = validate_tes_config(cfg, {"brute_force_success"})  # only 1 of 10 known
        assert any("config drift" in e for e in errors)

    def test_missing_terminal_sentence_rejected(self):
        cfg = {
            "scenarios": {
                "brute_force_success": {
                    "terminal_objective": "Get in somehow.",
                    "techniques": [
                        {"id": "T1110", "acw": 1.0, "tier": "critical", "justification": "x" * 30}
                    ],
                }
            }
        }
        errors = validate_tes_config(cfg, {"brute_force_success"})
        assert any("succeeds when" in e for e in errors)


# ───────────────────────────────────────────────────────────────
# DC-3 element checklist + behavior-level DC
# ───────────────────────────────────────────────────────────────


class TestElements:
    def test_complete_alert_is_dc3_capable(self):
        e = elements_for_alert(_alert())
        assert e == {
            "WHO": True,
            "WHAT": True,
            "WHEN": True,
            "WHERE": True,
            "HOW": True,
            "SEVERITY": True,
        }

    def test_missing_ip_blocks_where(self):
        alert = _alert(evidence=[{"host_name": "h", "user_name": "root"}])
        e = elements_for_alert(alert)
        assert e["WHERE"] is False
        assert e["WHO"] is True

    def test_ip_in_description_satisfies_where(self):
        alert = _alert(evidence=[], description="Detection on 10.50.1.22 for user=root")
        e = elements_for_alert(alert)
        assert e["WHERE"] is True
        assert e["WHO"] is True  # identity mention in text

    def test_no_identity_no_where(self):
        alert = _alert(evidence=[], description="suspicious command pattern")
        e = elements_for_alert(alert)
        assert e["WHO"] is False
        assert e["WHERE"] is False


class TestBehaviorDC:
    def test_dc3_when_any_alert_complete(self):
        result = dc_tier_for_behavior([_alert()], telemetry_seen=True)
        assert result["tier"] == "DC-3"
        assert result["score"] == 3.0

    def test_dc2_with_blockers_reported(self):
        alert = _alert(evidence=[{"host_name": "h"}])  # no identity, no IP
        result = dc_tier_for_behavior([alert], telemetry_seen=True)
        assert result["tier"] == "DC-2"
        assert result["score"] == 2.0
        assert set(result["blocking_elements"]) == {"WHO", "WHERE"}

    def test_best_alert_rule(self):
        weak = _alert(id=1, evidence=[{"host_name": "h"}])
        better = _alert(id=2, evidence=[{"host_name": "h", "host_ip": "10.0.0.5"}])
        result = dc_tier_for_behavior([better, weak], telemetry_seen=True)
        assert result["tier"] == "DC-2"
        assert result["blocking_elements"] == ["WHO"]
        assert result["alert_id"] == 2

    def test_dc1_telemetry_no_alert(self):
        result = dc_tier_for_behavior([], telemetry_seen=True)
        assert result["tier"] == "DC-1"
        assert result["score"] == 1.0

    def test_dc0_blind_spot(self):
        result = dc_tier_for_behavior([], telemetry_seen=False)
        assert result["tier"] == "DC-0"
        assert result["score"] == 0.0


# ───────────────────────────────────────────────────────────────
# DP / DS honesty gates
# ───────────────────────────────────────────────────────────────


class TestDpDs:
    def test_dp_unmeasured_when_nothing_to_score(self):
        assert detection_precision(tp=0, fp=0, cases=3)["value"] is None
        assert detection_precision(tp=0, fp=0, cases=0)["value"] is None

    def test_ds_tiers(self):
        assert ds_score(14.9) == {"score": 1.0, "tier": "Real-Time"}
        assert ds_score(15.0) == {"score": 0.75, "tier": "Acceptable Delay"}
        assert ds_score(30.0) == {"score": 0.75, "tier": "Acceptable Delay"}
        assert ds_score(30.1) == {"score": 0.5, "tier": "Significant Delay"}
        assert ds_score(None)["score"] is None

    def test_cs_unmeasured_without_conclusion(self):
        result = conclusion_speed(None, techniques_in_scenario=5)
        assert result["value"] is None
        assert "human adjudication" in result["unmeasured_reason"]


# ───────────────────────────────────────────────────────────────
# End-to-end (pure): one synthetic run through score_tes
# ───────────────────────────────────────────────────────────────


class TestScoreTes:
    def _config(self):
        return {
            "config_sha256": "deadbeef",
            "scenarios": {
                "brute_force_success": {
                    "terminal_objective": "The adversary succeeds when access is obtained.",
                    "techniques": [
                        {
                            "id": "T1110",
                            "acw": 1.0,
                            "tier": "critical",
                            "justification": "the terminal behavior itself",
                        }
                    ],
                },
                "data_exfiltration": {
                    "terminal_objective": "The adversary succeeds when data leaves.",
                    "techniques": [
                        {
                            "id": "T1048",
                            "acw": 1.0,
                            "tier": "critical",
                            "justification": "the terminal behavior itself",
                        }
                    ],
                },
            },
        }

    def test_end_to_end_components(self):
        fired_alert = _alert(
            id=10,
            host_name="live-matrix-brute_force_success-123456",
            case_id=7,
            status="new",
        )
        cfg = self._config()
        tes = score_tes(
            config=cfg,
            chains={"brute_force_success": True, "data_exfiltration": False},
            chain_hosts={
                "brute_force_success": "live-matrix-brute_force_success-123456",
                "data_exfiltration": "live-matrix-data_exfiltration-123456",
            },
            alerts=[fired_alert],
            matches=[],
            log_first_times={
                # the matrix fires BOTH chains' events; only one detected
                "live-matrix-brute_force_success-123456": _NOW + timedelta(minutes=1),
                "live-matrix-data_exfiltration-123456": _NOW + timedelta(minutes=1),
            },
            cases={7: {"id": 7, "alert_ids": [10], "resolved_at": None, "resolution_note": None}},
            case_alerts={7: [fired_alert]},
        )
        # Weighted DC: T1110 DC-3 (3.0x1.0) + T1048 DC-1 (1.0x1.0, telemetry
        # present, no alert) over weights 2.0 = 2.0 -> 0.667 normalized
        assert tes["weighted_dc"]["normalized"] == 0.667
        # The executed-but-undetected behavior: DC-1 (not DC-0 — telemetry
        # exists in the window; the generator fires every chain's events)
        exfil = next(b for b in tes["behaviors"] if b["technique"] == "T1048")
        assert exfil["dc"]["tier"] == "DC-1"
        assert exfil["dc"]["score"] == 1.0
        # DS for that behavior: the published "No Detection = 0.0" row
        assert exfil["ds"]["score"] == 0.0
        assert exfil["ds"]["tier"] == "No Detection"
        # MTTD: first detection (12:03) - first event (12:01) = 2 min -> Real-Time
        brute = next(b for b in tes["behaviors"] if b["technique"] == "T1110")
        assert brute["dc"]["tier"] == "DC-3"
        assert brute["mttd_minutes"] == 2.0
        assert brute["ds"]["score"] == 1.0
        assert tes["ds_normalized"] == 0.5
        # DP: TP=1 (DC-2+ only; DC-1 is telemetry-only), Cases=1 -> 1.0
        assert tes["dp"]["value"] == 1.0
        assert tes["dp"]["tp"] == 1
        assert tes["dp"]["cases"] == 1
        # DQI = (0.667 + 1.0 + 0.5)/3 = 0.722
        assert tes["dqi"] == 0.722
        # IQI: Weighted_IC from the case chain — T1110 IC-1 (1.0x1.0) +
        # T1048 IC-0 (0.0x1.0, no alert -> no investigation) = 0.5 -> 0.167;
        # AP/CS unmeasured
        assert tes["iqi"]["value"] is None
        assert tes["iqi"]["weighted_ic_normalized"] == 0.167
        assert "AP" in tes["iqi"]["unmeasured_reasons"]
        assert "CS_normalized" in tes["iqi"]["unmeasured_reasons"]
        # PQI never scored in a detection-only run
        assert tes["pq"]["scored"] is False
        # The TES line reports DQI (PQI absent), labeled self-scored
        assert tes["tes"] == tes["dqi"]

    def test_unmeasured_scenario_reported(self):
        cfg = self._config()
        del cfg["scenarios"]["data_exfiltration"]
        tes = score_tes(
            config=cfg,
            chains={"brute_force_success": True, "data_exfiltration": True},
            chain_hosts={
                "brute_force_success": "h1",
                "data_exfiltration": "h2",
            },
            alerts=[],
            matches=[],
            log_first_times={},
            cases={},
            case_alerts={},
        )
        assert tes["unmeasured_scenarios"] == [
            {"chain": "data_exfiltration", "reason": "no ACW scenario in the TES config"}
        ]
        # The remaining scored behavior (T1110: fired, telemetry-by-firing)
        # still scores: (1.0x1.0)/1.0 = 1.0 raw -> 0.333 normalized
        assert tes["weighted_dc"]["weighted"] == 1.0
        assert tes["weighted_dc"]["normalized"] == 0.333

    def test_fired_technique_not_in_config_reported_unmeasured(self):
        cfg = self._config()
        cfg["scenarios"]["brute_force_success"]["techniques"].append(
            {
                "id": "T9999",
                "acw": 0.25,
                "tier": "low",
                "justification": "placeholder for the drift test",
            }
        )
        del cfg["scenarios"]["brute_force_success"]["techniques"][0]
        tes = score_tes(
            config=cfg,
            chains={"brute_force_success": True},
            chain_hosts={"brute_force_success": "h1"},
            alerts=[_alert(host_name="h1", mitre_techniques=["T1110"])],
            matches=[],
            log_first_times={"h1": _NOW},
            cases={},
            case_alerts={},
        )
        row = next(b for b in tes["behaviors"] if b["technique"] == "T1110")
        assert row["unmeasured_reason"]
        assert row["acw"] is None

    def test_render_labels_self_scored(self):
        cfg = self._config()
        tes = score_tes(
            config=cfg,
            chains={"brute_force_success": False},
            chain_hosts={"brute_force_success": "h1"},
            alerts=[],
            matches=[],
            log_first_times={},
            cases={},
            case_alerts={},
        )
        md = render_tes_md(tes)
        assert "SELF-SCORED" in md
        assert "NOT program participation" in md
        assert "unmeasured" in md
