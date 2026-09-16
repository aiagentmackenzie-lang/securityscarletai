"""TES-aligned purple scoring (W1.2) — self-scored against the published
MITRE ATT&CK Evaluations Enterprise 2026 methodology specification
(https://evals.mitre.org/methodology-specification).

This module is SELF-SCORING infrastructure for the purple loop: it computes
DQI components (ACW-weighted Detection Coverage, Detection Precision with the
case-consolidation penalty, Detection Speed) and an IQI-style investigation
score from the case/evidence chain. It is NOT program participation, and
every artifact produced with it must carry the self-scored label.

Methodology anchors implemented here (verified against the published
specification, 2026-09-16):

  - TES = DQI + PQI (0-2.0). We score detection only: the purple matrix is a
    detection run (no block-timing stages execute), so PQI is NOT SCORED and
    the TES line reports DQI alone — labeled, never implied to be a full TES.
  - DQI = (Weighted_DC_normalized + DP + DS_normalized) / 3
  - DC tiers: DC-3 = 3.0 (all six published elements on the best alert for
    the behavior), DC-2 = 2.0 (alert fired without the full checklist),
    DC-1 = 1.0 (telemetry exists, no platform alert), DC-0 = 0.0 (blind
    spot). Behavior-level scoring: one DC score per ATT&CK behavior
    regardless of how many alerts fired for it.
  - ACW in {1.0, 0.75, 0.5, 0.25, 0.0}, per scenario, with a written
    terminal objective and per-technique justification (config/
    purple_tes.yaml; validated fail-closed, critical-weight ceiling
    enforced).
  - DP = TP / (TP + FP + (Cases - 1))  (case-consolidation penalty)
  - DS: <15 min = 1.0, 15-30 = 0.75, >30 = 0.5, no alert = 0.0
  - IQI = (Weighted_IC_normalized + AP + CS_normalized) / 3, reported
    SEPARATELY from TES. IC tiers from the core 5 (WHO/WHAT/WHEN/WHERE/HOW)
    + extended 4 (EVIDENCE/CORRELATION/SCOPE/DISPOSITION); AP and CS are
    measured only where the run's data supports them — unmeasured is
    reported as unmeasured, never as 0 (honesty gates; the sigmaforge
    standard adopted in W1.1).

Honest scoring choices (documented, not silent):
  - A persisted correlation match without an alert scores DC-1 (conservative:
    a platform detection signal, but not an analyst-facing alert).
  - MTTD is measured from the chain's first telemetry timestamp to its first
    detection timestamp (alert or match) — an approximation under the
    shipper's batch ingestion, labeled as such in the report.
  - The purple matrix fires no benign probes in-window, so DP's FP term is
    0 IN-WINDOW and labeled as such; benign-precision evidence lives in the
    deception matrix and the scorecard dispositions.

The published worked examples are reproduced as unit tests (golden tests)
so drift against the methodology is caught in CI.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

ACW_VOCABULARY: dict[float, str] = {
    1.0: "critical",
    0.75: "high",
    0.5: "medium",
    0.25: "low",
    0.0: "benign",
}
HIGHEST_DC_SCORE = 3.0

WHO_KEYS = {
    "user_name",
    "user",
    "source_user",
    "src_user",
    "process_name",
    "process_pid",
    "actor",
}
IP_KEYS = ("host_ip", "source_ip", "destination_ip", "ip", "remote_ip")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WHO_TEXT_RE = re.compile(r"(?i)\b(?:user(?:_name)?|uid|account)\b\s*[:=]")
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# The methodology's terminal-objective rule, enforced literally.
TERMINAL_SENTENCE_RE = re.compile(r"(?i)succeeds\s+when")


# ───────────────────────────────────────────────────────────────
# Config (versioned ACW weights) — fail-closed validation
# ───────────────────────────────────────────────────────────────


class TESConfigError(ValueError):
    """Raised when the TES config cannot be read at all (fail-closed: the
    run's TES block reports 'unmeasured — config invalid' rather than
    scoring with a broken config)."""


def load_tes_config(path: Path) -> dict:
    """Load + return the versioned ACW config. Raises TESConfigError on a
    malformed file (YAML or missing top-level keys)."""
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise TESConfigError(f"cannot read TES config {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), dict):
        raise TESConfigError(f"{path}: missing/invalid 'scenarios' mapping")
    data["config_sha256"] = hashlib.sha256(raw).hexdigest()
    return data


def validate_tes_config(cfg: dict, chain_names: set[str]) -> list[str]:
    """Fail-closed validation. Returns a list of error strings (empty = OK).

    Rules enforced (all published):
      - every scenario states a terminal objective containing the
        "succeeds when" sentence
      - technique ids ATT&CK-shaped; weights in the published vocabulary;
        tier label consistent with the weight
      - every technique carries a non-empty written justification
      - critical-weight ceiling: >25% of a scenario's techniques at 1.0x
        requires a ceiling_justification
      - scenarios must map 1:1 to the correlation registry (an unknown
        scenario = config drift = error; a registry chain MISSING from the
        config is allowed and reported unmeasured at scoring time)
    """
    errors: list[str] = []
    scenarios = cfg.get("scenarios") or {}
    for name, sc in scenarios.items():
        prefix = f"scenario '{name}'"
        if name not in chain_names:
            errors.append(f"{prefix}: not a chain in CORRELATION_RULES (config drift)")
            continue
        objective = str(sc.get("terminal_objective") or "")
        if not TERMINAL_SENTENCE_RE.search(objective):
            errors.append(f"{prefix}: terminal_objective must contain the 'succeeds when' sentence")
        techniques = sc.get("techniques") or []
        if not techniques:
            errors.append(f"{prefix}: no techniques listed")
            continue
        seen: set[str] = set()
        criticals = 0
        for t in techniques:
            tid = str(t.get("id", ""))
            if not TECHNIQUE_ID_RE.match(tid):
                errors.append(f"{prefix}: technique id '{tid}' is not an ATT&CK id")
            if tid in seen:
                errors.append(f"{prefix}: duplicate technique '{tid}'")
            seen.add(tid)
            acw = t.get("acw")
            if acw not in ACW_VOCABULARY:
                errors.append(f"{prefix}: {tid} weight {acw!r} outside the published vocabulary")
                continue
            expected = ACW_VOCABULARY[float(acw)]
            if str(t.get("tier", "")) != expected:
                errors.append(
                    f"{prefix}: {tid} tier '{t.get('tier')}' does not match weight {acw} "
                    f"(expected '{expected}')"
                )
            if len(str(t.get("justification", "")).strip()) < 20:
                errors.append(f"{prefix}: {tid} missing a written justification")
            if float(acw) == 1.0:
                criticals += 1
        total = len(techniques)
        if (
            total
            and (criticals / total) > 0.25
            and not str(sc.get("ceiling_justification", "")).strip()
        ):
            errors.append(
                f"{prefix}: {criticals}/{total} techniques at 1.0x exceed the published "
                f"critical-weight ceiling without a ceiling_justification"
            )
    return errors


# ───────────────────────────────────────────────────────────────
# DC-3 element checklist (published: WHO/WHAT/WHEN/WHERE/HOW/SEVERITY)
# ───────────────────────────────────────────────────────────────


def elements_for_alert(alert: dict) -> dict[str, bool]:
    """Evaluate the six published DC-3 elements for ONE alert.

    Elements may be platform-automated (alert fields) or demonstrated in the
    alert's own evidence (the Sigma pipeline stores the FULL matched log row
    as `evidence`, so user/process/IP identity is usually present) — both
    paths count per the methodology's element-population rule.
    """
    blob = json.dumps(
        {
            "description": alert.get("description") or "",
            "evidence": alert.get("evidence") or [],
            "ai_summary": alert.get("ai_summary") or "",
        },
        default=str,
    )
    try:
        evidence = alert.get("evidence") or []
        evidence_entries = evidence if isinstance(evidence, list) else [evidence]
    except (TypeError, ValueError):
        evidence_entries = []
    who = False
    where_ip = False
    for entry in evidence_entries:
        if not isinstance(entry, dict):
            continue
        if any(entry.get(k) for k in WHO_KEYS):
            who = True
        if any(entry.get(k) for k in IP_KEYS):
            where_ip = True
    techniques = alert.get("mitre_techniques") or []
    return {
        # WHO: user/entity identity — a structured identity field in the
        # evidence, or an identity mention in description/summary text.
        "WHO": bool(who or WHO_TEXT_RE.search(blob)),
        # WHAT: the detection criteria — the rule names the behavior.
        "WHAT": bool(str(alert.get("rule_name") or "").strip()),
        # WHEN: the behavior timestamp.
        "WHEN": alert.get("time") is not None,
        # WHERE: hostname AND an IP address (published minimum).
        "WHERE": bool(str(alert.get("host_name") or "").strip())
        and (where_ip or bool(IP_RE.search(blob))),
        # HOW: technique-level enrichment.
        "HOW": bool(techniques),
        # SEVERITY: any malicious/suspicious indication.
        "SEVERITY": bool(str(alert.get("severity") or "").strip()),
    }


def dc3_blockers(elements: dict[str, bool]) -> list[str]:
    """The DC-3 elements the best alert is missing (the actionable feedback)."""
    return sorted(k for k, ok in elements.items() if not ok)


def dc_tier_for_behavior(alerts_for_behavior: list[dict], telemetry_seen: bool) -> dict:
    """Behavior-level DC: the BEST alert quality across the behavior's alerts
    (one DC score per behavior, never per alert — published rule).

    telemetry_seen: the behavior's telemetry exists in the run window (its
    chain host has log rows) — DC-1 without an alert, DC-0 without either.
    """
    if not alerts_for_behavior:
        if telemetry_seen:
            return {
                "tier": "DC-1",
                "score": 1.0,
                "reason": "telemetry present in the run window, no alert fired",
                "alert_id": None,
                "elements": {},
                "blocking_elements": [],
            }
        return {
            "tier": "DC-0",
            "score": 0.0,
            "reason": "no alert and no telemetry for this behavior in the run window",
            "alert_id": None,
            "elements": {},
            "blocking_elements": [],
        }
    # Best-alert rule (published): the behavior's DC = its best alert.
    first = alerts_for_behavior[0]
    first_elements = elements_for_alert(first)
    if all(first_elements.values()):
        return {
            "tier": "DC-3",
            "score": 3.0,
            "reason": "a DC-3-complete alert exists (all six published elements)",
            "alert_id": first.get("id"),
            "elements": first_elements,
            "blocking_elements": [],
        }
    best: dict = {
        "tier": "DC-2",
        "score": 2.0,
        "reason": "alert fired but no alert carries all six DC-3 elements",
        "alert_id": first.get("id"),
        "elements": first_elements,
        "blocking_elements": dc3_blockers(first_elements),
    }
    for alert in alerts_for_behavior[1:]:
        elements = elements_for_alert(alert)
        if all(elements.values()):
            return {
                "tier": "DC-3",
                "score": 3.0,
                "reason": "a DC-3-complete alert exists (all six published elements)",
                "alert_id": alert.get("id"),
                "elements": elements,
                "blocking_elements": [],
            }
        blocking = dc3_blockers(elements)
        if len(blocking) < len(best["blocking_elements"]):
            best = {
                "tier": "DC-2",
                "score": 2.0,
                "reason": "alert fired but no alert carries all six DC-3 elements",
                "alert_id": alert.get("id"),
                "elements": elements,
                "blocking_elements": blocking,
            }
    return best


# ───────────────────────────────────────────────────────────────
# DP (case-consolidation penalty), DS (speed), weighted DC
# ───────────────────────────────────────────────────────────────


def detection_precision(tp: int, fp: int, cases: int) -> dict:
    """Published formula: DP = TP / (TP + FP + (Cases - 1)).

    Unmeasured (never a fabricated number) when there is nothing to score:
    no detections (TP == 0 and FP == 0) or no cases to count (Cases == 0).
    """
    if tp == 0 and fp == 0:
        return {"value": None, "unmeasured_reason": "no detections in the run window"}
    if cases == 0:
        return {"value": None, "unmeasured_reason": "no cases to measure consolidation against"}
    return {"value": round(tp / (tp + fp + (cases - 1)), 3)}


def ds_score(mttd_minutes: float | None) -> dict:
    """Published tier table: <15 min = 1.0 (Real-Time), 15-30 = 0.75
    (Acceptable Delay), >30 = 0.5 (Significant Delay). None MTTD = honest
    unmeasured (no derivable first-detection timestamp)."""
    if mttd_minutes is None:
        return {"score": None, "unmeasured_reason": "no derivable first-detection timestamp"}
    if mttd_minutes < 15.0:
        return {"score": 1.0, "tier": "Real-Time"}
    if mttd_minutes <= 30.0:
        return {"score": 0.75, "tier": "Acceptable Delay"}
    return {"score": 0.5, "tier": "Significant Delay"}


def weighted_dc(scores: list[tuple[float, float]]) -> dict:
    """Weighted_DC = sum(DC * ACW) / sum(ACW); normalized to /3.0."""
    total_weight = sum(w for _, w in scores)
    if total_weight <= 0:
        return {
            "weighted": None,
            "normalized": None,
            "unmeasured_reason": "no ACW-weighted behaviors scored",
        }
    weighted = sum(dc * w for dc, w in scores) / total_weight
    return {
        "weighted": round(weighted, 3),
        "normalized": round(weighted / HIGHEST_DC_SCORE, 3),
    }


# ───────────────────────────────────────────────────────────────
# IQI (reported separately from TES — published rule)
# ───────────────────────────────────────────────────────────────


def investigation_coverage(
    alert: dict | None,
    *,
    correlated: bool,
    case: dict | None,
) -> dict:
    """IC tier for ONE behavior from its best alert + the case chain.

    Core elements share the DC-3 checklist; extended elements:
    EVIDENCE (the alert carries stored evidence), CORRELATION (a multi-alert
    case or a persisted correlation match), SCOPE (the linked case spans
    more than one host), DISPOSITION (the alert or its case reached a
    resolution).
    """
    if alert is None:
        return {
            "tier": "IC-0",
            "score": 0.0,
            "core": {},
            "extended": {},
            "reason": "no alert to investigate",
        }
    core = elements_for_alert(alert)
    has_evidence = bool(alert.get("evidence"))
    multi_alert_case = bool(case and len(case.get("alert_ids") or []) >= 2)
    correlated_any = bool(correlated or multi_alert_case)
    case_alerts = (case or {}).get("alert_alerts") or []
    hosts = {
        str(a.get("host_name")) for a in case_alerts if isinstance(a, dict) and a.get("host_name")
    }
    disposition = bool(case and (case.get("resolved_at") or case.get("resolution_note")))
    extended = {
        "EVIDENCE": has_evidence,
        "CORRELATION": correlated_any,
        "SCOPE": len(hosts) > 1,
        "DISPOSITION": disposition,
    }
    core_met = sum(1 for ok in core.values() if ok)
    ext_count = sum(1 for ok in extended.values() if ok)
    if core_met == 5 and ext_count >= 3 and correlated_any:
        return {
            "tier": "IC-3",
            "score": 3.0,
            "core": core,
            "extended": extended,
            "reason": "5/5 core + correlated + >=3 extended",
        }
    if not core["HOW"]:
        # Published rule: missing HOW caps the investigation at IC-2.
        return {
            "tier": "IC-2",
            "score": 2.0,
            "core": core,
            "extended": extended,
            "reason": "HOW missing caps at IC-2",
        }
    if correlated_any or disposition:
        return {
            "tier": "IC-2",
            "score": 2.0,
            "core": core,
            "extended": extended,
            "reason": "correlated investigation (multi-alert case or correlation match)",
        }
    return {
        "tier": "IC-1",
        "score": 1.0,
        "core": core,
        "extended": extended,
        "reason": "alert enrichment only — no correlation",
    }


def analyst_precision(tp: int, fp: int, cases: int) -> dict:
    """Published AP formula (same shape as DP), evaluated at the
    INVESTIGATION layer. In an automated purple run there are no human
    conclusions to score correctness against — AP stays unmeasured unless
    the caller has real conclusion data. Never fabricated."""
    if tp == 0 and fp == 0:
        return {
            "value": None,
            "unmeasured_reason": "no investigation conclusions in the run window",
        }
    if cases == 0:
        return {"value": None, "unmeasured_reason": "no case consolidation to measure"}
    return {"value": round(tp / (tp + fp + (cases - 1)), 3)}


# ───────────────────────────────────────────────────────────────
# CS (conclusion speed) — complexity bands from the published tables
# ───────────────────────────────────────────────────────────────

_CS_BANDS: list[tuple[int, list[tuple[float, float]]]] = [
    # (band upper bound in techniques, [(max_minutes, score), ...])
    (15, [(30, 1.0), (60, 0.75), (120, 0.5), (240, 0.25)]),  # Small 1-15
    (40, [(60, 1.0), (120, 0.75), (240, 0.5), (360, 0.25)]),  # Medium 16-40
    (80, [(120, 1.0), (300, 0.75), (480, 0.5), (720, 0.25)]),  # Large 41-80
    (10**9, [(180, 1.0), (360, 0.75), (600, 0.5), (900, 0.25)]),  # Very Large 81+
]


def conclusion_speed(mtt_conclude_minutes: float | None, techniques_in_scenario: int) -> dict:
    """Published CS tables: complexity band from scenario size, then the
    speed table for that band. No conclusion = 0.0 (published), but an
    UNMEASURABLE conclusion time stays unmeasured (honesty gate)."""
    if mtt_conclude_minutes is None:
        return {
            "value": None,
            "unmeasured_reason": "no defensible conclusion yet — human adjudication pending",
        }
    for upper, table in _CS_BANDS:
        if techniques_in_scenario <= upper:
            for max_minutes, score in table:
                if mtt_conclude_minutes <= max_minutes:
                    return {"value": score, "mtt_conclude_minutes": round(mtt_conclude_minutes, 1)}
            return {"value": 0.0, "tier": "materially late"}
    return {"value": None, "unmeasured_reason": "scenario size outside the published bands"}


# ───────────────────────────────────────────────────────────────
# Full TES block for one purple run
# ───────────────────────────────────────────────────────────────


def score_tes(
    *,
    config: dict,
    chains: dict[str, bool],
    chain_hosts: dict[str, str],
    alerts: list[dict],
    matches: list[dict],
    log_first_times: dict[str, Any],
    cases: dict[int, dict],
    case_alerts: dict[int, list[dict]],
) -> dict:
    """Score one purple run against the published methodology.

    chains         : {chain_name: fired}
    chain_hosts    : {chain_name: run-unique host}
    alerts         : full alert rows for the run window (matrix hosts)
    matches        : persisted correlation matches (chain-fired evidence)
    log_first_times: {host: first telemetry timestamp in the window}
    cases          : {case_id: case row} for the run's linked cases
    case_alerts    : {case_id: alert rows in that case} (SCOPE element)
    """
    scenarios_cfg: dict[str, dict] = config.get("scenarios") or {}
    match_hosts = {m.get("host_name") for m in matches if m.get("host_name")}

    behavior_rows: list[dict] = []
    unmeasured_scenarios: list[dict] = []
    for chain, fired in sorted(chains.items()):
        sc = scenarios_cfg.get(chain)
        host = chain_hosts.get(chain, "")
        chain_alerts = [a for a in alerts if a.get("host_name") == host]
        chain_match = host in match_hosts
        telemetry = host in log_first_times or fired
        if sc is None:
            unmeasured_scenarios.append(
                {"chain": chain, "reason": "no ACW scenario in the TES config"}
            )
            continue
        cfg_techniques = {t["id"]: t for t in sc.get("techniques", [])}
        alert_techniques: set[str] = set()
        for a in chain_alerts:
            alert_techniques.update(a.get("mitre_techniques") or [])
        for tid in sorted(set(cfg_techniques) | alert_techniques):
            entry = cfg_techniques.get(tid)
            if entry is None:
                # The chain fired a technique the config does not weight —
                # honest gap, reported (never silently unweighted).
                behavior_rows.append(
                    {
                        "chain": chain,
                        "technique": tid,
                        "tier": None,
                        "acw": None,
                        "unmeasured_reason": (
                            "technique fired in the run but has no ACW weight in the config"
                        ),
                    }
                )
                continue
            behavior_alerts = [a for a in chain_alerts if tid in (a.get("mitre_techniques") or [])]
            dc = dc_tier_for_behavior(behavior_alerts, telemetry_seen=telemetry)
            first_detection = _first_detection_ts(behavior_alerts, matches, host)
            first_event = log_first_times.get(host)
            mttd = _minutes_between(first_event, first_detection)
            # DS: detection -> tier lookup; executed-but-undetected -> the
            # published "No Detection = 0.0" row; never-conducted -> N/A
            # (excluded from scoring, per the methodology's N/A rule).
            if first_detection is not None:
                ds = ds_score(mttd)
            elif telemetry:
                ds = {"score": 0.0, "tier": "No Detection"}
            else:
                ds = {"unmeasured_reason": "scenario not conducted in this run (N/A — excluded)"}
            case_row, case_id = _case_for(chain_alerts, cases)
            case_for_ic: dict[str, Any] | None = None
            if case_row is not None and case_id is not None:
                case_for_ic = {
                    **case_row,
                    "alert_alerts": case_alerts.get(case_id, []),
                }
            ic = investigation_coverage(
                behavior_alerts[0] if behavior_alerts else None,
                correlated=chain_match,
                case=case_for_ic,
            )
            behavior_rows.append(
                {
                    "chain": chain,
                    "technique": tid,
                    "tier": entry.get("tier"),
                    "acw": float(entry["acw"]),
                    "dc": dc,
                    "mttd_minutes": round(mttd, 2) if mttd is not None else None,
                    "ds": ds,
                    "ic": ic,
                }
            )

    scored = [r for r in behavior_rows if r.get("dc") is not None]
    weighted = weighted_dc([(r["dc"]["score"], r["acw"]) for r in scored])

    # DP inputs: TP = behaviors with an alert-level detection (DC-2+; DC-1
    # is telemetry-only, not a platform detection); FP = 0 IN-WINDOW
    # (labeled — see module docstring); Cases = distinct cases linked to
    # run alerts.
    tp = sum(1 for r in scored if r["dc"]["score"] >= 2.0)
    run_case_ids = {a.get("case_id") for a in alerts if a.get("case_id") is not None}
    dp = detection_precision(tp=tp, fp=0, cases=len(run_case_ids))
    dp["tp"] = tp
    dp["fp"] = 0
    dp["cases"] = len(run_case_ids)

    ds_entries = [r["ds"] for r in scored if r.get("ds")]
    ds_scores = [d["score"] for d in ds_entries if d.get("score") is not None]
    # N/A (not-conducted) behaviors are excluded per the methodology's N/A
    # rule; the mean runs over the behaviors that have a speed score.
    ds_norm = round(sum(ds_scores) / len(ds_scores), 3) if ds_scores else None

    dqi = None
    if weighted["normalized"] is not None and dp.get("value") is not None and ds_norm is not None:
        dqi = round((weighted["normalized"] + dp["value"] + ds_norm) / 3.0, 3)

    # IQI: Weighted_IC from the case/evidence chain; AP and CS are
    # platform-side proxies — AP stays unmeasured (no human conclusions in
    # an automated run), CS is measured ONLY where a case carries a
    # resolution timestamp. The aggregate is unmeasured unless ALL three
    # components measure (published IQI formula).
    ic_pairs = [(r["ic"]["score"], r["acw"]) for r in scored if r.get("ic") is not None]
    ic_weighted = weighted_dc(ic_pairs)
    ap = analyst_precision(tp=0, fp=0, cases=len(run_case_ids))
    resolved_cases = [c for c in cases.values() if c.get("resolved_at")]
    if run_case_ids and resolved_cases:
        first_alert = min((a["time"] for a in alerts), default=None)
        conclusion = min(c["resolved_at"] for c in resolved_cases)
        mtt_conclude = _minutes_between(first_alert, conclusion)
        cs = conclusion_speed(mtt_conclude, techniques_in_scenario=len(scored))
    else:
        cs = conclusion_speed(None, len(scored))
    iqi_components = [
        ic_weighted.get("normalized"),
        ap.get("value"),
        cs.get("value"),
    ]
    measured = [v for v in iqi_components if v is not None]
    iqi = round(sum(measured) / 3.0, 3) if len(measured) == 3 else None
    unmeasured_reasons = [
        label
        for label, v in zip(
            ("Weighted_IC_normalized", "AP", "CS_normalized"), iqi_components, strict=True
        )
        if v is None
    ]

    return {
        "methodology": "MITRE ATT&CK Evaluations Enterprise 2026 — TES, self-scored",
        "methodology_source": "https://evals.mitre.org/methodology-specification",
        "label": "self-scored against the published methodology; NOT program participation",
        "modifier": "(P) for DQI — platform-produced detections",
        "pq": {
            "scored": False,
            "reason": (
                "detection-only run: no protection/blocked stages execute, so "
                "PC/PP (and PQI) are not scored — never inferred"
            ),
        },
        "config_sha256": config.get("config_sha256"),
        "weighted_dc": weighted,
        "behaviors": behavior_rows,
        "dp": dp,
        "ds_normalized": ds_norm,
        "dqi": dqi,
        "iqi": {
            "weighted_ic_normalized": ic_weighted.get("normalized"),
            "ap": ap,
            "cs": cs,
            "value": iqi,
            "unmeasured_reasons": unmeasured_reasons,
        },
        "tes": dqi,  # detection-only: the TES line reports DQI (PQI not scored)
        "unmeasured_scenarios": unmeasured_scenarios,
    }


def _first_detection_ts(alerts: list[dict], matches: list[dict], host: str) -> Any:
    ts = [a.get("time") for a in alerts if a.get("host_name") == host]
    ts += [m.get("created_at") for m in matches if m.get("host_name") == host]
    return min((t for t in ts if t is not None), default=None)


def _minutes_between(start: Any, end: Any) -> float | None:
    if start is None or end is None:
        return None
    try:
        start_dt = (
            start
            if isinstance(start, datetime)
            else datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        )
        end_dt = (
            end
            if isinstance(end, datetime)
            else datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        )
        delta: timedelta = end_dt - start_dt
        return max(delta.total_seconds() / 60.0, 0.0)
    except (TypeError, ValueError):
        return None


def _case_for(chain_alerts: list[dict], cases: dict[int, dict]) -> tuple[dict | None, int | None]:
    for a in chain_alerts:
        cid = a.get("case_id")
        if cid is not None and cid in cases:
            return cases[cid], cid
    return None, None


def render_tes_md(tes: dict) -> str:
    """Render the TES section of the report (self-scored labels first)."""
    lines = [
        "## TES-aligned scoring (SELF-SCORED)",
        "",
        "Methodology: MITRE ATT&CK Evaluations Enterprise 2026 — self-scored,",
        "NOT program participation. Detection-only run: PQI is not scored;",
        "the TES line below reports DQI alone.",
        "",
    ]
    wd = tes.get("weighted_dc") or {}
    if wd.get("normalized") is not None:
        lines.append(f"- Weighted DC (ACW, /3.0): **{wd['normalized']}** (raw {wd['weighted']})")
    else:
        lines.append(f"- Weighted DC: unmeasured — {wd.get('unmeasured_reason')}")
    dp = tes.get("dp") or {}
    if dp.get("value") is not None:
        lines.append(
            f"- Detection Precision (case-consolidation penalty): **{dp['value']}** "
            f"(TP={dp['tp']}, FP={dp['fp']}, Cases={dp['cases']})"
        )
    else:
        lines.append(f"- Detection Precision: unmeasured — {dp.get('unmeasured_reason')}")
    if tes.get("ds_normalized") is not None:
        lines.append(f"- Detection Speed (normalized): **{tes['ds_normalized']}**")
    else:
        lines.append("- Detection Speed: unmeasured (at least one MTTD not derivable)")
    if tes.get("dqi") is not None:
        lines.append(f"- **DQI (detection-only TES): {tes['dqi']}** / 1.0")
    else:
        lines.append("- DQI: unmeasured (a component above is unmeasured — honesty gate)")
    iqi = tes.get("iqi") or {}
    if iqi.get("value") is not None:
        lines.append(f"- IQI (reported separately, per methodology): **{iqi['value']}** / 1.0")
    else:
        lines.append(
            "- IQI (reported separately): unmeasured — "
            + "; ".join(iqi.get("unmeasured_reasons") or [])
        )
    lines += [
        "",
        "| Behavior | Chain | ACW | DC | Blocking (DC-3 elements) | MTTD min | IC |",
        "|:--|:--|:--|:--|:--|:--|:--|",
    ]
    for r in tes.get("behaviors", []):
        dc = r.get("dc") or {}
        ic = r.get("ic") or {}
        mttd = r.get("mttd_minutes")
        if r.get("unmeasured_reason"):
            lines.append(
                f"| {r['technique']} | {r['chain']} | {r.get('acw')} | "
                f"unmeasured ({r['unmeasured_reason']}) | | | |"
            )
            continue
        lines.append(
            f"| {r['technique']} | {r['chain']} | {r.get('acw')} | {dc.get('tier')} "
            f"({dc.get('score')}) | {', '.join(dc.get('blocking_elements') or []) or '-'} "
            f"| {mttd if mttd is not None else 'unmeasured'} | {ic.get('tier')} |"
        )
    if tes.get("unmeasured_scenarios"):
        lines += ["", "### Unmeasured scenarios", ""]
        for item in tes["unmeasured_scenarios"]:
            lines.append(f"- **{item['chain']}**: {item['reason']}")
    return "\n".join(lines) + "\n"
