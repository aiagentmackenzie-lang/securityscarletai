"""Evidence-driven detection coverage (V0.3 — the detectability map).

The old MITRE heatmap counted RULES per technique ("rule exists"). That is
an aspirational number: a rule whose telemetry source does not exist on the
host cannot fire, and counting it inflates coverage — the detectability
trap detection engineering is moving away from (SANS 2026: identity is the
named visibility gap; 45% of SOCs don't monitor nontraditional assets).

This module answers the buyer-grade question instead:

    Which rules can actually fire on the telemetry this deployment ingests?

Armed  = the rule's required telemetry (category/action vocabulary buckets,
         process-name probes, alert severities, external sources) was seen
         in the lookback window. It does NOT guarantee a specific TTP fired —
         it guarantees the SOURCE exists.
Dormant-by-source = the rule selects vocabulary no ingested producer emits
         (Windows/AD verbs, cloud SaaS actions) — honest future-source
         waiver, surfaced instead of silently never firing.
Dormant = source ingested but the required vocabulary has not been seen in
         the lookback (e.g. auth shipper disabled → brute-force chain
         dormant; FIM unvalidated → file-signal rules dormant).

Cost: a handful of grouped bucket queries per run, no per-rule scans.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.correlation import CORRELATION_RULES

log = get_logger("detection.coverage")

# Categories our producers can actually emit (osquery parser vocabulary,
# auth shipper, NeuralGuard/AI-firewall ingesters, API ingest convention).
# Sigma rules selecting outside this set are DORMANT-BY-SOURCE.
INGESTED_CATEGORIES = {
    "process",
    "network",
    "file",
    "authentication",
    "configuration",
    "intrusion_detection",
}

# Correlation-chain requirements in bucket form. Bucket = (category, action)
# or (category, None) = any action in that category. "all"/"any" semantics
# per rule. Special buckets:
#   ("alerts", "high_or_critical") — fired high/critical alerts
#   ("enrichment", "bytes")        — ingesters carrying byte counts
CORRELATION_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "brute_force_success": {
        "all": [("authentication", "auth_failed"), ("authentication", "auth_success")],
        "note": "requires the auth shipper (sshd) — osquery has no auth-failure table",
    },
    "payload_callback": {
        "all": [("process", "process_start"), ("network", "network_connection")],
    },
    "persistence_activated": {
        "all": [("file", None), ("process", "process_start")],
        "note": "file telemetry needs FIM (osquery-fim.conf) or synthetic file_events",
    },
    "data_exfiltration": {
        "any": [("network", "network_connection"), ("enrichment", "bytes")],
        "note": "burst path arms on socket telemetry; volume path needs bytes-sent ingesters",
    },
    "privilege_escalation_chain": {
        "all": [("process", "process_start")],
        "process_names": ["sudo", "su", "doas"],
        "note": "also requires an interactive/user-writable root process",
    },
    "credential_theft_exfil": {
        "any": [("file", None), ("process", "process_start")],
        "note": "cmdline path (non-ssh .ssh access) arms today; file path needs FIM",
    },
    "defense_evasion_cleanup": {
        "all": [("alerts", "high_or_critical"), ("process", "process_start")],
    },
    "ai_verdict_block_sustained": {
        "all": [("intrusion_detection", "verdict_block")],
        "note": "needs NeuralGuard (or equivalent AI-firewall) events via POST /ingest",
    },
}

# Process names probed in the armed check (one grouped query, not per-rule).
_PROBED_PROCESS_NAMES = ("sudo", "su", "doas", "launchctl", "rm")


def extract_sigma_requirements(sigma_yaml: str) -> dict[str, Any]:
    """Pull the telemetry requirements a Sigma rule selects on.

    Returns {"category": str|None, "action_tokens": [str], "fields": [str]}.
    Only event_action/event_type keys in the detection selections count as
    vocabulary requirements; field selections (process_cmdline contains …)
    shape WHICH events fire, not WHETHER the source exists.
    """
    doc = yaml.safe_load(sigma_yaml) or {}
    logsource = doc.get("logsource") or {}
    detection = doc.get("detection") or {}
    category = logsource.get("category")
    action_tokens: list[str] = []
    fields: list[str] = []
    for key, selection in detection.items():
        if key in ("condition", "timeframe") or not isinstance(selection, dict):
            continue
        for sel_key in selection:
            field = sel_key.split("|")[0].strip()
            if field == "event_action":
                value = selection[sel_key]
                values = value if isinstance(value, list) else [value]
                # Exact and |contains modifiers both arm on token presence —
                # the bucket matcher applies contains semantics, so both
                # reduce to token collection.
                action_tokens.extend(str(v) for v in values)
            else:
                fields.append(field)
    return {"category": category, "action_tokens": action_tokens, "fields": fields}


def _bucket_present(buckets: dict, category: str | None, action: str | None) -> bool:
    """Is telemetry present for (category, action)? action=None = any action.

    Action matching follows the Sigma |contains semantics: a selected token
    ('failed', 'verdict_block') arms against a bucket whose action contains
    or equals it — so the closed vocabulary tokens match while future-source
    verbs (tgs_request, ntlm_auth) correctly do NOT.
    """
    if action is None:
        return any(k[0] == category for k in buckets)
    if category is None:
        return any(k[1] == action for k in buckets)
    return (category, action) in buckets or any(
        k[0] == category and k[1] and action.lower() in k[1].lower() for k in buckets
    )


def _correlation_armed(rule: str, buckets: dict, probed_names: set) -> tuple[bool, str]:
    req = CORRELATION_REQUIREMENTS.get(rule)
    if not req:
        return False, "no coverage requirement defined"
    if "all" in req:
        ok = all(_bucket_present(buckets, c, a) for c, a in req["all"])
    else:  # any
        ok = any(_bucket_present(buckets, c, a) for c, a in req["any"])
    if ok and req.get("process_names"):
        ok = bool(probed_names & set(req["process_names"]))
    return ok, req.get("note", "")


async def compute_coverage(lookback_hours: int = 168, as_of: datetime | None = None) -> dict:
    """Compute per-rule armed/dormant status + technique rollup.

    Returns {"summary": {...}, "rules": [...], "techniques": [...]} — the
    evidence-driven heatmap payload (rules whose telemetry exists, not
    rules that merely exist).
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    lookback_start = as_of - timedelta(hours=lookback_hours)
    pool = await get_pool()
    async with pool.acquire() as conn:
        action_buckets = {
            (row["event_category"], row["event_action"]): row["cnt"]
            for row in await conn.fetch(
                """
                SELECT event_category, event_action, COUNT(*) AS cnt
                FROM logs
                WHERE time > $1::timestamptz AND event_action IS NOT NULL
                GROUP BY event_category, event_action
                """,
                lookback_start,
            )
        }
        category_counts = {
            row["event_category"]: row["cnt"]
            for row in await conn.fetch(
                """
                SELECT event_category, COUNT(*) AS cnt
                FROM logs WHERE time > $1::timestamptz GROUP BY event_category
                """,
                lookback_start,
            )
        }
        name_rows = await conn.fetch(
            """
            SELECT DISTINCT process_name
            FROM logs
            WHERE event_category = 'process'
              AND event_type = 'start'
              AND process_name = ANY($2::text[])
              AND time > $1::timestamptz
            """,
            lookback_start,
            list(_PROBED_PROCESS_NAMES),
        )
        probed_names = {r["process_name"] for r in name_rows}
        high_crit_alerts = await conn.fetchval(
            """
            SELECT COUNT(*) FROM alerts
            WHERE severity IN ('high', 'critical')
              AND time > $1::timestamptz
            """,
            lookback_start,
        )
        bytes_seen = await conn.fetchval(
            "SELECT COUNT(*) FROM logs WHERE enrichment ? 'bytes_sent' AND time > $1::timestamptz",
            lookback_start,
        )

    # Live bucket snapshot for this run (shared across rules — read-only).
    req_buckets = {**action_buckets}
    # (category, None) buckets: rows in the category with ANY action value,
    # including NULL-action rows — the "any action" armed check.
    for cat, cnt in category_counts.items():
        req_buckets.setdefault((cat, None), cnt)
    if high_crit_alerts:
        req_buckets[("alerts", "high_or_critical")] = high_crit_alerts
    if bytes_seen:
        req_buckets[("enrichment", "bytes")] = bytes_seen

    output_rules: list[dict] = []

    # Correlation chains — hand-authored requirements.
    for rule_name, meta in CORRELATION_RULES.items():
        armed, note = _correlation_armed(rule_name, req_buckets, probed_names)
        output_rules.append(
            {
                "name": rule_name,
                "kind": "correlation",
                "title": meta["title"],
                "severity": meta["severity"],
                "mitre_tactics": meta["mitre_tactics"],
                "mitre_techniques": meta["mitre_techniques"],
                "armed": armed,
                "reason": note if not armed else "",
            }
        )

    # Sigma rules — sourced from the rules table (runtime truth, reconciled
    # from disk on boot). Requirements from the stored sigma_yaml.
    rule_rows = await conn.fetch(
        """
        SELECT name, severity, mitre_tactics, mitre_techniques, sigma_yaml
        FROM rules
        WHERE enabled = TRUE
        """
    )
    for row in rule_rows:
        req = extract_sigma_requirements(row["sigma_yaml"] or "")
        category = req["category"]
        tokens = req["action_tokens"]
        if category is not None and category not in INGESTED_CATEGORIES:
            armed, reason = False, f"source category '{category}' not ingested"
        elif tokens:
            # A rule with action requirements is armed iff ANY selected
            # token has a matching telemetry bucket (|contains semantics).
            armed = any(_bucket_present(req_buckets, category, tok) for tok in tokens)
            reason = "" if armed else "vocabulary not observed in lookback"
        else:
            armed = _bucket_present(req_buckets, category, None)
            reason = "" if armed else f"no '{category}' telemetry in lookback"
        output_rules.append(
            {
                "name": row["name"],
                "kind": "sigma",
                "severity": row["severity"],
                "mitre_tactics": row["mitre_tactics"] or [],
                "mitre_techniques": row["mitre_techniques"] or [],
                "armed": armed,
                "reason": reason,
            }
        )

    armed_count = sum(1 for r in output_rules if r["armed"])
    techniques: dict[str, dict[str, Any]] = {}
    for r in output_rules:
        for tech in r["mitre_techniques"]:
            entry = techniques.setdefault(tech, {"rules": 0, "armed_rules": 0})
            entry["rules"] += 1
            entry["armed_rules"] += int(r["armed"])

    return {
        "summary": {
            "total_rules": len(output_rules),
            "armed": armed_count,
            "dormant": len(output_rules) - armed_count,
            "lookback_hours": lookback_hours,
            "as_of": as_of.isoformat() if as_of else datetime.now(timezone.utc).isoformat(),
        },
        "rules": output_rules,
        "techniques": sorted(
            (
                {"technique": t, "rules": v["rules"], "armed_rules": v["armed_rules"]}
                for t, v in techniques.items()
            ),
            key=lambda x: (-x["armed_rules"], x["technique"]),
        ),
    }
