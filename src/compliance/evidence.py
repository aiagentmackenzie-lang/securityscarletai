"""Compliance evidence assembly (V0.7 -- Group E).

The incident evidence pack: one alert's full chain -- alert, correlation
match, case + case_events timeline, response actions with the four-eyes
approval + verification trail, quarantine state, and the related audit
receipts -- serialized as a regulator-consumable JSON document, designed
against the UK CS&R 24h/72h reporting cadence.

Integrity posture (honest): the pack is a CONVENIENCE PROJECTION. The
tamper-evident source of truth is the audit chain (audit_log, DB-enforced
append-only in the two-role posture) plus the raw telemetry tables. Every
object in the pack names the table(s) it came from so a regulator can
re-derive any number from the chain itself.

Read-only: this module only SELECTs. The export action itself is audited
by the API layer (compliance.evidence_pack_export).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.db.jsonb import load_jsonb

log = get_logger("compliance.evidence")

# UK CS&R reporting cadence (HL Bill 32): initial notification within 24h
# of becoming aware, full report within 72h. Encoded here so the pack
# carries the due dates computed from the incident's own timestamps.
INITIAL_NOTIFICATION_HOURS = 24
FINAL_REPORT_HOURS = 72

# Sources that must NOT ride into a regulator pack (never fabricate or
# leak): raw_data can carry sensitive payload content; the pack references
# it by table instead.
_PACK_LIMITS = {
    "max_case_events": 200,
    "max_audit_receipts": 100,
    "max_response_actions": 50,
    "max_correlation_matches": 20,
}


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


async def build_evidence_pack(alert_id: int, as_of: Optional[datetime] = None) -> Optional[dict]:
    """Build the evidence pack for one alert, or None if the alert does not exist.

    Every section carries a `sources` list naming the exact tables the
    data came from (regulator-consumable provenance). Never raises on
    missing related objects: an alert without a case or correlation still
    produces an honest pack.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            """
            SELECT id, time, rule_id, rule_name, severity, status, host_name,
                   description, mitre_tactics, mitre_techniques, evidence,
                   risk_score, assigned_to, resolved_at, resolution_note,
                   case_id, created_at, updated_at
            FROM alerts WHERE id = $1
            """,
            alert_id,
        )
        if not alert:
            return None

        correlation_matches = await _correlation_matches(conn, alert)
        case_block = await _case_block(conn, alert["case_id"], alert_id)
        audit_receipts, audit_truncated = await _audit_receipts(
            conn,
            alert_id=alert_id,
            case_id=alert["case_id"],
            action_ids=[a["id"] for a in case_block.get("response_actions", [])],
        )

    pack = {
        "document": {
            "kind": "incident_evidence_pack",
            "version": 1,
            "generated_at": as_of.isoformat(),
            "standards_note": (
                "the tamper-evident source of truth is the append-only audit "
                "chain; this pack is a convenience projection with provenance "
                "pointing back at the chain"
            ),
        },
        "reporting_cadence": {
            "regime": "UK Cyber Security & Resilience Bill",
            "initial_notification_due_hours": INITIAL_NOTIFICATION_HOURS,
            "final_report_due_hours": FINAL_REPORT_HOURS,
            "incident_detected_at": _iso(alert_time_or_created(alert)),
            "initial_notification_due": _iso(
                _shift(alert_time_or_created(alert), INITIAL_NOTIFICATION_HOURS)
            ),
            "final_report_due": _iso(_shift(alert_time_or_created(alert), FINAL_REPORT_HOURS)),
            "note": (
                "due dates are computed from the SIEM's detection timestamp; "
                "the duty-holder's awareness clock may differ -- this pack is "
                "an input to the report, not the report itself"
            ),
        },
        "incident": {
            "alert_id": alert["id"],
            "detected_at": _iso(alert["time"]),
            "rule_name": alert["rule_name"],
            "severity": alert["severity"],
            "status": alert["status"],
            "host_name": alert["host_name"],
            "description": alert["description"],
            "mitre_tactics": alert["mitre_tactics"] or [],
            "mitre_techniques": alert["mitre_techniques"] or [],
            "risk_score": alert["risk_score"],
            "assigned_to": alert["assigned_to"],
            "resolved_at": _iso(alert["resolved_at"]),
            "resolution_note": alert["resolution_note"],
            "evidence_excerpt": _safe_evidence(alert["evidence"]),
            "notes": _safe_notes(alert["notes"]),
            "sources": ["alerts"],
        },
        "correlation": correlation_matches,
        "case": case_block,
        "audit_receipts": audit_receipts,
        # W4-C: say when the bounded slice cut anything (the pack is
        # regulator-facing; a silently-dropped section is a lie by omission).
        "audit_receipts_truncated": audit_truncated,
    }
    return pack


def alert_time_or_created(alert) -> datetime:
    value = alert["time"] or alert["created_at"]
    if not isinstance(value, datetime):
        raise ValueError("alert row must carry a timestamp for the cadence block")
    return value


def _shift(dt: datetime, hours: int) -> datetime:
    return dt + timedelta(hours=hours)


async def _correlation_matches(conn, alert) -> list[dict]:
    """Correlation matches tied to this alert, if any.

    Correlation-origin alerts carry the match's correlation_id inside their
    evidence blob ({"match": {..., "correlation_id": ...}}). Resolve via
    that id; fall back to (rule_name, host) within a bounded window. There
    is no FK between the two tables by design (correlation_matches may be a
    hypertable-side table; see V0.5c).
    """
    evidence = _safe_evidence(alert["evidence"])
    correlation_id = None
    if isinstance(evidence, dict):
        match = evidence.get("match")
        if isinstance(match, dict):
            correlation_id = match.get("correlation_id")
    if not correlation_id:
        return []
    rows = await conn.fetch(
        """
        SELECT id, correlation_rule, severity, match_data, trigger_event_id,
               seen, created_at
        FROM correlation_matches
        WHERE match_data->>'correlation_id' = $1
        LIMIT $2
        """,
        str(correlation_id),
        _PACK_LIMITS["max_correlation_matches"],
    )
    return [
        {
            "match_id": r["id"],
            "correlation_rule": r["correlation_rule"],
            "severity": r["severity"],
            "seen": r["seen"],
            "created_at": _iso(r["created_at"]),
            "match_data": load_jsonb(r["match_data"]),
            "sources": ["correlation_matches"],
        }
        for r in rows
    ]


async def _case_block(conn, case_id: Optional[int], alert_id: int) -> dict:
    if case_id is None:
        return {
            "case": None,
            "timeline": [],
            "timeline_truncated": False,
            "response_actions": [],
            "response_actions_truncated": False,
            "quarantine": [],
        }
    case = await conn.fetchrow(
        """
        SELECT id, title, description, status, severity, assigned_to,
               lessons_learned, resolution_note, resolved_at, created_at, updated_at
        FROM cases WHERE id = $1
        """,
        case_id,
    )
    if not case:
        return {
            "case": None,
            "timeline": [],
            "timeline_truncated": False,
            "response_actions": [],
            "response_actions_truncated": False,
            "quarantine": [],
        }
    # W4-C: newest-first (DESC). A regulator pack must carry the NEWEST
    # evidence — the verdict lives at the end of the timeline, and the old
    # ASC LIMIT silently dropped it out of the pack on a big case. The
    # *_truncated flags say so when the slice cut anything.
    events = await conn.fetch(
        """
        SELECT id, event_type, actor, actor_kind, payload, alert_id, action_id, created_at
        FROM case_events
        WHERE case_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        """,
        case_id,
        _PACK_LIMITS["max_case_events"],
    )
    actions = await conn.fetch(
        """
        SELECT id, action_type, params, policy_effect, status, requested_by,
               justification, approved_by, approval_note, rejection_reason,
               executed_at, verified_at, evidence, rollback_note, created_at, updated_at
        FROM response_actions
        WHERE case_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        """,
        case_id,
        _PACK_LIMITS["max_response_actions"],
    )
    quarantine = await conn.fetch(
        """
        SELECT host_name, reason, quarantined_by, quarantined_at
        FROM quarantined_hosts
        WHERE host_name = (SELECT host_name FROM alerts WHERE id = $1)
        """,
        alert_id,
    )
    return {
        "case": {
            "id": case["id"],
            "title": case["title"],
            "description": case["description"],
            "status": case["status"],
            "severity": case["severity"],
            "assigned_to": case["assigned_to"],
            "lessons_learned": case["lessons_learned"],
            "resolution_note": case["resolution_note"],
            "resolved_at": _iso(case["resolved_at"]),
            "created_at": _iso(case["created_at"]),
            "sources": ["cases"],
        },
        "timeline": [
            {
                "event_id": e["id"],
                "event_type": str(e["event_type"]),
                "actor": e["actor"],
                "actor_kind": e["actor_kind"],
                "payload": load_jsonb(e["payload"]),
                "created_at": _iso(e["created_at"]),
                "sources": ["case_events"],
            }
            for e in events
        ],
        "timeline_truncated": len(events) == _PACK_LIMITS["max_case_events"],
        "response_actions": [
            {
                "id": a["id"],
                "action_type": str(a["action_type"]),
                "policy_effect": a["policy_effect"],
                "status": str(a["status"]),
                "requested_by": a["requested_by"],
                "justification": a["justification"],
                "approved_by": a["approved_by"],
                "approval_note": a["approval_note"],
                "rejection_reason": a["rejection_reason"],
                "executed_at": _iso(a["executed_at"]),
                "verified_at": _iso(a["verified_at"]),
                "verification_evidence": load_jsonb(a["evidence"]),
                "rollback_note": a["rollback_note"],
                "sources": ["response_actions"],
            }
            for a in actions
        ],
        "response_actions_truncated": len(actions) == _PACK_LIMITS["max_response_actions"],
        "quarantine": [
            {
                "host_name": q["host_name"],
                "reason": q["reason"],
                "quarantined_by": q["quarantined_by"],
                "quarantined_at": _iso(q["quarantined_at"]),
                "sources": ["quarantined_hosts"],
            }
            for q in quarantine
        ],
    }


def _pack_targets(
    alert_id: int, case_id: Optional[int], action_ids: list[int]
) -> dict[str, list[int]]:
    """The audit targets this incident touches, grouped by target_type."""
    grouped: dict[str, list[int]] = {"alert": [alert_id]}
    if case_id is not None:
        grouped["case"] = [case_id]
    if action_ids:
        grouped["response_action"] = list(action_ids)
    return grouped


async def _audit_receipts(
    conn, alert_id: int, case_id: Optional[int], action_ids: list[int]
) -> tuple[list[dict], bool]:
    """Audit-chain receipts for the incident's objects (bounded).

    The audit chain is the tamper-evident record; these receipts let the
    regulator's reviewer find the chain rows without knowing the ids.
    W4-C: newest-first per target (DESC) — the old ASC LIMIT dropped the
    newest audit rows out of the pack; returns (receipts, truncated).
    """
    receipts: list[dict] = []
    truncated = False
    for ttype, ids in _pack_targets(alert_id, case_id, action_ids).items():
        rows = await conn.fetch(
            """
            SELECT id, actor, action, target_type, target_id, created_at
            FROM audit_log
            WHERE target_type = $1 AND target_id = ANY($2::int[])
            ORDER BY created_at DESC
            LIMIT $3
            """,
            ttype,
            ids,
            _PACK_LIMITS["max_audit_receipts"],
        )
        if len(rows) == _PACK_LIMITS["max_audit_receipts"]:
            truncated = True
        receipts.extend(
            {
                "audit_id": r["id"],
                "actor": r["actor"],
                "action": r["action"],
                "target_type": r["target_type"],
                "target_id": r["target_id"],
                "created_at": _iso(r["created_at"]),
                "sources": ["audit_log (append-only in the two-role posture)"],
            }
            for r in rows
        )
    return receipts, truncated


def _safe_evidence(evidence: Any) -> Any:
    """The alert's evidence blob may carry ingest payload content; the pack
    carries it VERBATIM (it is the alert's own record) but as parsed JSON,
    never raw text injection material."""
    return load_jsonb(evidence)


def _safe_notes(notes: Any) -> list[dict]:
    value = load_jsonb(notes)
    return value if isinstance(value, list) else []
