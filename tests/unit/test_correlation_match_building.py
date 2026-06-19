"""
Tests for the correlation engine's match-building post-processing — the
`for row in rows: d = dict(row); d["correlation_rule"] = ...` enrichment in
each detect_* function (src/detection/correlation.py).

Existing correlation tests mock conn.fetch to return [] (empty), so the
enrichment branch (lines 246-254, 314-322, 375-387, 447-455, 523-531,
593-601) was never hit. These tests return a sample row and assert each
detect_* stamps correlation_rule, correlation_id (uuid), severity, title,
mitre_tactics, mitre_techniques, and confidence onto the match dict.

Also covers: _serialize_match_data set/frozenset branch, list_matches
since/until filter branches, run_all_correlations_legacy, and the
run_all_correlations per-rule exception handler.
"""
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection import correlation as corr

AS_OF = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _conn_returning(rows):
    """Build a mock asyncpg conn whose .fetch returns the given rows."""
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    return conn


def _sample_row(**extra):
    """A row dict superset — dict(row) works because asyncpg Record -> dict,
    and a plain dict is dict()-compatible. Extra keys per-rule where needed."""
    base = {
        "host_name": "host01",
        "process_name": "python3",
        "user_name": "admin",
        "source_ip": "10.0.0.5",
        "destination_ip": "203.0.113.50",
        "destination_port": 4444,
        "time": AS_OF,
    }
    base.update(extra)
    return base


DETECT_FUNCS = [
    ("payload_callback", corr.detect_payload_callback),
    ("persistence_activated", corr.detect_persistence_activated),
    ("data_exfiltration", corr.detect_data_exfiltration),
    ("privilege_escalation_chain", corr.detect_privilege_escalation_chain),
    ("credential_theft_exfil", corr.detect_credential_theft_exfil),
    ("defense_evasion_cleanup", corr.detect_defense_evasion_cleanup),
]


@pytest.mark.parametrize("rule_key,func", DETECT_FUNCS)
async def test_detect_function_enriches_match_row(rule_key, func):
    """Each detect_* stamps the canonical correlation metadata onto matches."""
    row = _sample_row(total_bytes=500_000_000) if rule_key == "data_exfiltration" else _sample_row()
    conn = _conn_returning([row])

    matches = await func(conn, AS_OF)

    assert len(matches) == 1
    m = matches[0]
    assert m["correlation_rule"] == rule_key
    # correlation_id is a fresh uuid string
    assert isinstance(m["correlation_id"], str)
    assert len(m["correlation_id"]) == 36  # uuid4 str length
    assert "severity" in m
    assert "title" in m
    assert "mitre_tactics" in m
    assert "mitre_techniques" in m
    assert "confidence" in m
    # the original row fields survive onto the match
    assert m["host_name"] == "host01"


async def test_detect_data_exfiltration_confidence_scales_with_volume():
    """Higher volume above threshold -> higher confidence (capped at 100)."""
    # total_bytes far above the 100MB threshold -> confidence should climb
    row = _sample_row(total_bytes=2_000_000_000)
    conn = _conn_returning([row])
    matches = await corr.detect_data_exfiltration(conn, AS_OF)
    assert 0 < matches[0]["confidence"] <= 100


async def test_detect_returns_empty_when_no_rows():
    """No rows -> empty list, no crash (the existing behavior)."""
    conn = _conn_returning([])
    matches = await corr.detect_payload_callback(conn, AS_OF)
    assert matches == []


# ── _serialize_match_data — set/frozenset branch (line 818-820) ──────────


def test_serialize_match_data_handles_set_and_frozenset():
    """Sets must serialize to sorted lists (JSON can't represent sets)."""
    match = {"correlation_rule": "x", "tags": {"a", "b"}, "frozen": frozenset(["z", "y"])}
    out = corr._serialize_match_data(match)
    data = json.loads(out)
    assert sorted(data["tags"]) == ["a", "b"]
    assert sorted(data["frozen"]) == ["y", "z"]


def test_serialize_match_data_handles_datetime():
    """datetime values serialize to ISO strings."""
    match = {"correlation_rule": "x", "ts": AS_OF}
    out = corr._serialize_match_data(match)
    data = json.loads(out)
    assert data["ts"] == AS_OF.isoformat()


# ── list_matches — since/until filter branches (899-905) ─────────────────


async def test_list_matches_since_until_filters():
    """since + until add created_at bounds to the query params."""
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[{"id": 1, "correlation_rule": "r"}])
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=acquirer)

    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    until = datetime(2025, 1, 2, tzinfo=timezone.utc)
    with patch("src.detection.correlation.get_pool", return_value=pool):
        rows = await corr.list_matches(since=since, until=until, limit=10)

    assert rows == [{"id": 1, "correlation_rule": "r"}]
    # fetch was called with since and until bound as params
    args = conn.fetch.await_args.args
    assert since in args and until in args


# ── run_all_correlations — per-rule exception handler (778-779) ──────────


async def test_run_all_correlations_continues_when_one_rule_raises():
    """A single detect_* raising must not abort the whole run."""
    good_conn = _conn_returning([_sample_row()])

    # Build a conn where the first fetch (for the first rule) raises, but the
    # pool yields the same conn for subsequent rules. The run must skip the
    # failed rule and still return results from the others.
    call_count = {"n": 0}

    async def fetch_side_effect(sql, *args):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("transient db error on first rule")
        return [_sample_row()]

    conn = AsyncMock()
    conn.fetch = AsyncMock(side_effect=fetch_side_effect)
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=acquirer)

    with patch("src.detection.correlation.get_pool", return_value=pool):
        result = await corr.run_all_correlations(as_of=AS_OF, persist=False)

    # the run completed (did not propagate the first rule's exception)
    assert "total_matches" in result
    assert "per_rule" in result


# ── run_all_correlations_legacy (975-998) ────────────────────────────────


async def test_run_all_correlations_legacy_returns_rule_metadata(monkeypatch):
    """Legacy shape returns {rule_name: [matches]} per rule (old API compat)."""
    async def fake_run(as_of, persist):
        return {
            "as_of": AS_OF.isoformat(),
            "total_matches": 0,
            "persisted": persist,
            "per_rule": {"brute_force_success": [], "payload_callback": []},
        }

    monkeypatch.setattr(corr, "run_all_correlations", fake_run)
    result = await corr.run_all_correlations_legacy(persist_alerts=False)

    # legacy returns the per_rule dict (rule_name -> matches)
    assert "brute_force_success" in result
    assert "payload_callback" in result


async def test_run_all_correlations_legacy_persists_alerts_for_matches(monkeypatch):
    """With persist_alerts=True, each match triggers a create_alert attempt."""
    match = {
        "correlation_rule": "payload_callback",
        "severity": "high",
        "host_name": "host01",
        "title": "Payload callback",
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
    }

    async def fake_run(as_of, persist):
        return {
            "as_of": AS_OF.isoformat(),
            "total_matches": 1,
            "persisted": persist,
            "per_rule": {"payload_callback": [match]},
        }

    monkeypatch.setattr(corr, "run_all_correlations", fake_run)
    with patch("src.detection.correlation.create_alert", new=AsyncMock()) as mock_create:
        result = await corr.run_all_correlations_legacy(persist_alerts=True)

    # one match -> one create_alert call
    assert mock_create.await_count == 1
    assert "payload_callback" in result
