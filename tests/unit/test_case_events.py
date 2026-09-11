"""
Tests for the V0.4 durable case object: case events, verdicts, timeline,
summary, and the governance gates (no resolve/close without a verdict).

Covers:
- CaseVerdict model validation (closed verdict vocabulary, rationale
  required, confidence bounds)
- _record_case_event helper (success path + never-breaks-the-mutation)
- The verdict gate on PATCH (resolve/close) and on the soft-delete endpoint
- POST /verdict endpoint (happy path, unknown case, unknown alert)
- GET /timeline and GET /summary endpoints
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.api.cases import VERDICTS, CaseVerdict, _record_case_event

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _make_user(role: str = "analyst", username: str = "testuser") -> dict:
    return {"sub": username, "role": role}


def _make_pool_with_conn():
    """Build the (pool, conn, acquire-mocks) tuple the tests patch in."""
    mock_pool = AsyncMock()
    mock_conn = AsyncMock()
    mock_acquirer = AsyncMock()
    mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_acquirer.__aexit__ = AsyncMock(return_value=False)
    mock_pool.acquire = MagicMock(return_value=mock_acquirer)
    return mock_pool, mock_conn


def _make_case_row(id=1, status="open", alert_ids=None):
    return {
        "id": id,
        "title": "Test Case",
        "description": "A test case",
        "status": status,
        "severity": "medium",
        "assigned_to": None,
        "alert_ids": alert_ids or [],
        "notes": [],
        "lessons_learned": None,
        "resolution_note": None,
        "resolved_at": None,
        "created_at": datetime.now(tz=timezone.utc),
        "updated_at": datetime.now(tz=timezone.utc),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Verdict vocabulary + model
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestVerdictVocabulary:
    def test_closed_vocabulary(self):
        assert VERDICTS == (
            "true_positive",
            "false_positive",
            "benign",
            "needs_review",
        )

    def test_verdict_valid(self):
        v = CaseVerdict(verdict="true_positive", rationale="Process + sudo chain confirms")
        assert v.verdict == "true_positive"
        assert v.confidence is None
        assert v.alert_id is None

    def test_verdict_invalid_rejected(self):
        with pytest.raises(Exception):
            CaseVerdict(verdict="guilty", rationale="not in the vocabulary")

    def test_verdict_rationale_required(self):
        with pytest.raises(Exception):
            CaseVerdict(verdict="false_positive", rationale="")

    def test_verdict_confidence_bounds(self):
        CaseVerdict(verdict="benign", rationale="operator artifact", confidence=0.0)
        CaseVerdict(verdict="benign", rationale="operator artifact", confidence=1.0)
        with pytest.raises(Exception):
            CaseVerdict(verdict="benign", rationale="x", confidence=1.5)
        with pytest.raises(Exception):
            CaseVerdict(verdict="benign", rationale="x", confidence=-0.1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _record_case_event helper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRecordCaseEvent:
    @pytest.mark.asyncio
    async def test_success_returns_event_id(self):
        conn = AsyncMock()
        conn.fetchval.return_value = 42
        event_id = await _record_case_event(conn, 1, "verdict", "analyst1", {"verdict": "benign"})
        assert event_id == 42
        sql = conn.fetchval.call_args[0][0]
        assert "case_events" in sql
        assert "::case_event_type" in sql

    @pytest.mark.asyncio
    async def test_failure_swallowed_never_breaks_mutation(self):
        conn = AsyncMock()
        conn.fetchval.side_effect = RuntimeError("db down")
        event_id = await _record_case_event(conn, 1, "note", "analyst1", {"text": "hi"})
        assert event_id is None  # logged, swallowed — caller's mutation proceeds


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Governance gates: no resolve/close without a verdict
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestVerdictGate:
    @pytest.mark.asyncio
    async def test_resolve_without_verdict_rejected(self):
        from src.api.cases import CaseUpdate, update_case

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = _make_case_row(status="open")
        mock_conn.fetchval.return_value = None  # no verdict event on the timeline

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await update_case(
                    1,
                    CaseUpdate(status="resolved", lessons_learned="learned"),
                    user=_make_user(),
                )
        assert exc_info.value.status_code == 400
        assert "verdict" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_resolve_with_verdict_passes_gate(self):
        from src.api.cases import CaseUpdate, update_case

        mock_pool, mock_conn = _make_pool_with_conn()
        current = _make_case_row(status="open")
        updated = dict(current, status="resolved", lessons_learned="learned")
        # First fetchrow = current state, second = the UPDATE ... RETURNING
        mock_conn.fetchrow.side_effect = [current, updated]
        mock_conn.fetchval.return_value = 1  # verdict exists

        with (
            patch("src.api.cases.get_pool", return_value=mock_pool),
            patch("src.api.cases.log_audit_action", new_callable=AsyncMock),
        ):
            result = await update_case(
                1,
                CaseUpdate(status="resolved", lessons_learned="learned"),
                user=_make_user(),
            )
        assert result["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_close_without_verdict_rejected(self):
        from src.api.cases import CaseUpdate, update_case

        mock_pool, mock_conn = _make_pool_with_conn()
        # Case is OPEN (never adjudicated) — closing requires a verdict
        mock_conn.fetchrow.return_value = _make_case_row(status="open")
        mock_conn.fetchval.return_value = None

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await update_case(
                    1,
                    CaseUpdate(status="closed", lessons_learned="learned"),
                    user=_make_user(),
                )
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_soft_delete_without_verdict_rejected(self):
        from src.api.cases import delete_case

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = _make_case_row(status="open")
        mock_conn.fetchval.return_value = None  # no verdict

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await delete_case(1, user=_make_user("admin"))
        assert exc_info.value.status_code == 400
        assert "verdict" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_status_change_writes_timeline_event(self):
        from src.api.cases import CaseUpdate, update_case

        mock_pool, mock_conn = _make_pool_with_conn()
        current = _make_case_row(status="open")
        updated = dict(current, status="in_progress")
        mock_conn.fetchrow.side_effect = [current, updated]
        mock_conn.fetchval.return_value = 77  # event id from _record_case_event

        with (
            patch("src.api.cases.get_pool", return_value=mock_pool),
            patch("src.api.cases.log_audit_action", new_callable=AsyncMock),
        ):
            await update_case(1, CaseUpdate(status="in_progress"), user=_make_user())

        # Two inserts through _record_case_event's fetchval? No: fetchval here
        # is only the verdict-gate check (returns truthy) and the event insert
        # (returns 77). The insert call must reference case_events.
        insert_calls = [c for c in mock_conn.fetchval.call_args_list if "case_events" in c[0][0]]
        assert insert_calls, "status transition must write a case_events row"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POST /cases/{id}/verdict
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestVerdictEndpoint:
    @pytest.mark.asyncio
    async def test_record_verdict_happy_path(self):
        from src.api.cases import CaseVerdict, record_verdict

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = {"id": 1, "status": "open"}
        mock_conn.fetchval.side_effect = [5]  # event id
        verdict = CaseVerdict(verdict="false_positive", rationale="Operator artifact")

        with (
            patch("src.api.cases.get_pool", return_value=mock_pool),
            patch("src.api.cases.log_audit_action", new_callable=AsyncMock),
        ):
            result = await record_verdict(1, verdict, user=_make_user())

        assert result["event_type"] == "verdict"
        assert result["verdict"] == "false_positive"
        assert result["event_id"] == 5

    @pytest.mark.asyncio
    async def test_record_verdict_unknown_case_404(self):
        from src.api.cases import CaseVerdict, record_verdict

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = None

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await record_verdict(
                    999,
                    CaseVerdict(verdict="benign", rationale="x"),
                    user=_make_user(),
                )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_record_verdict_unknown_alert_404(self):
        from src.api.cases import CaseVerdict, record_verdict

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = {"id": 1, "status": "open"}
        mock_conn.fetchval.return_value = None  # alert lookup misses

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await record_verdict(
                    1,
                    CaseVerdict(verdict="true_positive", rationale="x", alert_id=99),
                    user=_make_user(),
                )
        assert exc_info.value.status_code == 404
        assert "alert" in exc_info.value.detail.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GET /cases/{id}/timeline and /summary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestTimelineAndSummary:
    @pytest.mark.asyncio
    async def test_timeline_unknown_case_404(self):
        from src.api.cases import get_case_timeline

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchval.return_value = None

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            with pytest.raises(HTTPException) as exc_info:
                await get_case_timeline(999, user=_make_user("viewer"))
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_timeline_returns_events_oldest_first(self):
        from src.api.cases import get_case_timeline

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchval.return_value = 1  # case exists
        mock_conn.fetch.return_value = [
            {"id": 1, "event_type": "created", "actor": "analyst1"},
            {"id": 2, "event_type": "verdict", "actor": "analyst1"},
        ]

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            result = await get_case_timeline(1, user=_make_user("viewer"))

        assert [r["event_type"] for r in result] == ["created", "verdict"]
        sql = mock_conn.fetch.call_args[0][0]
        assert "ORDER BY created_at ASC" in sql  # chronological, not newest-first

    @pytest.mark.asyncio
    async def test_summary_adjudicated_flag(self):
        from src.api.cases import get_case_summary

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = {
            "id": 1,
            "title": "Test Case",
            "status": "open",
            "severity": "medium",
            "assigned_to": None,
            "created_at": datetime.now(tz=timezone.utc),
            "updated_at": datetime.now(tz=timezone.utc),
        }
        mock_conn.fetch.return_value = [
            {"event_type": "verdict", "n": 1},
            {"event_type": "note", "n": 2},
        ]
        mock_conn.fetchval.return_value = 3  # linked alert count

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            result = await get_case_summary(1, user=_make_user("viewer"))

        assert result["adjudicated"] is True
        assert result["event_counts"]["verdict"] == 1
        assert result["total_events"] == 3
        assert result["linked_alerts"] == 3

    @pytest.mark.asyncio
    async def test_summary_not_adjudicated_when_no_verdicts(self):
        from src.api.cases import get_case_summary

        mock_pool, mock_conn = _make_pool_with_conn()
        mock_conn.fetchrow.return_value = {
            "id": 1,
            "title": "Test Case",
            "status": "open",
            "severity": "high",
            "assigned_to": None,
            "created_at": datetime.now(tz=timezone.utc),
            "updated_at": datetime.now(tz=timezone.utc),
        }
        mock_conn.fetch.return_value = [{"event_type": "created", "n": 1}]
        mock_conn.fetchval.return_value = 0

        with patch("src.api.cases.get_pool", return_value=mock_pool):
            result = await get_case_summary(1, user=_make_user("viewer"))

        assert result["adjudicated"] is False
