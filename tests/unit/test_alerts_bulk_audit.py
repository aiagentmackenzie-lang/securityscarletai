"""SS-048: bulk dispositions must persist the operator's note and be auditable.

`bulk_resolve` / `bulk_mark_false_positive` accepted a note, dropped it on the
floor (the UPDATE never touched `alerts.resolution_note`, no timeline note was
appended) and wrote no action-level audit row — only the HTTP request row,
which records the path and a body hash, not the decision. Up to 1000 alerts
could be marked false-positive with the rationale irretrievably lost, and those
labels feed triage training.

The tests assert the absence of the defect: the note reaches the database, the
timeline carries it, the affected ids are returned so the API can write one
audit row naming the alerts and the note.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection.alerts import bulk_mark_false_positive, bulk_resolve


def _pool(rows: list[dict]):
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    conn.execute = AsyncMock(return_value="UPDATE 0")
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=acquirer)
    return pool, conn


class TestBulkResolvePersistsNote:
    @pytest.mark.asyncio
    async def test_resolution_note_is_written(self):
        pool, conn = _pool([{"id": 1}, {"id": 2}])
        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)):
            ids = await bulk_resolve([1, 2], "Duplicate of INC-42", updated_by="analyst1")

        assert ids == [1, 2]
        sql = conn.fetch.call_args.args[0].lower()
        assert "resolution_note" in sql, "the note is still discarded by the UPDATE"
        params = conn.fetch.call_args.args[1:]
        assert "Duplicate of INC-42" in params

    @pytest.mark.asyncio
    async def test_timeline_note_is_appended(self):
        pool, conn = _pool([{"id": 1}])
        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)):
            await bulk_resolve([1], "Duplicate of INC-42", updated_by="analyst1")

        sql = conn.fetch.call_args.args[0].lower()
        assert "notes" in sql, "no timeline entry is appended for the bulk decision"
        note_param = next(
            p
            for p in conn.fetch.call_args.args[1:]
            if isinstance(p, str) and p.lstrip().startswith("[")
        )
        entries = json.loads(note_param)
        assert isinstance(entries, list)
        assert entries[0]["text"].startswith("Status changed to: resolved")
        assert entries[0]["author"] == "analyst1"
        assert "Duplicate of INC-42" in entries[0]["text"]

    @pytest.mark.asyncio
    async def test_empty_list_short_circuits(self):
        assert await bulk_resolve([]) == []
        assert await bulk_mark_false_positive([]) == []


class TestBulkFalsePositivePersistsNote:
    @pytest.mark.asyncio
    async def test_note_and_timeline_are_written(self):
        pool, conn = _pool([{"id": 7}])
        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)):
            ids = await bulk_mark_false_positive(
                [7], "Known scanner, approved by CSIRT", updated_by="analyst1"
            )

        assert ids == [7]
        sql = conn.fetch.call_args.args[0].lower()
        assert "resolution_note" in sql
        assert "notes" in sql
        note_param = next(
            p
            for p in conn.fetch.call_args.args[1:]
            if isinstance(p, str) and p.lstrip().startswith("[")
        )
        entries = json.loads(note_param)
        assert entries[0]["author"] == "analyst1"
        assert "false_positive" in entries[0]["text"]


class TestBulkRoutesWriteActionAudit:
    @pytest.mark.asyncio
    async def test_bulk_resolve_writes_audit_row(self):
        from src.api.alerts import BulkOperation, bulk_resolve_alerts

        with (
            patch("src.api.alerts.bulk_resolve", AsyncMock(return_value=[1, 2])),
            patch("src.api.audit.log_audit_action", AsyncMock(return_value=9)) as audit,
        ):
            op = BulkOperation(alert_ids=[1, 2], note="Duplicate of INC-42")
            result = await bulk_resolve_alerts(op=op, user="analyst1")

        assert result["resolved"] == 2
        assert audit.await_count == 1
        kwargs = audit.call_args.kwargs
        assert kwargs["actor"] == "analyst1"
        assert kwargs["action"] == "alert.bulk_resolve"
        assert kwargs["new_values"]["alert_ids"] == [1, 2]
        assert kwargs["new_values"]["note"] == "Duplicate of INC-42"

    @pytest.mark.asyncio
    async def test_bulk_false_positive_writes_audit_row(self):
        from src.api.alerts import BulkOperation, bulk_false_positive_alerts

        with (
            patch("src.api.alerts.bulk_mark_false_positive", AsyncMock(return_value=[3])),
            patch("src.api.audit.log_audit_action", AsyncMock(return_value=10)) as audit,
        ):
            op = BulkOperation(alert_ids=[3], note="Known scanner")
            result = await bulk_false_positive_alerts(op=op, user="analyst1")

        assert result["marked_false_positive"] == 1
        kwargs = audit.call_args.kwargs
        assert kwargs["action"] == "alert.bulk_false_positive"
        assert kwargs["new_values"]["alert_ids"] == [3]
        assert kwargs["new_values"]["note"] == "Known scanner"


class TestReopenClearsResolvedAt:
    """SS-049: reopening an alert must not keep the old `resolved_at`.

    The CASE only ever set NOW() on a terminal status and kept the previous
    value otherwise, so `resolved -> investigating` left a non-NULL
    resolved_at and MTTR/reporting counted a reopened alert as resolved at the
    old timestamp.
    """

    @pytest.mark.asyncio
    async def test_non_terminal_status_clears_resolved_at(self):
        from src.detection.alerts import update_alert_status

        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="UPDATE 1")
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)):
            await update_alert_status(5, "investigating", updated_by="analyst1")

        # First statement is the UPDATE (the second is the timeline note).
        sql = conn.execute.call_args_list[0].args[0]
        # Terminal statuses stamp NOW(); everything else clears the column.
        assert "THEN NOW()" in sql
        assert "ELSE NULL" in sql, "reopening leaves a stale resolved_at (SS-049)"
        assert "ELSE resolved_at" not in sql
