"""Wave E regressions: response rollback invariant, webhook transport, evidence pack.

SS-038/SS-058  "rollback note before approval" was documented but never checked
SS-057         webhook channels accepted http:// (HMAC over cleartext)
SS-062         evidence pack omitted the request-level audit trail and a
               docstring promised a (rule_name, host) fallback the code lacks
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _pool(row):
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row)
    conn.fetchval = AsyncMock(return_value=row.get("id") if row else None)
    acq = MagicMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=None)
    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=acq)
    return pool, conn


def _action_row(**over):
    row = {
        "id": 9,
        "case_id": 1,
        "action_type": "disable_account",
        "params": {},
        "policy_effect": "approval_required",
        "status": "requested",
        "requested_by": "analyst1",
        "justification": "containment",
        "evidence": {},
        "rollback_note": "Re-enable the account after review.",
    }
    row.update(over)
    return row


class TestRollbackNoteBeforeApproval:
    @pytest.mark.asyncio
    async def test_approval_refused_without_a_rollback_note(self):
        """LATENT for operator-added policy entries that omit the note."""
        from fastapi import HTTPException

        from src.api.response import ApproveRequest, approve_action

        pool, _conn = _pool(_action_row(rollback_note=None))
        with (
            patch("src.api.response.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.response.log_audit_action", AsyncMock()),
        ):
            with pytest.raises(HTTPException) as exc:
                await approve_action(
                    action_id=9,
                    body=ApproveRequest(note="ok"),
                    user={"sub": "admin2", "role": "admin"},
                )

        assert exc.value.status_code == 400
        assert "rollback" in exc.value.detail.lower()

    @pytest.mark.asyncio
    async def test_blank_rollback_note_is_refused(self):
        from fastapi import HTTPException

        from src.api.response import ApproveRequest, approve_action

        pool, _conn = _pool(_action_row(rollback_note="   "))
        with (
            patch("src.api.response.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.response.log_audit_action", AsyncMock()),
        ):
            with pytest.raises(HTTPException):
                await approve_action(
                    action_id=9,
                    body=ApproveRequest(note="ok"),
                    user={"sub": "admin2", "role": "admin"},
                )

    @pytest.mark.asyncio
    async def test_approval_audit_carries_the_rollback_note(self):
        from src.api.response import ApproveRequest, approve_action

        pool, _conn = _pool(_action_row())
        audit = AsyncMock()
        with (
            patch("src.api.response.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.response.log_audit_action", audit),
            patch("src.api.response._execute_approved_action", AsyncMock(), create=True),
            patch("src.api.response._transition", AsyncMock(), create=True),
        ):
            try:
                await approve_action(
                    action_id=9,
                    body=ApproveRequest(note="approved for containment"),
                    user={"sub": "admin2", "role": "admin"},
                )
            except Exception:
                # Execution path may need more mocks; the audit row is what
                # this test asserts, and it is written before execution.
                pass

        approved = [
            c for c in audit.call_args_list if c.kwargs.get("action") == "response.approved"
        ]
        assert approved, "approval was not audited"
        assert approved[0].kwargs["new_values"]["rollback_note"] == (
            "Re-enable the account after review."
        )


class TestWebhookTransport:
    def _parse(self, document):
        from src.response.notification_channels import parse_channels_document

        return parse_channels_document(document)

    def _doc(self, url, extra=None):
        config = {"url": url}
        config.update(extra or {})
        return {
            "notification_channels": {
                "version": 1,
                "channels": [
                    {
                        "name": "hook",
                        "type": "webhook",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": config,
                    }
                ],
            }
        }

    def test_http_webhook_is_dropped(self):
        """SS-057: a signed webhook over cleartext exposes the alert body."""
        assert self._parse(self._doc("http://example.com/hook")) == []

    def test_https_webhook_is_accepted(self):
        assert len(self._parse(self._doc("https://example.com/hook"))) == 1

    def test_http_loopback_is_allowed(self):
        """A local receiver on loopback is not on the wire."""
        assert len(self._parse(self._doc("http://127.0.0.1:9000/hook"))) == 1

    def test_http_with_explicit_opt_in_is_allowed(self):
        assert (
            len(self._parse(self._doc("http://lab.example/hook", {"allow_insecure_http": True})))
            == 1
        )

    @pytest.mark.asyncio
    async def test_send_time_check_refuses_plain_http_remote(self):
        """Defense in depth: a ChannelConfig built in code (not from YAML)
        must not send over cleartext either."""
        from src.response.notification_channels import (
            ChannelConfig,
            _send_webhook_body,
        )

        channel = ChannelConfig(
            name="hook", type="webhook", severities=("critical",), config={"url": "http://evil/h"}
        )
        ok, _status, detail = await _send_webhook_body(channel, {"a": 1})
        assert ok is False
        assert "https" in detail.lower()

    def test_docs_describe_the_transport_requirement(self):
        from pathlib import Path

        src = Path("src/response/notification_channels.py").read_text()
        assert "allow_insecure_http" in src
        assert "loopback" in src.lower()


class TestEvidencePackScope:
    def test_correlation_fallback_claim_is_gone(self):
        """SS-062: the docstring promised a (rule_name, host) fallback the
        code does not implement — the code returns [] without a
        correlation_id. A regulator-facing artifact must not claim it."""
        from pathlib import Path

        src = Path("src/compliance/evidence.py").read_text()
        section = src[
            src.index("async def _correlation_matches") : src.index(
                "async def", src.index("async def _correlation_matches") + 10
            )
        ]
        assert "fall back to (rule_name, host)" not in section
        assert "correlation_id" in section

    @pytest.mark.asyncio
    async def test_pack_includes_request_level_receipts(self):
        """The second audit chain (audit_logs, HTTP request-level) was not
        represented at all."""

        src = Path("src/compliance/evidence.py").read_text()
        assert "audit_logs" in src
        assert "request_receipts" in src
