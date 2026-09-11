"""
Tests for the V0.4 response actions API: policy-gated requests, HITL
approval with the four-eyes rule, rejection, execution guards, and the
verified-outcome recording.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.response.policy import PolicyEntry

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _user(role: str = "analyst", username: str = "analyst1") -> dict:
    return {"sub": username, "role": role}


def _pool_and_conn():
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    return pool, conn


def _action_row(status="requested", action_type="disable_siem_user", requested_by="analyst1"):
    return {
        "id": 1,
        "case_id": 5,
        "action_type": action_type,
        "params": {"username": "bob"},
        "policy_effect": "approval_required",
        "status": status,
        "requested_by": requested_by,
        "justification": "brute force observed",
        "approved_by": None,
        "approval_note": None,
        "rejection_reason": None,
        "executed_at": None,
        "verified_at": None,
        "evidence": {"before": {"before_is_active": True}},
        "rollback_note": "re-enable after review",
        "created_at": None,
        "updated_at": None,
    }


def _policy_entries(effects: dict[str, str]) -> dict[str, PolicyEntry]:
    return {
        name: PolicyEntry(effect=effect, max_per_day=10, requires_case=False, description="t")
        for name, effect in effects.items()
    }


def _patch_policy(entries):
    return patch(
        "src.api.response._load_policy",
        return_value=(("config/response_policy.yaml", "1"), entries),
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Request endpoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRequestAction:
    @pytest.mark.asyncio
    async def test_unknown_action_type_refused(self):
        from src.api.response import ActionRequest, request_action

        with pytest.raises(HTTPException) as exc_info:
            await request_action(
                ActionRequest(action_type="nuke_from_orbit", case_id=5),
                user=_user(),
            )
        assert exc_info.value.status_code == 403
        assert "fail-closed" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_policy_never_refused(self):
        from src.api.response import ActionRequest, request_action

        pool, conn = _pool_and_conn()
        entries = _policy_entries({"disable_siem_user": "never"})
        with (
            patch("src.api.response.get_pool", return_value=pool),
            _patch_policy(entries),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await request_action(
                    ActionRequest(
                        action_type="disable_siem_user",
                        params={"username": "bob"},
                        case_id=5,
                        justification="x",
                    ),
                    user=_user(),
                )
        assert exc_info.value.status_code == 403
        assert "never" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_invalid_params_rejected(self):
        from src.api.response import ActionRequest, request_action

        with pytest.raises(HTTPException) as exc_info:
            await request_action(
                ActionRequest(action_type="disable_siem_user", params={}, case_id=5),
                user=_user(),
            )
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_approval_required_parks_action_never_executes(self):
        from src.api.response import ActionRequest, request_action

        pool, conn = _pool_and_conn()
        entries = _policy_entries({"disable_siem_user": "approval_required"})
        inserted = _action_row()
        conn.fetchrow.return_value = inserted
        conn.fetchval.return_value = 99  # case event id

        with (
            patch("src.api.response.get_pool", return_value=pool),
            _patch_policy(entries),
            patch("src.api.response._actions_today", new_callable=AsyncMock, return_value=0),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
            patch(
                "src.response.notifications.send_slack_notification",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            result = await request_action(
                ActionRequest(
                    action_type="disable_siem_user",
                    params={"username": "bob"},
                    case_id=5,
                    justification="brute force",
                ),
                user=_user(),
            )
        assert result["approval_required"] is True
        assert result["action"]["status"] == "requested"
        # The row was inserted as 'requested' and NO execution happened
        executed = [c for c in conn.execute.call_args_list if "UPDATE siem_users" in str(c)]
        assert executed == []

    @pytest.mark.asyncio
    async def test_allow_tier_executes_immediately_and_verifies(self):
        from src.api.response import ActionRequest, request_action

        pool, conn = _pool_and_conn()
        inserted = _action_row(action_type="notify_slack")
        inserted["policy_effect"] = "allow"
        inserted["case_id"] = None
        inserted["params"] = {"message": "approved"}
        conn.fetchrow.return_value = inserted

        with (
            patch("src.api.response.get_pool", return_value=pool),
            _patch_policy(_policy_entries({"notify_slack": "allow"})),
            patch("src.api.response._actions_today", new_callable=AsyncMock, return_value=0),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
            patch(
                "src.response.notifications.send_slack_notification",
                new_callable=AsyncMock,
                return_value=True,
            ) as slack_mock,
        ):
            result = await request_action(
                ActionRequest(
                    action_type="notify_slack",
                    params={"message": "approved"},
                    case_id=None,
                ),
                user=_user(),
            )

        assert result["approval_required"] is False
        # The allow-tier action executed immediately: the Slack delivery was
        # attempted and the outcome was verified via the delivery receipt.
        assert result["outcome"]["status"] == "verified"
        assert result["outcome"]["verification"]["verified"] is True
        slack_mock.assert_called_once()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Approve endpoint (four-eyes)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestApproveAction:
    @pytest.mark.asyncio
    async def test_four_eyes_requester_cannot_self_approve(self):
        from src.api.response import ApproveRequest, approve_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _action_row()  # requested_by: analyst1

        with patch("src.api.response.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc_info:
                await approve_action(1, ApproveRequest(note="ok"), user=_user("admin", "analyst1"))
        assert exc_info.value.status_code == 403
        assert "four-eyes" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_approve_executes_and_verifies(self):
        from src.api.response import ApproveRequest, approve_action

        pool, conn = _pool_and_conn()
        requested = _action_row(status="requested", requested_by="analyst1")
        requested["case_id"] = None
        executed = dict(requested, status="verified", approved_by="admin1")
        # fetchrow sequence: (approve) action row, (execute UPDATE RETURNING),
        # (get_action final read)
        conn.fetchrow.side_effect = [requested, executed, executed]
        conn.fetchval.return_value = False  # verify re-query: is_active False

        with (
            patch("src.api.response.get_pool", return_value=pool),
            patch("src.response.executors.get_pool", return_value=pool),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
        ):
            result = await approve_action(
                1,
                ApproveRequest(note="confirmed with host owner"),
                user=_user("admin", "admin1"),
            )
        assert result["approved_by"] == "admin1"
        assert result["outcome"]["status"] == "verified"

    @pytest.mark.asyncio
    async def test_approve_wrong_status_rejected(self):
        from src.api.response import ApproveRequest, approve_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _action_row(status="executed")

        with patch("src.api.response.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc_info:
                await approve_action(1, ApproveRequest(), user=_user("admin", "admin1"))
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_approve_unknown_action_404(self):
        from src.api.response import ApproveRequest, approve_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = None

        with patch("src.api.response.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc_info:
                await approve_action(999, ApproveRequest(), user=_user("admin", "admin1"))
        assert exc_info.value.status_code == 404


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Reject endpoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRejectAction:
    @pytest.mark.asyncio
    async def test_reject_records_reason(self):
        from src.api.response import RejectRequest, reject_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _action_row(status="requested")

        with (
            patch("src.api.response.get_pool", return_value=pool),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
        ):
            result = await reject_action(
                1,
                RejectRequest(reason="not authorized by policy owner"),
                user=_user("admin", "admin1"),
            )
        assert result["status"] == "rejected"

    @pytest.mark.asyncio
    async def test_reject_wrong_status_rejected(self):
        from src.api.response import RejectRequest, reject_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _action_row(status="verified")

        with patch("src.api.response.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc_info:
                await reject_action(1, RejectRequest(reason="x"), user=_user("admin", "admin1"))
        assert exc_info.value.status_code == 400


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Execute endpoint guards
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestExecuteGuards:
    @pytest.mark.asyncio
    async def test_jsonb_as_string_rows_survive_execution(self):
        """Regression for the 2026-09-11 live-fire finding: asyncpg may
        return JSONB columns as strings; dict(evidence_string) used to
        crash execution with ValueError. The row is now normalized."""
        from src.api.response import execute_action

        pool, conn = _pool_and_conn()
        approved = _action_row(status="approved")
        approved["case_id"] = None
        approved["params"] = json.dumps({"username": "bob"})
        approved["evidence"] = json.dumps({"before": {"before_is_active": True}})
        verified = dict(approved, status="verified")
        conn.fetchrow.side_effect = [approved, approved, verified]
        conn.fetchval.return_value = False  # verify re-query

        with (
            patch("src.api.response.get_pool", return_value=pool),
            patch("src.response.executors.get_pool", return_value=pool),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
        ):
            result = await execute_action(1, user=_user("admin", "admin1"))
        assert result["outcome"]["status"] == "verified"

    @pytest.mark.asyncio
    async def test_cannot_execute_requested_containment_action(self):
        from src.api.response import execute_action

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _action_row(status="requested")

        with patch("src.api.response.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc_info:
                await execute_action(1, user=_user("admin", "admin1"))
        assert exc_info.value.status_code == 400
        assert "never auto-executes" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_executes_approved_action(self):
        from src.api.response import execute_action

        pool, conn = _pool_and_conn()
        approved = _action_row(status="approved")
        approved["case_id"] = None
        verified = dict(approved, status="verified")
        conn.fetchrow.side_effect = [approved, approved, verified]
        conn.fetchval.return_value = False

        with (
            patch("src.api.response.get_pool", return_value=pool),
            patch("src.response.executors.get_pool", return_value=pool),
            patch("src.api.response.log_audit_action", new_callable=AsyncMock),
        ):
            result = await execute_action(1, user=_user("admin", "admin1"))
        assert result["outcome"]["status"] == "verified"
