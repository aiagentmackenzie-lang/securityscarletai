"""
Tests for the V0.4 response executors: capability gates, param validation,
and the verified-outcome protocol (re-query of the source system).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.response.executors import (
    EXECUTORS,
    DisableMacosUserExecutor,
    DisableSiemUserExecutor,
    ExecutionResult,
    IsolateHostFleetExecutor,
    NotifySlackExecutor,
    PfBlockIpExecutor,
    QuarantineHostExecutor,
    _refused,
    get_executor,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Registry
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRegistry:
    def test_all_six_action_types_registered(self):
        assert set(EXECUTORS) == {
            "notify_slack",
            "disable_siem_user",
            "quarantine_host",
            "pf_block_ip",
            "disable_macos_user",
            "isolate_host_fleet",
        }

    def test_unknown_action_type_returns_none(self):
        assert get_executor("nuke_from_orbit") is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Param validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestParamValidation:
    def test_disable_siem_user_requires_username(self):
        assert DisableSiemUserExecutor().validate_params({}) is not None
        assert DisableSiemUserExecutor().validate_params({"username": ""}) is not None
        assert DisableSiemUserExecutor().validate_params({"username": "bob"}) is None

    def test_quarantine_host_requires_host(self):
        assert QuarantineHostExecutor().validate_params({}) is not None
        assert QuarantineHostExecutor().validate_params({"host_name": "h1"}) is None

    def test_pf_block_ip_requires_ip(self):
        assert PfBlockIpExecutor().validate_params({}) is not None
        assert PfBlockIpExecutor().validate_params({"ip": "203.0.113.7"}) is None

    def test_notify_slack_requires_message(self):
        assert NotifySlackExecutor().validate_params({}) is not None
        assert NotifySlackExecutor().validate_params({"message": "hi"}) is None


@pytest.fixture
def exec_pool():
    """Mocked DB pool wired into the executors module for one test."""
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    with patch("src.response.executors.get_pool", return_value=pool):
        yield pool, conn


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# disable_siem_user -- live executor with re-query verification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDisableSiemUserExecutor:
    @pytest.mark.asyncio
    async def test_execute_deactivates_and_verify_confirms(self, exec_pool):
        _, conn = exec_pool
        ex = DisableSiemUserExecutor()
        # execute: fetchrow returns the UPDATE ... RETURNING row
        conn.fetchrow.return_value = {"username": "bob", "is_active": False}
        result = await ex.execute({"username": "bob"})
        assert result.ok is True
        assert result.intended_state == {"username": "bob", "is_active": False}

        # verify: re-query shows is_active = False
        conn.fetchval.return_value = False
        verification = await ex.verify({"username": "bob"}, before={"before_is_active": True})
        assert verification.verified is True
        assert verification.mode == "live"
        assert verification.after == {"username": "bob", "is_active": False}

    @pytest.mark.asyncio
    async def test_verify_reports_unverified_when_state_not_reached(self, exec_pool):
        _, conn = exec_pool
        ex = DisableSiemUserExecutor()
        conn.fetchval.return_value = True  # still active!
        verification = await ex.verify({"username": "bob"}, before={"before_is_active": True})
        assert verification.verified is False
        assert "NOT reached" in verification.detail

    @pytest.mark.asyncio
    async def test_execute_unknown_user_fails_honestly(self, exec_pool):
        _, conn = exec_pool
        ex = DisableSiemUserExecutor()
        conn.fetchrow.return_value = None
        result = await ex.execute({"username": "ghost"})
        assert result.ok is False
        assert "not found" in result.detail


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# quarantine_host -- live executor with re-query verification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestQuarantineHostExecutor:
    @pytest.mark.asyncio
    async def test_execute_and_verify(self, exec_pool):
        _, conn = exec_pool
        ex = QuarantineHostExecutor()
        conn.fetchrow.return_value = None  # not quarantined yet (plan)
        before = await ex.plan({"host_name": "bad-host"})
        assert before == {"before_quarantined": False}

        result = await ex.execute({"host_name": "bad-host"})
        assert result.ok is True

        conn.fetchrow.return_value = {"host_name": "bad-host"}
        verification = await ex.verify({"host_name": "bad-host"}, before=before)
        assert verification.verified is True
        assert verification.mode == "live"

    @pytest.mark.asyncio
    async def test_verify_unquarantined_reports_not_reached(self, exec_pool):
        _, conn = exec_pool
        ex = QuarantineHostExecutor()
        conn.fetchrow.return_value = None
        verification = await ex.verify({"host_name": "bad-host"})
        assert verification.verified is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Capability-gated executors -- fail closed, never simulated
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCapabilityGates:
    @pytest.mark.asyncio
    async def test_pf_refuses_without_root(self):
        ex = PfBlockIpExecutor()
        with patch("os.geteuid", return_value=1000):
            result = await ex.execute({"ip": "203.0.113.7"})
            assert result.ok is False
            assert "refused" in result.detail
            assert "root" in result.detail
            assert "NOT simulated" in result.detail
            verification = await ex.verify({"ip": "203.0.113.7"})
            assert verification.verified is False
            assert verification.mode == "capability_refused"

    @pytest.mark.asyncio
    async def test_pf_refuses_without_binary(self):
        ex = PfBlockIpExecutor()
        with (
            patch("os.geteuid", return_value=0),
            patch("shutil.which", return_value=None),
        ):
            result = await ex.execute({"ip": "203.0.113.7"})
            assert result.ok is False
            assert "pfctl" in result.detail

    @pytest.mark.asyncio
    async def test_disable_macos_user_refuses_without_root(self):
        ex = DisableMacosUserExecutor()
        with patch("os.geteuid", return_value=1000):
            result = await ex.execute({"username": "ops"})
            assert result.ok is False
            assert "NOT simulated" in result.detail

    @pytest.mark.asyncio
    async def test_fleet_isolate_refuses_without_fleet_url(self):
        ex = IsolateHostFleetExecutor()
        result = await ex.execute({"host_name": "host-1"})
        assert result.ok is False
        assert "fleet" in result.detail.lower()
        verification = await ex.verify({"host_name": "host-1"})
        assert verification.verified is False
        assert verification.mode == "capability_refused"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# notify_slack -- verification by delivery receipt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNotifySlackExecutor:
    @pytest.mark.asyncio
    async def test_verify_uses_delivery_receipt(self):
        ex = NotifySlackExecutor()
        verification = await ex.verify(
            {"message": "hi"}, execution=ExecutionResult(ok=True, detail="sent")
        )
        assert verification.verified is True
        assert verification.mode == "live"

        verification = await ex.verify(
            {"message": "hi"},
            execution=ExecutionResult(ok=False, detail="failed"),
        )
        assert verification.verified is False


def test_refused_helper_message_is_honest():
    result = _refused("some_executor", "root required")
    assert result.ok is False
    assert "fail-closed" in result.detail
    assert "NOT simulated" in result.detail
