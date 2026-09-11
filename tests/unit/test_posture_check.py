"""Unit tests — posture/mode-isolation check (V0.3 build hygiene)."""

import pytest

from scripts.posture_check import (
    Problem,
    check_demo_flag_in_prod,
    check_demo_seeded_volume,
    detect_posture,
    run_checks,
)


class FakeConn:
    """Minimal asyncpg-conn stand-in for the demo-seed volume probe.

    fetchval is async (the probe awaits it) and returns the live-demo-user
    verdict. has_demo_user=True models the demo seed leaving an ACTIVE
    demo_analyst; has_demo_user=False covers both a clean volume and the
    standing prod volume's DEACTIVATED legacy demo row (is_active=false).
    """

    def __init__(self, has_demo_user: bool):
        self.has_demo_user = has_demo_user
        self.called = False

    async def fetchval(self, query, *args):
        self.called = True
        # The corrected probe targets the real siem_users table and checks
        # is_active (the Sep 4 cutover retired the demo user; a deactivated
        # row is not a live demo volume).
        assert "siem_users" in query
        assert "is_active" in query
        return 1 if self.has_demo_user else None


class TestDetectPosture:
    def test_demo_flag_wins(self):
        env = {
            "DEMO_SEED_ENABLED": "true",
            "PASSWORD_PEPPER": "x" * 32,
        }
        assert detect_posture(env) == "demo"

    def test_prod_markers(self):
        env = {"PASSWORD_PEPPER": "x" * 32}
        assert detect_posture(env) == "prod"

    def test_prod_marker_superuser_url(self):
        env = {"DATABASE_SUPERUSER_URL": "postgres://..."}
        assert detect_posture(env) == "prod"

    def test_dev_when_nothing_set(self):
        assert detect_posture({}) == "dev"

    def test_false_seed_string_is_not_demo(self):
        assert detect_posture({"DEMO_SEED_ENABLED": "false"}) == "dev"


class TestDemoFlagInProd:
    def test_violation_when_both_set(self):
        env = {"DEMO_SEED_ENABLED": "true", "PASSWORD_PEPPER": "x" * 32}
        problem = check_demo_flag_in_prod(env)
        assert isinstance(problem, Problem)
        assert problem.check == "demo-flag-in-prod"

    def test_passes_for_plain_demo_posture(self):
        env = {"DEMO_SEED_ENABLED": "true"}
        assert check_demo_flag_in_prod(env) is None

    def test_passes_for_prod_without_flag(self):
        env = {"DATABASE_SUPERUSER_URL": "postgres://..."}
        assert check_demo_flag_in_prod(env) is None


class TestDemoSeededVolume:
    @pytest.mark.asyncio
    async def test_live_demo_user_refused(self):
        problem = await check_demo_seeded_volume(FakeConn(has_demo_user=True))
        assert isinstance(problem, Problem)
        assert problem.check == "demo-seeded-volume-in-prod"
        assert "demo_analyst" in problem.detail

    @pytest.mark.asyncio
    async def test_deactivated_legacy_demo_user_passes(self):
        """The standing prod volume: demo_analyst row exists but was
        consciously deactivated at the Sep 4 cutover -- not a live demo."""
        assert await check_demo_seeded_volume(FakeConn(has_demo_user=False)) is None

    @pytest.mark.asyncio
    async def test_probe_targets_siem_users(self):
        """Regression for the live-boot finding (2026-09-11): the original
        check queried a nonexistent 'users' table and did not await the
        coroutine -- a truthy coroutine object flagged EVERY prod boot."""
        conn = FakeConn(has_demo_user=False)
        await check_demo_seeded_volume(conn)
        assert conn.called


class TestRunChecks:
    @pytest.mark.asyncio
    async def test_dev_posture_runs_env_checks_only(self):
        assert await run_checks({}) == []

    @pytest.mark.asyncio
    async def test_prod_posture_checks_env_and_volume(self):
        problems = await run_checks(
            {"PASSWORD_PEPPER": "x" * 32, "DEMO_SEED_ENABLED": "true"},
            conn=FakeConn(has_demo_user=False),
        )
        assert len(problems) == 1
        assert problems[0].check == "demo-flag-in-prod"

    @pytest.mark.asyncio
    async def test_prod_on_demo_seeded_volume_is_flagged(self):
        problems = await run_checks(
            {"PASSWORD_PEPPER": "x" * 32},
            conn=FakeConn(has_demo_user=True),
        )
        assert len(problems) == 1
        assert problems[0].check == "demo-seeded-volume-in-prod"

    def test_problem_renders_with_check_name(self):
        problem = Problem(check="x", detail="y")
        assert "x" in str(problem) and "y" in str(problem)


@pytest.mark.parametrize(
    "env,expected",
    [
        ({"DEMO_SEED_ENABLED": "TRUE"}, "demo"),
        ({"DEMO_SEED_ENABLED": " true "}, "demo"),
        ({"DEMO_SEED_ENABLED": "false", "PASSWORD_PEPPER": "x"}, "prod"),
        ({}, "dev"),
    ],
)
def test_detect_posture_normalization(env, expected):
    assert detect_posture(env) == expected
