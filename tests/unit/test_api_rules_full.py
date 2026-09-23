"""
Tests for src/api/rules.py endpoints and models.

Covers:
- RuleCreate model validation
- RuleResponse model
- create_rule (success, invalid sigma)
- list_rules (all, enabled_only)
- get_rule (found, not found)
- update_rule (found, not found)
- delete_rule (found, not found)
- get_rule_by_id helper
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.api.rules import RuleCreate, RuleResponse


class _DepthTrackingPool:
    """W4-E pin fixture: a fake pool counting how many connections are held
    at once. Collaborators (audit/reload/re-fetch) acquire from the SAME
    pool, mimicking their real behavior — so max_depth exposes
    hold-one-need-two deadlocks."""

    def __init__(self, conn):
        self._conn = conn
        self.depth = 0
        self.max_depth = 0

    def acquire(self):
        pool = self

        class _Ctx:
            async def __aenter__(self):
                pool.depth += 1
                pool.max_depth = max(pool.max_depth, pool.depth)
                return pool._conn

            async def __aexit__(self, *args):
                pool.depth -= 1

        return _Ctx()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pydantic models
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRuleCreateModel:
    def test_valid_rule(self):
        rule = RuleCreate(
            name="Test Rule",
            sigma_yaml="title: Test\ndetection:\n  condition: selection",
        )
        assert rule.name == "Test Rule"
        assert rule.severity == "medium"
        assert rule.enabled is True
        assert rule.run_interval == 60
        assert rule.lookback == 300
        assert rule.threshold == 1

    def test_custom_values(self):
        rule = RuleCreate(
            name="Custom Rule",
            description="Custom description",
            sigma_yaml="title: Custom",
            severity="critical",
            enabled=False,
            run_interval=120,
            lookback=600,
            threshold=5,
        )
        assert rule.severity == "critical"
        assert rule.enabled is False
        assert rule.run_interval == 120

    def test_name_required(self):
        with pytest.raises(Exception):
            RuleCreate(sigma_yaml="title: Test")

    def test_name_max_length(self):
        rule = RuleCreate(name="A" * 200, sigma_yaml="title: Test")
        assert len(rule.name) == 200

    def test_name_too_long(self):
        with pytest.raises(Exception):
            RuleCreate(name="A" * 201, sigma_yaml="title: Test")

    def test_sigma_yaml_required(self):
        with pytest.raises(Exception):
            RuleCreate(name="Test")


class TestRuleResponseModel:
    def test_rule_response(self):
        response = RuleResponse(
            id=1,
            name="Test Rule",
            description="A test rule",
            severity="high",
            enabled=True,
            last_run="2024-01-01T12:00:00",
            last_match=None,
            match_count=5,
        )
        assert response.id == 1
        assert response.match_count == 5
        assert response.last_match is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# list_rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestListRules:
    @pytest.mark.asyncio
    async def test_list_all_rules(self):
        from src.api.rules import list_rules

        mock_rows = [
            {
                "id": 1,
                "name": "Rule 1",
                "description": "Desc 1",
                "severity": "high",
                "enabled": True,
                "last_run": None,
                "last_match": None,
                "match_count": 0,
            },
            {
                "id": 2,
                "name": "Rule 2",
                "description": "Desc 2",
                "severity": "medium",
                "enabled": False,
                "last_run": None,
                "last_match": None,
                "match_count": 10,
            },
        ]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)):
            result = await list_rules(enabled_only=False, user="analyst1")

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_list_enabled_only(self):
        from src.api.rules import list_rules

        mock_rows = [
            {
                "id": 1,
                "name": "Enabled Rule",
                "description": "Test",
                "severity": "high",
                "enabled": True,
                "last_run": None,
                "last_match": None,
                "match_count": 0,
            },
        ]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)):
            result = await list_rules(enabled_only=True, user="analyst1")

        assert len(result) >= 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# get_rule_by_id helper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestGetRuleById:
    @pytest.mark.asyncio
    async def test_found(self):
        from src.api.rules import get_rule_by_id

        mock_row = {"id": 1, "name": "Test Rule", "severity": "high"}
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=mock_row)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)):
            result = await get_rule_by_id(1)

        assert result is not None
        assert result["name"] == "Test Rule"

    @pytest.mark.asyncio
    async def test_serializes_interval_timedeltas(self):
        """RT-002 FAIL-proof: run_interval/lookback arrive as timedelta from
        asyncpg (INTERVAL columns) and must leave as strings.

        Runtime live-fire 2026-09-23: POST /rules / GET /rules/{id} /
        PATCH /rules/{id} 500'd with ResponseValidationError — d9f447a
        (2026-08-22, P1-15) typed the RuleResponse fields as str while this
        helper serialized only datetimes. The list endpoint works because it
        routes through RuleResponse.from_row; every detail-route caller gets
        the raw dict here.
        """
        from datetime import timedelta

        from src.api.rules import get_rule_by_id

        mock_row = {
            "id": 5,
            "name": "Interval Rule",
            "severity": "low",
            "run_interval": timedelta(seconds=60),
            "lookback": timedelta(seconds=300),
            "last_run": None,
            "last_match": None,
        }
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=mock_row)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)):
            result = await get_rule_by_id(5)

        assert result["run_interval"] == "0:01:00"
        assert result["lookback"] == "0:05:00"

    @pytest.mark.asyncio
    async def test_not_found(self):
        from src.api.rules import get_rule_by_id

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)):
            result = await get_rule_by_id(9999)

        assert result is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# create_rule
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCreateRule:
    @pytest.mark.asyncio
    async def test_create_rule_invalid_sigma(self):
        from src.api.rules import create_rule

        rule = RuleCreate(
            name="Bad Rule",
            sigma_yaml="invalid: yaml: content",
        )

        with patch("src.api.rules.parse_sigma_rule", side_effect=Exception("Invalid Sigma")):
            with pytest.raises(HTTPException) as exc_info:
                await create_rule(rule=rule, user="analyst1")
            assert exc_info.value.status_code == 400


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# delete_rule
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDeleteRule:
    @pytest.mark.asyncio
    async def test_delete_not_found(self):
        from src.api.rules import delete_rule

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 0")

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with (
            patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)),
            patch("src.api.rules.reload_rules", AsyncMock()),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await delete_rule(rule_id=9999, user="admin")
            assert exc_info.value.status_code == 404


class TestPoolAcquireDepth:
    """W4-E: admin mutations must hold at most ONE pool connection.

    log_audit_action / reload_rules / get_rule_by_id each acquire their own
    connection — when they ran INSIDE the endpoint's acquire block
    (hold-one-need-two), a saturated pool self-deadlocked every concurrent
    admin mutation. The fake collaborators acquire from the SAME tracked
    pool, so max_depth == 1 is the honest contract.
    """

    def _wired(self, conn):
        from src.api import rules as rules_module

        pool = _DepthTrackingPool(conn)

        async def fake_log_audit(**kwargs):
            async with pool.acquire():
                pass

        async def fake_reload_rules():
            async with pool.acquire():
                pass

        async def fake_get_rule_by_id(rule_id):
            async with pool.acquire():
                return {"id": rule_id, "name": "rule"}

        return rules_module, pool, fake_log_audit, fake_reload_rules, fake_get_rule_by_id

    @pytest.mark.asyncio
    async def test_create_rule_holds_at_most_one_connection(self, monkeypatch):
        conn = AsyncMock()
        conn.fetchval = AsyncMock(return_value=42)
        rules_module, pool, audit, reload, get_by_id = self._wired(conn)

        with (
            patch.object(rules_module, "get_pool", AsyncMock(return_value=pool)),
            patch.object(
                rules_module,
                "parse_sigma_rule",
                MagicMock(return_value=MagicMock(mitre_tactics=[], mitre_techniques=[])),
            ),
            patch.object(rules_module, "log_audit_action", audit),
            patch.object(rules_module, "reload_rules", reload),
            patch.object(rules_module, "get_rule_by_id", get_by_id),
        ):
            result = await rules_module.create_rule(
                rule=RuleCreate(name="R", sigma_yaml="valid: true"),
                user={"sub": "admin", "role": "admin"},
            )
        assert result["id"] == 42
        assert pool.max_depth == 1, f"hold-one-need-two: max_depth={pool.max_depth}"
        assert pool.depth == 0  # everything released

    @pytest.mark.asyncio
    async def test_update_rule_holds_at_most_one_connection(self, monkeypatch):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": 7})  # rule exists
        rules_module, pool, audit, reload, get_by_id = self._wired(conn)
        monkeypatch.setattr(rules_module, "get_pool", AsyncMock(return_value=pool))
        monkeypatch.setattr(rules_module, "log_audit_action", audit)
        monkeypatch.setattr(rules_module, "reload_rules", reload)
        monkeypatch.setattr(rules_module, "get_rule_by_id", get_by_id)

        await rules_module.update_rule(
            rule_id=7,
            updates=RuleCreate(name="R2", sigma_yaml="valid: true"),
            user={"sub": "admin", "role": "admin"},
        )
        assert pool.max_depth == 1, f"hold-one-need-two: max_depth={pool.max_depth}"
        assert pool.depth == 0

    @pytest.mark.asyncio
    async def test_delete_rule_holds_at_most_one_connection(self, monkeypatch):
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="DELETE 1")
        rules_module, pool, audit, reload, _ = self._wired(conn)
        monkeypatch.setattr(rules_module, "get_pool", AsyncMock(return_value=pool))
        monkeypatch.setattr(rules_module, "log_audit_action", audit)
        monkeypatch.setattr(rules_module, "reload_rules", reload)

        await rules_module.delete_rule(rule_id=7, user={"sub": "admin", "role": "admin"})
        assert pool.max_depth == 1, f"hold-one-need-two: max_depth={pool.max_depth}"
        assert pool.depth == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Rule mutation RBAC (P1-12)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRuleMutationRBAC:
    """Rule create/update/delete require admin role (P1-12)."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_rules(self):
        from src.api.auth import require_role

        # require_role("admin") returns an async _check_role that calls
        # get_current_user; patch it to return a viewer payload.
        check_role = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "v", "role": "viewer"}):
            with pytest.raises(HTTPException) as exc_info:
                await check_role(credentials=MagicMock())
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_pass_role_check(self):
        from src.api.auth import require_role

        check_role = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "a", "role": "admin"}):
            payload = await check_role(credentials=MagicMock())
            assert payload["role"] == "admin"

    def test_mutation_endpoints_depend_on_admin_role(self):
        """The rule mutation endpoints are wired to require_role('admin')."""
        import inspect

        from src.api.rules import create_rule, delete_rule, update_rule

        for fn in (create_rule, update_rule, delete_rule):
            sig = inspect.signature(fn)
            user_param = sig.parameters["user"]
            dep = user_param.default
            # The dependency is Depends(require_role("admin")) -> the inner
            # dependency attribute is the _check_role closure.
            assert hasattr(dep, "dependency")
            assert dep.dependency.__name__ == "_check_role"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RT-002: the HTTP detail surface (TestClient — the layer the 500 was live on)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRuleDetailHTTPSurface:
    """GET /rules/{id} must serialize INTERVAL columns (RT-002).

    Live-fire 2026-09-23: the route returned get_rule_by_id's raw dict —
    run_interval/lookback as timedelta — against RuleResponse's str fields:
    ResponseValidationError -> 500 on every detail fetch.
    """

    @pytest.fixture
    def client(self) -> TestClient:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.rules import router as rules_router

        app = FastAPI()
        app.include_router(rules_router, prefix="/api/v1")

        demo_admin = {"sub": "tester", "role": "admin"}

        from src.api.auth import get_current_user

        app.dependency_overrides[get_current_user] = lambda: demo_admin
        for route in rules_router.routes:
            for dep in route.dependencies or []:
                app.dependency_overrides[dep.call] = lambda: demo_admin

        return TestClient(app, raise_server_exceptions=False)

    def test_get_rule_detail_returns_200_with_interval_strings(self, client):
        """FAIL-proof: 500 (ResponseValidationError) on the old code."""
        from datetime import timedelta

        row = {
            "id": 9,
            "name": "HTTP Surface Rule",
            "description": "d",
            "severity": "low",
            "enabled": False,
            "last_run": None,
            "last_match": None,
            "match_count": 0,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "sigma_yaml": "title: x",
            "run_interval": timedelta(seconds=60),
            "lookback": timedelta(seconds=300),
            "threshold": 1,
            "created_at": None,
            "updated_at": None,
        }
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=row)

        class AsyncCtx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *args):
                pass

        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.rules.get_pool", AsyncMock(return_value=pool)):
            resp = client.get("/api/v1/rules/9", headers={"Authorization": "Bearer test-token"})

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["run_interval"] == "0:01:00"
        assert body["lookback"] == "0:05:00"
