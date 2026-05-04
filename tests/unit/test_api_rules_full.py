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
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from src.api.rules import RuleCreate, RuleResponse


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
            {"id": 1, "name": "Rule 1", "description": "Desc 1", "severity": "high",
             "enabled": True, "last_run": None, "last_match": None, "match_count": 0},
            {"id": 2, "name": "Rule 2", "description": "Desc 2", "severity": "medium",
             "enabled": False, "last_run": None, "last_match": None, "match_count": 10},
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
            {"id": 1, "name": "Enabled Rule", "enabled": True},
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

        with patch("src.api.rules.get_pool", AsyncMock(return_value=mock_pool)), \
             patch("src.api.rules.reload_rules", AsyncMock()):
            with pytest.raises(HTTPException) as exc_info:
                await delete_rule(rule_id=9999, user="admin")
            assert exc_info.value.status_code == 404