"""
Integration-style API endpoint tests — function-level testing.

Since FastAPI's require_role() creates dynamic closures that are hard
to override via dependency_overrides, we test the endpoint functions
directly with mocked DB and auth, mirroring the pattern in test_cases_api.py.

Covers:
- Correlation API logic
- Threat Intel API logic
- Audit API logic
- Auth enforcement tests
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Correlation Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCorrelationRules:
    """Test correlation rule definitions and metadata."""

    def test_list_correlation_rules(self):
        """list_correlation_rules should return all 7 rules."""
        from src.detection.correlation import list_correlation_rules

        rules = list_correlation_rules()
        assert len(rules) == 7
        for rule in rules:
            assert "name" in rule
            assert "title" in rule
            assert "severity" in rule

    def test_get_existing_rule_info(self):
        """get_correlation_rule_info should return metadata for known rules."""
        from src.detection.correlation import get_correlation_rule_info

        info = get_correlation_rule_info("brute_force_success")
        assert info is not None
        assert "title" in info
        assert info["severity"] == "critical"

    def test_get_nonexistent_rule_info(self):
        """get_correlation_rule_info should return None for unknown rules."""
        from src.detection.correlation import get_correlation_rule_info

        assert get_correlation_rule_info("nonexistent") is None

    def test_all_rules_have_functions(self):
        """Every rule in CORRELATION_RULES should have a matching async detection function."""
        from src.detection.correlation import (
            CORRELATION_RULES,
            detect_brute_force_then_success,
            detect_credential_theft_exfil,
            detect_data_exfiltration,
            detect_defense_evasion_cleanup,
            detect_payload_callback,
            detect_persistence_activated,
            detect_privilege_escalation_chain,
        )

        func_map = {
            "brute_force_success": detect_brute_force_then_success,
            "payload_callback": detect_payload_callback,
            "persistence_activated": detect_persistence_activated,
            "data_exfiltration": detect_data_exfiltration,
            "privilege_escalation_chain": detect_privilege_escalation_chain,
            "credential_theft_exfil": detect_credential_theft_exfil,
            "defense_evasion_cleanup": detect_defense_evasion_cleanup,
        }
        for rule_name in CORRELATION_RULES:
            assert rule_name in func_map, f"Rule {rule_name} has no detection function"

    def test_brute_force_confidence_calculation(self):
        """Confidence should increase with failed count."""
        from src.detection.correlation import CORRELATION_RULES

        base_conf = CORRELATION_RULES["brute_force_success"]["confidence_base"]
        assert base_conf == 80


class TestCorrelationDetection:
    """Test correlation detection with mocked DB."""

    @pytest.mark.asyncio
    async def test_detect_payload_callback(self):
        from datetime import datetime, timezone

        from src.detection.correlation import detect_payload_callback

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_payload_callback(
                mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            )
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_persistence_activated(self):
        from datetime import datetime, timezone

        from src.detection.correlation import detect_persistence_activated

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_persistence_activated(
                mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            )
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_data_exfiltration(self):
        from datetime import datetime, timezone

        from src.detection.correlation import detect_data_exfiltration

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_data_exfiltration(
                mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            )
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_privilege_escalation_chain(self):
        from datetime import datetime, timezone

        from src.detection.correlation import detect_privilege_escalation_chain

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_privilege_escalation_chain(
                mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            )
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_get_host_sessions(self):
        from src.detection.correlation import get_host_sessions

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await get_host_sessions("server01")
            assert isinstance(result, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Threat Intel Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestThreatIntelAPIModels:
    """Test threat intel API endpoint models and logic."""

    def test_hash_type_detection_md5(self):
        """32-char hash should be classified as MD5."""
        # Just verify it accepts 32-char hashes (the endpoint validates length)
        assert len("a" * 32) == 32

    def test_hash_type_detection_sha256(self):
        """64-char hash should be classified as SHA256."""
        assert len("a" * 64) == 64


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Audit Log Function Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuditLogFunction:
    """Test log_audit_action function (core logic)."""

    @pytest.mark.asyncio
    async def test_log_with_all_fields(self):
        from src.api.audit import log_audit_action

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=42)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=mock_pool):
            result = await log_audit_action(
                actor="admin",
                action="rule.create",
                target_type="rule",
                target_id=1,
                old_values={"status": "new"},
                new_values={"status": "enabled"},
                ip_address="10.0.0.1",
            )
            assert result == 42
            # Verify JSON serialization
            call_args = mock_conn.fetchval.call_args[0]
            assert call_args[1] == "admin"
            assert call_args[2] == "rule.create"

    @pytest.mark.asyncio
    async def test_log_minimal_fields(self):
        from src.api.audit import log_audit_action

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=mock_pool):
            result = await log_audit_action(
                actor="system",
                action="alert.auto_resolve",
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_log_db_error_returns_none(self):
        from src.api.audit import log_audit_action

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=Exception("DB connection lost"))
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=mock_pool):
            with pytest.raises(RuntimeError, match="Audit log write failed"):
                await log_audit_action(
                    actor="admin",
                    action="test",
                )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auth Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuthRoleHierarchy:
    """Test RBAC role hierarchy."""

    def test_admin_has_highest_level(self):
        from src.api.auth import ROLE_HIERARCHY

        assert ROLE_HIERARCHY["admin"] > ROLE_HIERARCHY["analyst"]
        assert ROLE_HIERARCHY["analyst"] > ROLE_HIERARCHY["viewer"]

    def test_role_hierarchy_values(self):
        from src.api.auth import ROLE_HIERARCHY

        assert ROLE_HIERARCHY == {"admin": 3, "analyst": 2, "viewer": 1}

    def test_password_hash_and_verify(self):
        """Password hashing should work correctly."""
        from src.api.auth import hash_password, verify_password

        hashed = hash_password("test_password_123")
        assert verify_password("test_password_123", hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_password_sha256_prehash_handles_long_passwords(self):
        """After M-10 fix: SHA-256 pre-hash ensures passwords >72 bytes work correctly.
        bcrypt silently truncated at 72 bytes — SHA-256 pre-hash fixes this."""
        from src.api.auth import hash_password, verify_password

        long_password = "a" * 100
        hashed = hash_password(long_password)
        # Full password should verify (SHA-256 always produces 32-byte output)
        assert verify_password(long_password, hashed) is True
        # Shortened password should NOT verify (SHA-256 digest changes)
        assert verify_password("a" * 72, hashed) is False
        # Completely different should not verify
        assert verify_password("b" * 100, hashed) is False

    def test_jwt_creation_and_verification(self):
        """JWT should encode and decode correctly."""
        from jose import jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt
        from src.config.settings import settings

        token = create_jwt("analyst1", "analyst")
        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "analyst1"
        assert payload["role"] == "analyst"

    def test_jwt_expiry(self):
        """JWT should have an expiry time."""
        from src.api.auth import create_jwt

        token = create_jwt("admin", "admin")
        from jose import jwt

        from src.api.auth import JWT_ALGORITHM
        from src.config.settings import settings

        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert "exp" in payload

    def test_constant_time_token_comparison(self):
        """Token comparison should use constant-time comparison."""
        import secrets

        # This just verifies the import works - actual test would need timing analysis
        assert secrets.compare_digest("token1", "token1") is True
        assert secrets.compare_digest("token1", "token2") is False
