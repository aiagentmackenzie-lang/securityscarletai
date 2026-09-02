"""
Phase 1.5 (trust & truth), 2026-09-01: fail-closed on placeholder secrets.

All three required secrets (DB_PASSWORD, API_SECRET_KEY, API_BEARER_TOKEN)
are CHANGE_ME-gated at startup — a deployment booting with a placeholder
documented in the repo must crash loudly instead of running on a public
secret.
"""
from __future__ import annotations

import secrets

import pytest
from pydantic import ValidationError

from src.config.settings import Settings

REQUIRED_SECRETS = ("db_password", "api_secret_key", "api_bearer_token")


def _valid_values() -> dict:
    """Real random values for every required secret (kwargs beat env/.env)."""
    return {
        "db_password": secrets.token_urlsafe(24),
        "api_secret_key": secrets.token_hex(64),
        "api_bearer_token": secrets.token_hex(32),
    }


class TestPlaceholderGates:
    @pytest.mark.parametrize("field", REQUIRED_SECRETS)
    def test_placeholder_rejected_at_construction(self, field: str):
        """A CHANGE_ME value on ANY required secret must raise ValidationError."""
        values = _valid_values()
        values[field] = "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND"
        with pytest.raises(ValidationError) as exc:
            Settings(**values)
        assert field in str(exc.value), f"{field} placeholder must be rejected"

    @pytest.mark.parametrize("field", REQUIRED_SECRETS)
    def test_real_random_values_pass(self, field: str):
        fresh = Settings(**_valid_values())
        assert getattr(fresh, field) is not None
