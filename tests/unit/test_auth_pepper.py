"""
Tests for the optional PASSWORD_PEPPER (P2-9).

Covers:
- hash_password / verify_password round-trip with and without a pepper.
- A peppered hash differs from an unpeppered hash for the same password.
- Backward compat: with no pepper set, hashing is byte-identical to the
  pre-pepper behaviour (existing DB hashes keep validating).
- verify_password rejects a wrong password under both modes.
"""

from unittest.mock import patch

import pytest

from src.api.auth import _apply_pepper, hash_password, verify_password


class TestApplyPepper:
    def test_no_pepper_returns_plain_unchanged(self):
        """Unset pepper = no-op: the plaintext is returned as-is so the
        downstream SHA-256 pre-hash + bcrypt are byte-identical to today."""
        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = None
            assert _apply_pepper("hunter2") == "hunter2"

    def test_pepper_hmac_differs_from_plain(self):
        """With a pepper, _apply_pepper returns the HMAC-SHA256 hex digest,
        never the plaintext, and it differs from both the plain password
        and from a different pepper."""
        with patch("src.api.auth.settings") as mock_settings:
            from pydantic import SecretStr

            mock_settings.password_pepper = SecretStr("server-secret-pepper")
            out = _apply_pepper("hunter2")
            assert out != "hunter2"
            # 64 hex chars = SHA-256 digest
            assert len(out) == 64
            assert all(c in "0123456789abcdef" for c in out)

            # A different pepper yields a different digest (key matters).
            mock_settings.password_pepper = SecretStr("different-pepper")
            assert _apply_pepper("hunter2") != out


class TestPepperHashing:
    def test_round_trip_without_pepper(self):
        """verify_password(hash_password(pw)) is True with no pepper (current
        behaviour preserved)."""
        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = None
            h = hash_password("correct horse battery staple")
            assert verify_password("correct horse battery staple", h) is True
            assert verify_password("wrong password", h) is False

    def test_round_trip_with_pepper(self):
        """verify_password(hash_password(pw)) is True with a pepper set."""
        from pydantic import SecretStr

        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = SecretStr("pepper-secret-123456")
            h = hash_password("correct horse battery staple")
            assert verify_password("correct horse battery staple", h) is True
            assert verify_password("wrong password", h) is False

    def test_peppered_hash_differs_from_unpeppered(self):
        """The same password hashed with a pepper must differ from the hash
        without one (otherwise the pepper adds nothing)."""
        from pydantic import SecretStr

        plain = "same-password"
        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = None
            unpeppered = hash_password(plain)

            mock_settings.password_pepper = SecretStr("pepper-secret-123456")
            peppered = hash_password(plain)

        assert unpeppered != peppered

    def test_verify_uses_current_pepper_setting(self):
        """A hash produced WITH a pepper must NOT verify when the pepper is
        later unset (the pepper is a verification secret). This proves the
        pepper is actually mixed into the stored hash, not just the input."""
        from pydantic import SecretStr

        plain = "peppered-password"
        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = SecretStr("pepper-secret-123456")
            h = hash_password(plain)

            # Unset the pepper -> the same plaintext must NOT verify against
            # the peppered hash.
            mock_settings.password_pepper = None
            assert verify_password(plain, h) is False

    @pytest.mark.parametrize("password", ["short", "a" * 100, "pässwörd-Ω-日本語"])
    def test_round_trip_various_passwords(self, password):
        """Round-trip holds across lengths and unicode (SHA-256 pre-hash
        normalizes length; pepper HMAC handles unicode bytes)."""
        from pydantic import SecretStr

        with patch("src.api.auth.settings") as mock_settings:
            mock_settings.password_pepper = SecretStr("pepper")
            h = hash_password(password)
            assert verify_password(password, h) is True