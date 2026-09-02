"""
P3.7 boot-blocker regression — API_CORS_ORIGINS env parsing.

docker-compose passes API_CORS_ORIGINS as a bare string
(`${API_CORS_ORIGINS:-http://localhost:8501}`) and pydantic-settings 2.13
demands strict JSON for list fields at the EnvSettingsSource level — every
container boot crashed before the NoDecode + validator fix. The documented
.env.example uses the same bare-string form. All three forms must parse.
"""
import pytest
from pydantic import ValidationError
from pydantic_settings.exceptions import SettingsError


def _build_with(monkeypatch, env_value: str):
    monkeypatch.setenv("API_CORS_ORIGINS", env_value)
    from src.config.settings import Settings

    return Settings(
        db_password="x" * 40, api_secret_key="0" * 40, api_bearer_token="b" * 20
    )


class TestCorsEnvParsing:
    def test_compose_default_bare_string(self, monkeypatch):
        s = _build_with(monkeypatch, "http://localhost:8501")
        assert s.api_cors_origins == ["http://localhost:8501"]

    def test_env_example_comma_list(self, monkeypatch):
        s = _build_with(monkeypatch, "http://a:8501, http://b:8501")
        assert s.api_cors_origins == ["http://a:8501", "http://b:8501"]

    def test_json_array(self, monkeypatch):
        s = _build_with(monkeypatch, '["http://c:8501"]')
        assert s.api_cors_origins == ["http://c:8501"]

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("API_CORS_ORIGINS", raising=False)
        from src.config.settings import Settings

        s = Settings(
            db_password="x" * 40, api_secret_key="0" * 40, api_bearer_token="b" * 20
        )
        assert s.api_cors_origins == ["http://localhost:8501"]

    def test_broken_json_is_an_honest_error(self, monkeypatch):
        """A malformed JSON array must fail loudly, not be comma-split."""
        with pytest.raises((ValidationError, SettingsError)):
            _build_with(monkeypatch, "[http://broken:8501")
