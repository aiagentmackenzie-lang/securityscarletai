"""Tests for the SSF/CAEP receiver + transmitter (W1.4).

Covers:
- config/ssf.yaml loading + fail-closed validation (both legs off by
  default; literal secrets refused; TLS required; closed event vocabulary)
- validate_set: the RFC 8935 + SSF + CAEP validation matrix (explicit
  typing, aud required, issuer allow-list, kid-pinned JWKS verify, no
  sub/exp, top-level sub_id, one event, closed vocabularies)
- the RFC 8935 wire contract on POST /api/v1/ingest/ssf (202 empty body /
  400 {"err","description"} + Content-Language, no bearer auth by design)
- the transmitter: signed SET round-trips through the receiver's
  validate_set; missing signing env refuses; maybe_propagate is a silent
  no-op when disabled/unverified and audited best-effort emission otherwise
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from jose import jwt as jose_jwt

from src.ingestion.ssf import (
    CAEP_CREDENTIAL_CHANGE_URI,
    CAEP_SESSION_REVOKED_URI,
    SSF_VERIFICATION_URI,
    SSFConfig,
    SSFError,
    TransmitterConfig,
    load_ssf_config,
    new_jti,
    set_to_event,
    severity_for_event,
    validate_set,
)
from src.services.writer import writer as writer_singleton

ISSUER = "https://idp.example.com/"
AUD = "scarletai-receiver"


def _ssf_pool_mock(conn):
    """A fake pool for the SSF endpoint's replay-guard queries (W5-F)."""
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


# ───────────────────────────────────────────────────────────────
# Helpers: key material + config + SET building
# ───────────────────────────────────────────────────────────────


def _keypair() -> tuple[bytes, dict]:
    """An ES256 (P-256) keypair: (PEM private key, public JWK with kid)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "test-key-1",
        "x": base64.urlsafe_b64encode(pub.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(pub.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }
    return pem, jwk


def _jwk_from_pem(pem: bytes, kid: str = "test-key-1") -> dict:
    """The public JWK for a PEM EC private key (round-trip tests)."""
    priv = serialization.load_pem_private_key(pem, password=None)
    pub = priv.public_key().public_numbers()  # type: ignore[attr-defined]
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "x": base64.urlsafe_b64encode(pub.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(pub.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }


def _transmitter(jwk: dict, events: set[str] | None = None) -> TransmitterConfig:
    return TransmitterConfig(
        issuer=ISSUER,
        aud=AUD,
        events=events or {CAEP_SESSION_REVOKED_URI, CAEP_CREDENTIAL_CHANGE_URI},
        jwks_inline={"keys": [jwk]},
    )


def _cfg(jwk: dict, *, enabled: bool = True, events: set[str] | None = None) -> SSFConfig:
    return SSFConfig(
        receiver_enabled=enabled,
        transmitters=[_transmitter(jwk, events)],
    )


def _claims(**overrides) -> dict:
    claims = {
        "iss": ISSUER,
        "aud": AUD,
        "jti": "jti-1",
        "iat": 1700000000,
        "sub_id": {"format": "email", "email": "user@example.com"},
        "events": {CAEP_SESSION_REVOKED_URI: {}},
    }
    claims.update(overrides)
    return claims


def _encode(
    claims: dict,
    pem: bytes,
    *,
    kid: str | None = "test-key-1",
    typ: str = "secevent+jwt",
    alg: str = "ES256",
) -> str:
    headers: dict = {}
    if typ:
        headers["typ"] = typ
    if kid:
        headers["kid"] = kid
    return jose_jwt.encode(claims, pem, algorithm=alg, headers=headers)


def _write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _receiver_yaml(
    path: Path,
    *,
    enabled: bool = True,
    transmitters: list | None = None,
    transmitter_leg: dict | None = None,
) -> Path:
    data: dict = {"schema_version": 1}
    if transmitters is None:
        transmitters = [
            {
                "issuer": ISSUER,
                "aud": AUD,
                "jwks_uri": "https://idp.example.com/jwks.json",
                "events": ["session-revoked", "credential-change", "verification"],
            }
        ]
    data["receiver"] = {"enabled": enabled, "transmitters": transmitters}
    data["transmitter"] = transmitter_leg or {"enabled": False}
    return _write_yaml(path, data)


# ───────────────────────────────────────────────────────────────
# Config validation (fail-closed)
# ───────────────────────────────────────────────────────────────


class TestLoadSsfConfig:
    def test_default_repo_config_loads_both_legs_off(self):
        cfg = load_ssf_config(Path(__file__).resolve().parents[2] / "config" / "ssf.yaml")
        assert cfg.receiver_enabled is False
        assert cfg.transmitter_enabled is False
        assert cfg.transmitters == []
        assert cfg.config_sha256.startswith("sha256:")

    def test_receiver_enabled_without_transmitters_refused(self, tmp_path):
        path = _write_yaml(tmp_path / "ssf.yaml", {"receiver": {"enabled": True}})
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_transmitter_missing_aud_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml",
            transmitters=[{"issuer": ISSUER, "jwks_uri": "https://a/jwks.json", "events": []}],
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_both_jwks_sources_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml",
            transmitters=[
                {
                    "issuer": ISSUER,
                    "aud": AUD,
                    "jwks_uri": "https://idp.example.com/jwks.json",
                    "jwks": {"keys": []},
                    "events": [],
                }
            ],
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_no_jwks_source_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml", transmitters=[{"issuer": ISSUER, "aud": AUD, "events": []}]
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_http_issuer_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml",
            transmitters=[{"issuer": "http://idp.example.com/", "aud": AUD, "jwks": {"keys": []}}],
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_http_jwks_uri_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml",
            transmitters=[{"issuer": ISSUER, "aud": AUD, "jwks_uri": "http://a/jwks.json"}],
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_unknown_event_vocabulary_refused(self, tmp_path):
        path = _receiver_yaml(
            tmp_path / "ssf.yaml",
            transmitters=[
                {
                    "issuer": ISSUER,
                    "aud": AUD,
                    "jwks": {"keys": []},
                    "events": ["session-destroyed"],
                }
            ],
        )
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_literal_signing_key_rejects_whole_config(self, tmp_path):
        pem_stub = "-".join(["begin", "private", "key", "stub"])  # not real key material
        leg = {
            "enabled": True,
            "issuer": "https://siem.example.com/",
            "signing_key": pem_stub,
            "signing_key_env": "SSF_SIGNING_KEY",
            "receivers": [{"endpoint_url": "https://r.example.com/ssf", "audience": "https://r/"}],
        }
        path = _receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=leg)
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_transmitter_requires_env_reference(self, tmp_path):
        leg = {
            "enabled": True,
            "issuer": "https://siem.example.com/",
            "receivers": [{"endpoint_url": "https://r.example.com/ssf", "audience": "https://r/"}],
        }
        path = _receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=leg)
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_transmitter_requires_receiver(self, tmp_path):
        leg = {"enabled": True, "issuer": "https://siem.example.com/", "signing_key_env": "K"}
        path = _receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=leg)
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_http_receiver_endpoint_refused(self, tmp_path):
        leg = {
            "enabled": True,
            "issuer": "https://siem.example.com/",
            "signing_key_env": "K",
            "receivers": [{"endpoint_url": "http://r.example.com/ssf", "audience": "https://r/"}],
        }
        path = _receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=leg)
        with pytest.raises(SSFError) as e:
            load_ssf_config(path)
        assert e.value.err == "invalid_request"

    def test_full_transmitter_leg_loads(self, tmp_path):
        leg = {
            "enabled": True,
            "issuer": "https://siem.example.com/",
            "signing_key_env": "SSF_SIGNING_KEY",
            "key_id": "scarletai-caep-1",
            "receivers": [{"endpoint_url": "https://r.example.com/ssf", "audience": "https://r/"}],
        }
        path = _receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=leg)
        cfg = load_ssf_config(path)
        assert cfg.transmitter_enabled is True
        assert cfg.tx_key_id == "scarletai-caep-1"
        assert cfg.tx_receivers[0]["endpoint_url"] == "https://r.example.com/ssf"


# ───────────────────────────────────────────────────────────────
# validate_set — the RFC 8935 + SSF + CAEP matrix
# ───────────────────────────────────────────────────────────────


class TestValidateSet:
    def _ok(self, claims: dict, pem: bytes, **kwargs) -> object:
        return validate_set(_encode(claims, pem, **kwargs), _cfg(_jwk_from_pem(pem)))

    def test_happy_session_revoked_email_subject(self):
        pem, _ = _keypair()
        parsed = self._ok(_claims(), pem)
        assert parsed.action == "identity_session_revoked"
        assert parsed.user_name == "user@example.com"
        assert parsed.event_uri == CAEP_SESSION_REVOKED_URI
        assert parsed.transmitter.issuer == ISSUER

    def test_opaque_subject_maps_to_id(self):
        pem, jwk = _keypair()
        parsed = self._ok(_claims(sub_id={"format": "opaque", "id": "user-77"}), pem)
        assert parsed.user_name == "user-77"

    def test_complex_subject_prefers_user_member(self):
        pem, jwk = _keypair()
        sub_id = {
            "format": "complex",
            "user": {"format": "email", "email": "u@x.com"},
            "session": {"format": "opaque", "id": "sess-9"},
        }
        parsed = self._ok(_claims(sub_id=sub_id), pem)
        assert parsed.user_name == "u@x.com"

    def test_wrong_typ_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), pem, typ="JWT"), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_hs256_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), b"symmetric-secret", kid=None, alg="HS256"), _cfg(jwk))
        assert e.value.err == "invalid_key"

    def test_unknown_issuer_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(iss="https://evil.example.com/"), pem), _cfg(jwk))
        assert e.value.err == "invalid_issuer"

    def test_wrong_audience_invalid_audience(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(aud="https://other.example.com/"), pem), _cfg(jwk))
        assert e.value.err == "invalid_audience"

    def test_missing_aud_claim_invalid_audience(self):
        # python-jose skips audience validation when aud is absent — the
        # explicit fail-closed check must catch it.
        pem, jwk = _keypair()
        claims = _claims()
        claims.pop("aud")
        with pytest.raises(SSFError) as e:
            validate_set(_encode(claims, pem), _cfg(jwk))
        assert e.value.err == "invalid_audience"

    def test_array_audience_containing_expected_accepted(self):
        pem, jwk = _keypair()
        parsed = self._ok(_claims(aud=["https://a.example.com/", AUD]), pem)
        assert parsed.action == "identity_session_revoked"

    def test_missing_kid_invalid_key(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), pem, kid=None), _cfg(jwk))
        assert e.value.err == "invalid_key"

    def test_unknown_kid_invalid_key(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), pem, kid="ghost"), _cfg(jwk))
        assert e.value.err == "invalid_key"

    def test_tampered_signature_invalid_key(self):
        pem, jwk = _keypair()
        other_pem, _ = _keypair()
        # Signed by a key that is NOT the transmitter's JWKS entry.
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), other_pem), _cfg(jwk))
        assert e.value.err == "invalid_key"

    def test_sub_claim_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(sub="user@example.com"), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_exp_claim_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(exp=1999999999), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_missing_jti_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(jti=None), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_missing_iat_refused(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(iat=None), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_two_events_refused(self):
        pem, jwk = _keypair()
        events = {
            CAEP_SESSION_REVOKED_URI: {},
            CAEP_CREDENTIAL_CHANGE_URI: {"credential_type": "password", "change_type": "revoke"},
        }
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_unknown_event_uri_refused(self):
        pem, jwk = _keypair()
        events = {"https://schemas.openid.net/secevent/caep/event-type/session-destroyed": {}}
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_event_outside_transmitter_vocabulary_refused(self):
        # The URI is a known CAEP type but NOT configured for this
        # transmitter (closed vocabulary per transmitter).
        pem, jwk = _keypair()
        cfg = _cfg(jwk, events={CAEP_CREDENTIAL_CHANGE_URI})
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), pem), cfg)
        assert e.value.err == "invalid_request"

    def test_happy_credential_change(self):
        pem, jwk = _keypair()
        events = {
            CAEP_CREDENTIAL_CHANGE_URI: {"credential_type": "password", "change_type": "revoke"}
        }
        parsed = self._ok(_claims(events=events), pem)
        assert parsed.action == "identity_credential_change"

    def test_credential_change_unknown_credential_type_refused(self):
        pem, jwk = _keypair()
        events = {
            CAEP_CREDENTIAL_CHANGE_URI: {
                "credential_type": "carrier-pigeon",
                "change_type": "revoke",
            }
        }
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_credential_change_bad_change_type_refused(self):
        pem, jwk = _keypair()
        events = {
            CAEP_CREDENTIAL_CHANGE_URI: {"credential_type": "password", "change_type": "explode"}
        }
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_bad_initiating_entity_refused(self):
        pem, jwk = _keypair()
        events = {CAEP_SESSION_REVOKED_URI: {"initiating_entity": "hacker"}}
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_event_timestamp_must_be_number(self):
        pem, jwk = _keypair()
        events = {CAEP_SESSION_REVOKED_URI: {"event_timestamp": "yesterday"}}
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(events=events), pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_verification_event_accepted(self):
        pem, jwk = _keypair()
        claims = _claims(
            sub_id={"format": "opaque", "id": "stream-1"},
            events={SSF_VERIFICATION_URI: {}},
        )
        parsed = self._ok(claims, pem)
        assert parsed.action == "identity_verification"

    def test_verification_event_requires_opaque_sub_id(self):
        pem, jwk = _keypair()
        claims = _claims(
            sub_id={"format": "email", "email": "u@x.com"}, events={SSF_VERIFICATION_URI: {}}
        )
        with pytest.raises(SSFError) as e:
            validate_set(_encode(claims, pem), _cfg(jwk))
        assert e.value.err == "invalid_request"

    def test_receiver_disabled_access_denied(self):
        pem, jwk = _keypair()
        with pytest.raises(SSFError) as e:
            validate_set(_encode(_claims(), pem), _cfg(jwk, enabled=False))
        assert e.value.err == "access_denied"

    def test_verification_always_allowed_even_if_not_configured(self):
        # The SSF verification leg is the delivery health-check any
        # configured transmitter may send, regardless of its allow-list.
        pem, jwk = _keypair()
        cfg = _cfg(jwk, events={CAEP_SESSION_REVOKED_URI})
        claims = _claims(sub_id={"format": "opaque", "id": "s"}, events={SSF_VERIFICATION_URI: {}})
        parsed = validate_set(_encode(claims, pem), cfg)
        assert parsed.action == "identity_verification"


class TestSeverityAndEventShape:
    def test_session_revoked_high(self):
        assert severity_for_event("identity_session_revoked", {}) == "high"

    @pytest.mark.parametrize(
        ("change_type", "expected"),
        [("revoke", "high"), ("delete", "high"), ("create", "medium"), ("update", "medium")],
    )
    def test_credential_change_severity(self, change_type, expected):
        assert (
            severity_for_event("identity_credential_change", {"change_type": change_type})
            == expected
        )

    def test_unknown_action_info(self):
        assert severity_for_event("identity_verification", {}) == "info"

    def test_set_to_event_shape(self):
        pem, jwk = _keypair()
        parsed = validate_set(_encode(_claims(jti="abc"), pem), _cfg(jwk))
        event = set_to_event(parsed, "2026-09-16T00:00:00+00:00")
        assert event["issuer"] == ISSUER
        assert event["event_uri"] == CAEP_SESSION_REVOKED_URI
        assert event["jti"] == "abc"
        assert event["received_at"] == "2026-09-16T00:00:00+00:00"
        assert "token" not in event  # never the raw JWT

    def test_new_jti_unique(self):
        assert new_jti() != new_jti()


# ───────────────────────────────────────────────────────────────
# W5-B: the JWKS fetch cache + key-rotation refetch
# ───────────────────────────────────────────────────────────────


class TestJwksCache:
    """W5-B: the JWKS fetch is TTL-cached per jwks_uri (the old code
    re-fetched on EVERY SET — one hung IdP stalled the loop 10s per SET);
    a kid-miss forces exactly ONE refetch (transmitter key rotation)
    before refusing."""

    JWKS_URI = "https://idp.example.com/jwks.json"

    @pytest.fixture(autouse=True)
    def _clean_cache(self):
        from src.ingestion import ssf as _ssf

        _ssf._JWKS_CACHE.clear()
        yield
        _ssf._JWKS_CACHE.clear()

    def _uri_cfg(self) -> SSFConfig:
        return SSFConfig(
            receiver_enabled=True,
            transmitters=[
                TransmitterConfig(
                    issuer=ISSUER,
                    aud=AUD,
                    events={CAEP_SESSION_REVOKED_URI, CAEP_CREDENTIAL_CHANGE_URI},
                    jwks_uri=self.JWKS_URI,
                )
            ],
        )

    def test_cached_path_no_second_fetch_within_ttl(self, monkeypatch):
        import io

        pem, jwk = _keypair()
        payload = {"keys": [jwk]}
        calls: list[int] = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        cfg = self._uri_cfg()

        token = _encode(_claims(), pem)
        parsed = validate_set(token, cfg)
        assert parsed.transmitter.issuer == ISSUER
        parsed2 = validate_set(token, cfg)  # second SET within the TTL
        assert parsed2.transmitter.issuer == ISSUER
        assert len(calls) == 1, "cached path must return without a second fetch"

    def test_kid_miss_forces_exactly_one_refetch(self, monkeypatch):
        import io

        pem1, jwk1 = _keypair()
        pem2, jwk2 = _keypair()
        rotated = {**jwk2, "kid": "test-key-2"}
        payload = {"keys": [jwk1]}  # server starts WITHOUT the rotated key
        calls: list[int] = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        cfg = self._uri_cfg()

        # SET 1: signed with the known key — cold cache, one fetch.
        validate_set(_encode(_claims(), pem1), cfg)
        assert len(calls) == 1
        # SET 2: signed with the ROTATED key — kid-miss must force exactly
        # ONE refetch; the "server" now serves the rotated key too, so the
        # SET verifies (calls 1 -> 2, not 3: one fetch per miss, no storm).
        payload["keys"].append(rotated)
        parsed = validate_set(_encode(_claims(), pem2, kid="test-key-2"), cfg)
        assert parsed.transmitter.issuer == ISSUER
        assert len(calls) == 2, "kid-miss must trigger exactly one refetch"
        # SET 3: another unknown kid — the miss forces exactly one further
        # refetch (per-miss semantics), the refreshed JWKS still lacks the
        # kid, and the SET is refused (fail-closed after the one retry).
        with pytest.raises(SSFError) as exc_info:
            validate_set(_encode(_claims(), pem1, kid="ghost"), cfg)
        assert exc_info.value.err == "invalid_key"
        assert len(calls) == 3


# ───────────────────────────────────────────────────────────────
# The RFC 8935 endpoint contract (router-only TestClient; NO auth
# dependency — the SET signature + configured transmitter IS the auth)
# ───────────────────────────────────────────────────────────────


class TestReceiveEndpoint:
    @pytest.fixture
    def app(self):
        from src.api.ssf import router

        application = FastAPI()
        application.include_router(router, prefix="/api/v1")
        return application

    @pytest.fixture
    def client(self, app):
        from fastapi.testclient import TestClient as TC

        return TC(app)

    def _post(self, client, token: str, content_type: str = "application/secevent+jwt"):
        return client.post(
            "/api/v1/ingest/ssf",
            content=token,
            headers={"Content-Type": content_type},
        )

    def test_wrong_content_type_400(self, app, client, tmp_path, monkeypatch):
        monkeypatch.setenv("SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml")))
        pem, jwk = _keypair()
        resp = self._post(client, _encode(_claims(), pem), content_type="application/json")
        assert resp.status_code == 400
        assert resp.json()["err"] == "invalid_request"
        assert resp.headers["content-language"] == "en-US"

    def test_receiver_disabled_400_access_denied(self, client, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "SSF_CONFIG_PATH",
            str(_receiver_yaml(tmp_path / "ssf.yaml", enabled=False)),
        )
        pem, _ = _keypair()
        with patch("src.api.ssf.log_audit_action", AsyncMock()):
            resp = self._post(client, _encode(_claims(), pem))
        assert resp.status_code == 400
        assert resp.json()["err"] == "access_denied"

    def test_missing_config_400_access_denied(self, client, tmp_path, monkeypatch):
        monkeypatch.setenv("SSF_CONFIG_PATH", str(tmp_path / "nope.yaml"))
        resp = self._post(client, "garmin-token-not-even-a-jwt")
        assert resp.status_code == 400
        assert resp.json()["err"] == "access_denied"

    def test_valid_set_202_empty_body_persists_audits(self, client, tmp_path, monkeypatch):
        pem, jwk = _keypair()
        tx = {
            "issuer": ISSUER,
            "aud": AUD,
            "jwks": {"keys": [jwk]},
            "events": ["session-revoked", "credential-change", "verification"],
        }
        monkeypatch.setenv(
            "SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml", transmitters=[tx]))
        )
        with (
            patch("src.api.ssf.log_audit_action", AsyncMock()) as audit,
            patch("src.detection.correlation.trigger_correlation_coalesced", AsyncMock()),
            patch.object(writer_singleton, "write", AsyncMock()) as write,
            patch(
                "src.api.ssf.get_pool",
                return_value=_ssf_pool_mock(
                    AsyncMock(fetchval=AsyncMock(return_value="2026-09-23T00:00:00+00:00+00"))
                ),
            ),
        ):
            resp = self._post(client, _encode(_claims(), pem))
        assert resp.status_code == 202
        assert resp.content == b""  # the published RFC 8935 contract
        assert write.call_count == 1
        event = write.call_args[0][0]
        assert event.source == "ssf"
        assert event.event_category == "identity"
        assert event.event_action == "identity_session_revoked"
        assert event.host_name == ISSUER
        assert event.user_name == "user@example.com"
        accepted = [c for c in audit.call_args_list if c.kwargs.get("action") == "ssf.set_accepted"]
        assert accepted, "accepted SETs must be audited"

    def test_replayed_set_refused_audited_not_persisted(self, client, tmp_path, monkeypatch):
        # W5-F: a SET whose (issuer, jti) was already accepted (fetchval ->
        # None: the ON CONFLICT swallowed the insert) is a REPLAY — 400
        # invalid_request, audited, and the event is NOT persisted twice.
        pem, jwk = _keypair()
        tx = {"issuer": ISSUER, "aud": AUD, "jwks": {"keys": [jwk]}, "events": ["session-revoked"]}
        monkeypatch.setenv(
            "SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml", transmitters=[tx]))
        )
        replay_conn = AsyncMock()
        replay_conn.fetchval = AsyncMock(return_value=None)  # conflict — already seen
        with (
            patch("src.api.ssf.log_audit_action", AsyncMock()) as audit,
            patch.object(writer_singleton, "write", AsyncMock()) as write,
            patch("src.detection.correlation.trigger_correlation_coalesced", AsyncMock()),
            patch("src.api.ssf.get_pool", return_value=_ssf_pool_mock(replay_conn)),
        ):
            resp = self._post(client, _encode(_claims(jti="jti-1"), pem))
        assert resp.status_code == 400
        assert resp.json()["err"] == "invalid_request"
        assert "replay" in resp.json()["description"]
        replayed = [
            c for c in audit.call_args_list if c.kwargs.get("action") == "ssf.set_replay_refused"
        ]
        assert replayed, "replays must be audited"
        assert replayed[0].kwargs["new_values"]["jti"] == "jti-1"
        assert replayed[0].kwargs["actor"] == ISSUER
        write.assert_not_awaited()  # the replayed SET is never persisted twice
        # The guard query is the (issuer, jti) memory insert.
        sql = replay_conn.fetchval.call_args.args[0]
        assert "ON CONFLICT DO NOTHING" in sql
        assert "RETURNING seen_at" in sql

    def test_fresh_jti_row_inserts_and_event_persists(self, client, tmp_path, monkeypatch):
        # W5-F: the FIRST delivery inserts its (issuer, jti) row and proceeds.
        pem, jwk = _keypair()
        tx = {"issuer": ISSUER, "aud": AUD, "jwks": {"keys": [jwk]}, "events": ["session-revoked"]}
        monkeypatch.setenv(
            "SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml", transmitters=[tx]))
        )
        fresh_conn = AsyncMock()
        fresh_conn.fetchval = AsyncMock(return_value="2026-09-23T00:00:00+00:00")
        with (
            patch("src.api.ssf.log_audit_action", AsyncMock()) as audit,
            patch.object(writer_singleton, "write", AsyncMock()) as write,
            patch("src.detection.correlation.trigger_correlation_coalesced", AsyncMock()),
            patch("src.api.ssf.get_pool", return_value=_ssf_pool_mock(fresh_conn)),
        ):
            resp = self._post(client, _encode(_claims(), pem))
        assert resp.status_code == 202
        write.assert_awaited_once()  # the event IS persisted
        sql = fresh_conn.fetchval.call_args.args[0]
        assert "INSERT INTO ssf_seen_sets" in sql

    def test_unknown_issuer_400_audited(self, client, tmp_path, monkeypatch):
        pem, jwk = _keypair()
        tx = {"issuer": ISSUER, "aud": AUD, "jwks": {"keys": [jwk]}, "events": ["session-revoked"]}
        monkeypatch.setenv(
            "SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml", transmitters=[tx]))
        )
        with patch("src.api.ssf.log_audit_action", AsyncMock()) as audit:
            resp = self._post(client, _encode(_claims(iss="https://evil.example.com/"), pem))
        assert resp.status_code == 400
        assert resp.json()["err"] == "invalid_issuer"
        refused = [c for c in audit.call_args_list if c.kwargs.get("action") == "ssf.set_refused"]
        assert refused, "refusals must be audited"
        assert refused[0].kwargs["new_values"]["err"] == "invalid_issuer"

    def test_unparseable_token_400(self, client, tmp_path, monkeypatch):
        tx = {
            "issuer": ISSUER,
            "aud": AUD,
            "jwks_uri": "https://idp.example.com/jwks.json",
            "events": [],
        }
        monkeypatch.setenv(
            "SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml", transmitters=[tx]))
        )
        with patch("src.api.ssf.log_audit_action", AsyncMock()):
            resp = self._post(client, "not-a-jwt", content_type="application/secevent+jwt")
        assert resp.status_code == 400
        assert resp.json()["err"] == "invalid_request"


# ───────────────────────────────────────────────────────────────
# Transmitter: signed SET build + round-trip + best-effort emission
# ───────────────────────────────────────────────────────────────


def _tx_leg_cfg() -> dict:
    return {
        "enabled": True,
        "issuer": "https://siem.example.com/",
        "signing_key_env": "SSF_SIGNING_KEY",
        "key_id": "scarletai-caep-1",
        "receivers": [
            {"endpoint_url": "https://r.example.com/ssf", "audience": "https://r.example.com/"}
        ],
    }


class TestTransmitter:
    def test_round_trip_through_validate_set(self, tmp_path):
        from src.response.ssf_transmitter import build_session_revoked_set

        pem, jwk = _keypair()
        tx_leg = _tx_leg_cfg()
        tx_cfg = load_ssf_config(_receiver_yaml(tmp_path / "tx.yaml", transmitter_leg=tx_leg))
        token = build_session_revoked_set(
            tx_cfg,
            subject="alice",
            reason="verified disable_siem_user",
            action_id=42,
            audience="https://r.example.com/",
            key_pem=pem,
        )
        # The receiver side of the loop: the SIEM's own key is the
        # transmitter's JWKS — the JWK kid MUST match the kid the
        # transmitter put in the JOSE header (tx_key_id).
        rx = SSFConfig(
            receiver_enabled=True,
            transmitters=[
                TransmitterConfig(
                    issuer="https://siem.example.com/",
                    aud="https://r.example.com/",
                    events={CAEP_SESSION_REVOKED_URI},
                    jwks_inline={"keys": [_jwk_from_pem(pem, kid="scarletai-caep-1")]},
                )
            ],
        )
        parsed = validate_set(token, rx)
        assert parsed.action == "identity_session_revoked"
        assert parsed.user_name == "alice"
        assert parsed.claims["txn"] == "response-action-42"
        assert parsed.claims["iss"] == "https://siem.example.com/"
        assert parsed.claims["aud"] == "https://r.example.com/"

    def test_transmitter_disabled_refuses(self, tmp_path):
        from src.response.ssf_transmitter import build_session_revoked_set

        cfg = load_ssf_config(_receiver_yaml(tmp_path / "ssf.yaml"))
        with pytest.raises(SSFError) as e:
            build_session_revoked_set(
                cfg, subject="a", reason="r", action_id=1, audience="https://r/", key_pem=b"x"
            )
        assert e.value.err == "access_denied"

    def test_missing_signing_env_refuses(self, tmp_path, monkeypatch):
        from src.response.ssf_transmitter import build_session_revoked_set

        monkeypatch.delenv("SSF_SIGNING_KEY", raising=False)
        cfg = load_ssf_config(_receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=_tx_leg_cfg()))
        with pytest.raises(SSFError) as e:
            build_session_revoked_set(
                cfg, subject="a", reason="r", action_id=1, audience="https://r/"
            )
        assert e.value.err == "authentication_failed"

    def test_signing_env_used_when_no_pem(self, tmp_path, monkeypatch):
        from src.response.ssf_transmitter import build_session_revoked_set

        pem, _ = _keypair()
        monkeypatch.setenv("SSF_SIGNING_KEY", pem.decode())
        cfg = load_ssf_config(_receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=_tx_leg_cfg()))
        token = build_session_revoked_set(
            cfg, subject="a", reason="r", action_id=1, audience="https://r.example.com/"
        )
        header = jose_jwt.get_unverified_header(token)
        assert header["typ"] == "secevent+jwt"
        assert header["kid"] == "scarletai-caep-1"

    async def test_maybe_propagate_noop_for_other_actions(self):
        from src.response import ssf_transmitter

        assert (
            await ssf_transmitter.maybe_propagate_session_revoked(
                "quarantine_host", {"username": "u"}, 1, True
            )
            is None
        )
        assert not ssf_transmitter._emit_tasks

    async def test_maybe_propagate_noop_unverified(self, tmp_path, monkeypatch):
        from src.response import ssf_transmitter

        monkeypatch.setenv(
            "SSF_CONFIG_PATH",
            str(_receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=_tx_leg_cfg())),
        )
        await ssf_transmitter.maybe_propagate_session_revoked(
            "disable_siem_user", {"username": "u"}, 1, verified=False
        )
        assert not ssf_transmitter._emit_tasks

    async def test_maybe_propagate_noop_disabled(self, tmp_path, monkeypatch):
        from src.response import ssf_transmitter

        monkeypatch.setenv("SSF_CONFIG_PATH", str(_receiver_yaml(tmp_path / "ssf.yaml")))
        await ssf_transmitter.maybe_propagate_session_revoked(
            "disable_siem_user", {"username": "u"}, 1, verified=True
        )
        assert not ssf_transmitter._emit_tasks

    async def test_maybe_propagate_emits_audited(self, tmp_path, monkeypatch):
        """Enabled + verified: a signed SET is POSTed (stubbed urlopen) and
        the attempt is audited — the best-effort doctrine."""
        from src.response import ssf_transmitter

        pem, _ = _keypair()
        monkeypatch.setenv(
            "SSF_CONFIG_PATH",
            str(_receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=_tx_leg_cfg())),
        )
        monkeypatch.setenv("SSF_SIGNING_KEY", pem.decode())

        class _FakeResp:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b""

        posted = []

        def fake_urlopen(req, timeout=None):
            posted.append((req.full_url, req.headers))
            return _FakeResp()

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        with patch("src.api.audit.log_audit_action", AsyncMock()) as audit:
            await ssf_transmitter.maybe_propagate_session_revoked(
                "disable_siem_user", {"username": "alice"}, 7, verified=True
            )
            tasks = list(ssf_transmitter._emit_tasks)
            assert tasks, "the emit task must be created"
            await asyncio.gather(*tasks)
        assert len(posted) == 1
        assert posted[0][0] == "https://r.example.com/ssf"
        assert posted[0][1].get("Content-type") == "application/secevent+jwt"
        attempts = [c for c in audit.call_args_list if c.kwargs.get("action") == "ssf.emit_attempt"]
        assert attempts and attempts[-1].kwargs["new_values"]["ok"] is True

    async def test_emit_refusal_audited_not_sent(self, tmp_path, monkeypatch):
        """A refused sign (missing env) is audited and NOTHING is posted."""
        from src.response import ssf_transmitter

        monkeypatch.setenv(
            "SSF_CONFIG_PATH",
            str(_receiver_yaml(tmp_path / "ssf.yaml", transmitter_leg=_tx_leg_cfg())),
        )
        monkeypatch.delenv("SSF_SIGNING_KEY", raising=False)
        posted = []
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: posted.append(req))
        with patch("src.api.audit.log_audit_action", AsyncMock()) as audit:
            await ssf_transmitter.maybe_propagate_session_revoked(
                "disable_siem_user", {"username": "alice"}, 3, verified=True
            )
            tasks = list(ssf_transmitter._emit_tasks)
            await asyncio.gather(*tasks)
        assert posted == []
        refused = [c for c in audit.call_args_list if c.kwargs.get("action") == "ssf.emit_attempt"]
        assert refused and refused[0].kwargs["new_values"]["status"] == "refused"
