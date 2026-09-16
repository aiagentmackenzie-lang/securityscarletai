"""SSF/CAEP receiver core (W1.4) — Shared Signals Framework Security Event
Tokens, push-delivered per RFC 8935, profiled by the OpenID SSF spec 1.0.

Standards anchors (verified against the published specs, 2026-09-16):
  - RFC 8935 (push delivery): POST to the receiver endpoint with
    Content-Type application/secevent+jwt; valid -> 202 Accepted (empty
    body); validation/auth errors -> 400 with {"err", "description"} using
    the IANA SET error codes.
  - SSF profile of SET (openid-sharedsignals-framework-1_0): explicit
    typing ("typ": "secevent+jwt") REQUIRED; the JWT "sub" claim MUST NOT
    be present (SSF events use the top-level "sub_id" Subject Identifier,
    RFC 9493); the "exp" claim MUST NOT be present; "iss" MUST match the
    transmitter configuration.
  - CAEP event types (openid-caep-1_0): session-revoked (no event-specific
    required claims) and credential-change (credential_type + change_type
    REQUIRED from published closed sets) are the starting vocabulary; the
    SSF verification event (.../ssf/event-type/verification) is the
    delivery health-check and is accepted when configured.

Fail-closed rules:
  - Both legs OFF by default; the endpoint refuses with access_denied when
    the receiver is not configured.
  - A SET from any issuer not configured here is refused (invalid_issuer)
    and audited — never persisted as telemetry.
  - Unknown event types are refused (closed vocabulary), consistent with
    the W1.5 deception-vocabulary doctrine.
  - A literal private key in the config file REJECTS the whole config
    (secrets are env-referenced only; the W1.7 pattern).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt
from jose.exceptions import JWTClaimsError, JWTError

from src.config.logging import get_logger
from src.ingestion.schemas import (
    EVENT_ACTION_IDENTITY_CREDENTIAL_CHANGE,
    EVENT_ACTION_IDENTITY_SESSION_REVOKED,
)

log = get_logger("ingestion.ssf")

# The ONE vocabulary home for identity event actions is
# src/ingestion/schemas.py (the W1.5 doctrine); these are the CAEP URIs.
CAEP_BASE_URI = "https://schemas.openid.net/secevent/caep/event-type/"
CAEP_SESSION_REVOKED_URI = f"{CAEP_BASE_URI}session-revoked"
CAEP_CREDENTIAL_CHANGE_URI = f"{CAEP_BASE_URI}credential-change"
SSF_VERIFICATION_URI = "https://schemas.openid.net/secevent/ssf/event-type/verification"

# Published CAEP vocabularies (openid-caep-1_0 §3.3.1). The spec's "or any
# other credential type supported mutually by the Transmitter and the
# Receiver" is honored via the per-transmitter event allow-list, not by
# silently widening this set.
CAEP_CREDENTIAL_TYPES = {
    "password",
    "pin",
    "x509",
    "fido2-platform",
    "fido2-roaming",
    "fido-u2f",
    "verifiable-credential",
    "phone-voice",
    "phone-sms",
    "app",
}
CAEP_CHANGE_TYPES = {"create", "revoke", "update", "delete"}
CAEP_INITIATING_ENTITIES = {"admin", "user", "policy", "system"}

# Short config names -> full URIs (the closed identity vocabulary).
CAEP_EVENT_SHORT_NAMES = {
    "session-revoked": CAEP_SESSION_REVOKED_URI,
    "credential-change": CAEP_CREDENTIAL_CHANGE_URI,
    "verification": SSF_VERIFICATION_URI,
}

# Allowed JOSE algs for received SETs. SSF SETs are JWS-signed; we accept
# the asymmetric algorithms an IdP transmitter plausibly uses and refuse
# everything else (fail-closed). HS256 requires an out-of-band shared
# secret per transmitter — not supported in v1 (documented).
ALLOWED_SET_ALGORITHMS = ("ES256", "RS256")

# RFC 8417 / SSF explicit typing.
SET_TYP = "secevent+jwt"
# The RFC 8935 wire content type (the header value; SET_TYP is the JOSE typ).
SET_CONTENT_TYPE = "application/secevent+jwt"


@dataclass
class TransmitterConfig:
    issuer: str
    aud: str
    events: set[str]  # full CAEP/SSF URIs
    jwks_uri: str | None = None
    jwks_inline: dict[str, Any] | None = None


@dataclass
class SSFConfig:
    receiver_enabled: bool = False
    transmitters: list[TransmitterConfig] = field(default_factory=list)
    transmitter_enabled: bool = False
    tx_issuer: str | None = None
    tx_signing_key_env: str | None = None
    tx_key_id: str | None = None
    tx_receivers: list[dict[str, Any]] = field(default_factory=list)
    config_sha256: str = ""
    source_path: str = ""


class SSFError(Exception):
    """A refused SET/config, carrying the RFC 8935 err code."""

    def __init__(self, err: str, description: str):
        self.err = err
        self.description = description
        super().__init__(f"{err}: {description}")


def _config_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_events(raw: Any, issuer: str) -> set[str]:
    """Config event names -> full URIs. Short names (session-revoked) and
    full URIs are both accepted; anything else is a config error."""
    out: set[str] = set()
    for name in raw or []:
        if not isinstance(name, str):
            raise SSFError(
                "invalid_request", f"transmitter {issuer}: event entries must be strings"
            )
        if name in CAEP_EVENT_SHORT_NAMES:
            out.add(CAEP_EVENT_SHORT_NAMES[name])
        elif name.startswith("https://schemas.openid.net/secevent/"):
            out.add(name)
        else:
            raise SSFError(
                "invalid_request",
                f"transmitter {issuer}: event type '{name}' is outside the supported vocabulary",
            )
    return out


def load_ssf_config(path: Path) -> SSFConfig:
    """Load + validate the SSF config. Raises SSFError (invalid_request) on
    any invalid entry — fail-closed; the caller must not partially use it."""
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise SSFError("invalid_request", f"cannot read SSF config {path}: {e}") from e
    if not isinstance(data, dict):
        raise SSFError("invalid_request", "SSF config must be a mapping")

    cfg = SSFConfig(
        config_sha256="sha256:" + hashlib.sha256(raw).hexdigest(), source_path=str(path)
    )
    receiver = data.get("receiver") or {}
    cfg.receiver_enabled = bool(receiver.get("enabled", False))
    for t in receiver.get("transmitters") or []:
        if not isinstance(t, dict):
            raise SSFError("invalid_request", "receiver.transmitters entries must be mappings")
        issuer = str(t.get("issuer") or "")
        if not issuer.startswith("https://"):
            raise SSFError(
                "invalid_request", f"transmitter issuer must be an https URL, got {issuer!r}"
            )
        aud = str(t.get("aud") or "")
        if not aud:
            raise SSFError(
                "invalid_request", f"transmitter {issuer}: 'aud' (our audience) is required"
            )
        jwks_uri = t.get("jwks_uri")
        jwks_inline = t.get("jwks")
        if jwks_uri and isinstance(jwks_inline, dict):
            raise SSFError(
                "invalid_request", f"transmitter {issuer}: set jwks_uri OR inline jwks, not both"
            )
        if jwks_uri and not str(jwks_uri).startswith("https://"):
            raise SSFError(
                "invalid_request", f"transmitter {issuer}: jwks_uri must be HTTP over TLS"
            )
        if not jwks_uri and not isinstance(jwks_inline, dict):
            raise SSFError(
                "invalid_request", f"transmitter {issuer}: needs jwks_uri or inline jwks"
            )
        cfg.transmitters.append(
            TransmitterConfig(
                issuer=issuer,
                aud=aud,
                jwks_uri=str(jwks_uri) if jwks_uri else None,
                jwks_inline=jwks_inline if isinstance(jwks_inline, dict) else None,
                events=_resolve_events(t.get("events"), issuer),
            )
        )

    transmitter = data.get("transmitter") or {}
    cfg.transmitter_enabled = bool(transmitter.get("enabled", False))
    if cfg.transmitter_enabled:
        cfg.tx_issuer = str(transmitter.get("issuer") or "")
        if not cfg.tx_issuer.startswith("https://"):
            raise SSFError(
                "invalid_request", "transmitter.issuer must be an https URL when enabled"
            )
        cfg.tx_signing_key_env = str(transmitter.get("signing_key_env") or "")
        if not cfg.tx_signing_key_env:
            raise SSFError(
                "invalid_request",
                "transmitter.signing_key_env is required (env-referenced only)",
            )
        if transmitter.get("signing_key"):
            # A literal key in the file rejects the WHOLE config (W1.7 rule).
            raise SSFError(
                "invalid_request",
                "literal signing key in the SSF config is refused — use *_env references",
            )
        cfg.tx_key_id = str(transmitter.get("key_id") or "scarletai-caep-1")
        receivers = transmitter.get("receivers") or []
        if not receivers:
            raise SSFError("invalid_request", "transmitter.enabled requires at least one receiver")
        for r in receivers:
            if not isinstance(r, dict):
                raise SSFError("invalid_request", "transmitter.receivers entries must be mappings")
            url = str(r.get("endpoint_url") or "")
            if not url.startswith("https://"):
                raise SSFError(
                    "invalid_request", f"receiver endpoint_url must be HTTP over TLS: {url!r}"
                )
            if not r.get("audience"):
                raise SSFError("invalid_request", f"receiver {url}: 'audience' is required")
            cfg.tx_receivers.append(dict(r))
    if cfg.receiver_enabled and not cfg.transmitters:
        raise SSFError("invalid_request", "receiver.enabled requires at least one transmitter")
    return cfg


# ───────────────────────────────────────────────────────────────
# SET parse + validate (fail-closed; RFC 8935 §2 order + SSF §4)
# ───────────────────────────────────────────────────────────────


@dataclass
class ParsedSet:
    claims: dict[str, Any]
    event_uri: str  # full URI
    event_payload: dict[str, Any]
    transmitter: TransmitterConfig
    action: str  # identity vocabulary token (or "verification")
    user_name: str | None  # best-effort principal from the subject


def _simple_subject_name(member: Any) -> str | None:
    if not isinstance(member, dict):
        return None
    if member.get("format") == "email" and member.get("email"):
        return str(member["email"])
    if member.get("format") == "iss_sub" and member.get("sub"):
        return str(member["sub"])
    if member.get("format") == "opaque" and member.get("id"):
        return str(member["id"])
    return None


def _subject_user_name(sub_id: Any) -> str | None:
    """Best-effort principal from an RFC 9493 subject (simple or complex).
    Prefer email; then iss_sub's sub; then opaque id. Complex subjects use
    the user member, then session, then device, then tenant."""
    if not isinstance(sub_id, dict):
        return None
    if sub_id.get("format") == "complex":
        for member_name in ("user", "session", "device", "tenant"):
            got = _simple_subject_name(sub_id.get(member_name))
            if got:
                return got
        return None
    return _simple_subject_name(sub_id)


def _validate_caep_optional_claims(event_payload: dict) -> None:
    """CAEP optional claims with closed value sets, validated when present
    (openid-caep-1_0 §2)."""
    ie = event_payload.get("initiating_entity")
    if ie is not None and ie not in CAEP_INITIATING_ENTITIES:
        raise SSFError(
            "invalid_request", "initiating_entity must be one of admin/user/policy/system"
        )
    ts = event_payload.get("event_timestamp")
    if ts is not None and not isinstance(ts, (int, float)):
        raise SSFError("invalid_request", "event_timestamp must be a JSON number")


def validate_set(token: str, cfg: SSFConfig) -> ParsedSet:
    """RFC 8935 §2 receiver validation, fail-closed, in the order the RFC
    lists: parse -> authentic -> audience -> issuer -> vocabulary. Raises
    SSFError carrying the IANA err code on every refusal."""
    if not cfg.receiver_enabled or not cfg.transmitters:
        raise SSFError("access_denied", "SSF receiver is not configured on this deployment")

    # 1. Parse (unverified header — the routing decision only, RFC §2).
    try:
        header = jose_jwt.get_unverified_header(token)
    except JWTError as e:
        raise SSFError("invalid_request", f"cannot parse SET: {e}") from e
    if header.get("typ") != SET_TYP:
        # SSF requires explicit typing — defense against JWT confusion.
        raise SSFError("invalid_request", "SET must be explicitly typed secevent+jwt")
    alg = header.get("alg")
    if alg not in ALLOWED_SET_ALGORITHMS:
        raise SSFError("invalid_key", f"signature algorithm {alg!r} is not accepted")

    # 2. Issuer must be a configured transmitter (before any crypto work).
    try:
        unverified = jose_jwt.get_unverified_claims(token)
    except JWTError as e:
        raise SSFError("invalid_request", f"cannot parse SET claims: {e}") from e
    iss = unverified.get("iss")
    if not isinstance(iss, str):
        raise SSFError("invalid_request", "SET missing the iss claim")
    transmitter = next((t for t in cfg.transmitters if t.issuer == iss), None)
    if transmitter is None:
        raise SSFError("invalid_issuer", f"not authorized for issuer {iss}")

    # 3. Signature verification against the transmitter's JWKS (kid-pinned).
    kid = header.get("kid")
    if not kid:
        # Without kid the receiver cannot select the verification key
        # (invalid_key — the RFC 8935 §2.2 key-selection failure).
        raise SSFError("invalid_key", "SET header missing the kid claim")
    keys: list[Any] = []
    if transmitter.jwks_uri:
        keys = _fetch_jwks(transmitter.jwks_uri)
    elif transmitter.jwks_inline:
        keys = transmitter.jwks_inline.get("keys", [])
    key_entry = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if key_entry is None:
        raise SSFError("invalid_key", f"no transmitter key for kid {kid!r}")
    try:
        key_obj = jose_jwk.construct(key_entry, algorithm=alg)
        claims = jose_jwt.decode(
            token,
            key_obj,
            algorithms=[alg],
            audience=transmitter.aud,
            issuer=iss,
            options={"verify_exp": False},  # exp presence is OUR check below
        )
    except JWTClaimsError as e:
        # python-jose raises JWTClaimsError for several claims-level
        # problems (audience mismatch, jti/iat typing). Only the audience
        # leg maps to RFC 8935 "invalid_audience" (§2.4); a malformed
        # claim otherwise is a malformed SET ("invalid_request").
        if "audience" in str(e).lower():
            raise SSFError("invalid_audience", f"SET claims validation failed: {e}") from e
        raise SSFError("invalid_request", f"SET claims validation failed: {e}") from e
    except (TypeError, ValueError) as e:
        # python-jose's numeric-claim validators leak TypeError on JSON
        # null values (int(None)); a hostile SET must be refused, never a
        # 500 on the endpoint.
        raise SSFError("invalid_request", f"SET claims validation failed: {e}") from e
    except JWTError as e:
        raise SSFError("invalid_key", f"SET signature validation failed: {e}") from e
    # python-jose skips audience validation when the aud claim is absent —
    # fail-closed: the aud claim MUST be present and name the configured
    # audience (scalar or RFC 7519 array containing it) — RFC 8935 §2.4.
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud_ok = aud == transmitter.aud
    elif isinstance(aud, list):
        aud_ok = transmitter.aud in aud
    else:
        aud_ok = False
    if not aud_ok:
        raise SSFError("invalid_audience", "SET missing or mismatching the aud claim")

    # 4. SSF profile claims (verified against the published SSF spec §4).
    if "sub" in claims:
        raise SSFError("invalid_request", "SSF SETs MUST NOT carry the JWT sub claim")
    if "exp" in claims:
        raise SSFError("invalid_request", "SSF SETs MUST NOT carry the exp claim")
    if not claims.get("jti"):
        raise SSFError("invalid_request", "SET missing the jti claim")
    if "iat" not in claims:
        raise SSFError("invalid_request", "SET missing the iat claim")
    sub_id = claims.get("sub_id")
    if not isinstance(sub_id, dict) or not sub_id.get("format"):
        raise SSFError("invalid_request", "SSF SET requires a top-level sub_id (RFC 9493)")
    events = claims.get("events")
    if not isinstance(events, dict) or len(events) != 1:
        # The events claim SHOULD contain one event (SSF §4.2.1).
        raise SSFError("invalid_request", "SET must carry exactly one event in the events claim")
    event_uri, event_payload = next(iter(events.items()))
    if not isinstance(event_payload, dict):
        event_payload = {}

    # 5. Closed event vocabulary per transmitter (plus the SSF verification
    # leg — the delivery health-check any configured transmitter may send).
    allowed = set(transmitter.events) | {SSF_VERIFICATION_URI}
    if event_uri not in allowed:
        raise SSFError(
            "invalid_request",
            f"event type {event_uri!r} is not in this transmitter's vocabulary",
        )

    if event_uri == SSF_VERIFICATION_URI:
        # The verification event's sub_id MUST be {format: opaque, id: the
        # stream id}. We do not initiate verification requests in v1, so we
        # accept and audit the receipt proof without a state check (honest:
        # no expected state to compare).
        if sub_id.get("format") != "opaque" or not sub_id.get("id"):
            raise SSFError(
                "invalid_request", "verification SET requires sub_id {format: opaque, id}"
            )
        action = "identity_verification"
    elif event_uri == CAEP_SESSION_REVOKED_URI:
        _validate_caep_optional_claims(event_payload)
        action = EVENT_ACTION_IDENTITY_SESSION_REVOKED
    elif event_uri == CAEP_CREDENTIAL_CHANGE_URI:
        ctype = event_payload.get("credential_type")
        if ctype not in CAEP_CREDENTIAL_TYPES:
            raise SSFError(
                "invalid_request",
                f"credential-change requires a known credential_type (got {ctype!r})",
            )
        if event_payload.get("change_type") not in CAEP_CHANGE_TYPES:
            raise SSFError(
                "invalid_request",
                f"credential-change requires change_type in {sorted(CAEP_CHANGE_TYPES)}",
            )
        _validate_caep_optional_claims(event_payload)
        action = EVENT_ACTION_IDENTITY_CREDENTIAL_CHANGE
    else:  # pragma: no cover — guarded by the vocabulary check above
        raise SSFError("invalid_request", f"unsupported event type {event_uri!r}")

    return ParsedSet(
        claims=claims,
        event_uri=event_uri,
        event_payload=event_payload,
        transmitter=transmitter,
        action=action,
        user_name=_subject_user_name(sub_id),
    )


def _fetch_jwks(uri: str) -> list[Any]:
    """Fetch a transmitter's JWKS over HTTPS (stdlib; bounded timeout).
    Raises SSFError(invalid_key) on any failure."""
    import urllib.request

    try:
        req = urllib.request.Request(uri, headers={"Accept": "application/json"})  # noqa: S310
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise SSFError("invalid_key", f"cannot fetch transmitter JWKS: {e}") from e
    keys = data.get("keys")
    if not isinstance(keys, list):
        raise SSFError("invalid_key", "transmitter JWKS has no keys array")
    return keys


# ───────────────────────────────────────────────────────────────
# Ingestion: a validated SET becomes identity telemetry (logs row) so the
# Sigma engine sees it like any other source (the "feeds identity
# detections" leg). High-fidelity by construction: the IdP asserts it.
# ───────────────────────────────────────────────────────────────


def set_to_event(parsed: ParsedSet, received_at: str) -> dict[str, Any]:
    """ParsedSet -> a raw_data payload for the identity logs row (never the
    raw JWT: the parsed claims are the audit truth, and the raw token could
    contain PII we should not duplicate)."""
    return {
        "issuer": parsed.transmitter.issuer,
        "event_uri": parsed.event_uri,
        "event_payload": parsed.event_payload,
        "jti": parsed.claims.get("jti"),
        "iat": parsed.claims.get("iat"),
        "txn": parsed.claims.get("txn"),
        "received_at": received_at,
    }


def severity_for_event(action: str, event_payload: dict) -> str:
    """Identity events are high-fidelity by construction (the IdP asserts
    them). Session revocation and credential revocation/deletion are the
    response-relevant legs; creations/updates stay medium."""
    if action == EVENT_ACTION_IDENTITY_SESSION_REVOKED:
        return "high"
    if action == EVENT_ACTION_IDENTITY_CREDENTIAL_CHANGE:
        return "high" if event_payload.get("change_type") in ("revoke", "delete") else "medium"
    return "info"


def event_type_for_action(action: str) -> str:
    return "info"  # identity lifecycle events are state changes, not starts/ends


def new_jti() -> str:
    """jti for SETs we EMIT (the transmitter leg imports this)."""
    return str(uuid.uuid4())
