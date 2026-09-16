"""SSF/CAEP push receiver endpoint (W1.4) — RFC 8935 wire contract.

POST /api/v1/ingest/ssf
  - Request body: the SET itself (a JWS-signed JWT), Content-Type MUST be
    application/secevent+jwt; Accept SHOULD be application/json.
  - Valid SET: 202 Accepted, EMPTY body (published contract).
  - Refused SET: 400 with {"err", "description"} — the IANA SET error codes
    — plus Content-Language: en-US.

Authentication is the SET signature itself: every received SET must verify
against the JWKS of a CONFIGURED transmitter (config/ssf.yaml), carry that
transmitter's audience, and use only its configured event vocabulary. There
is intentionally NO bearer dependency here — a leaked SIEM bearer token must
not become the SSF trust root, and the IdP's signature is the RFC's
deployment-specific mechanism (fail-closed: no configured transmitters ->
every request is refused). Rate limited like the other ingest paths
(RFC 8935 §5.4 names invalid-SET floods as the DoS vector).

RFC 8935 §2: persist FIRST (validation + the logs row are durable before
the response); detection runs asynchronously via the standard post-ingest
pipeline, never inside the request.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from src.api.audit import log_audit_action
from src.api.rate_limit import LIMIT_INGEST, limiter
from src.config.logging import get_logger
from src.ingestion.ssf import SET_CONTENT_TYPE, SSFError, load_ssf_config, validate_set

router = APIRouter(tags=["ingestion"])
log = get_logger("api.ssf")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SSF_YAML = REPO_ROOT / "config" / "ssf.yaml"
ERR_CONTENT_LANGUAGE = "en-US"


def _error_response(err: str, description: str) -> JSONResponse:
    """The published RFC 8935 §2.3 failure response shape."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"err": err, "description": description},
        media_type="application/json",
        headers={"Content-Language": ERR_CONTENT_LANGUAGE},
    )


def _unverified_iss(token: str) -> str:
    """Unverified iss for the refusal audit trail only — never trusted for
    any decision (the validation path re-reads it after parsing)."""
    try:
        from jose import jwt as jose_jwt

        claims = jose_jwt.get_unverified_claims(token)
        return str(claims.get("iss") or "unknown")
    except Exception:  # noqa: BLE001 — the audit path must never raise
        return "unknown"


def _config_path() -> Path:
    """The SSF config path: SSF_CONFIG_PATH env override (tests/deploys) or
    the repo default."""
    env = os.environ.get("SSF_CONFIG_PATH")
    return Path(env) if env else SSF_YAML


@router.post(
    "/ingest/ssf",
    status_code=status.HTTP_202_ACCEPTED,
    include_in_schema=True,
)
@limiter.limit(LIMIT_INGEST)
async def receive_ssf_set(request: Request) -> Response:
    """Receive one push-delivered SSF SET (RFC 8935).

    Auth: the SET's own signature against a configured transmitter's JWKS
    (config/ssf.yaml, receiver.enabled). No bearer token by design.
    """
    from src.detection.correlation import trigger_correlation_coalesced
    from src.ingestion.schemas import NormalizedEvent
    from src.ingestion.ssf import set_to_event, severity_for_event
    from src.services.writer import writer

    content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if content_type != SET_CONTENT_TYPE:
        return _error_response(
            "invalid_request", "Content-Type must be application/secevent+jwt (RFC 8935 §2.1)"
        )

    token = (await request.body()).decode("utf-8", errors="replace")
    try:
        cfg = load_ssf_config(_config_path())
    except SSFError as e:
        # A broken config is a deployment fault, not a transmitter error.
        log.error("ssf_config_invalid", error=e.description)
        return _error_response("access_denied", "SSF receiver configuration error")
    try:
        parsed = validate_set(token, cfg)
    except SSFError as e:
        # RFC 8935 §2: parse/validate/auth failures are 400 + err codes.
        # Audited: every refusal names the (unverified) issuer and reason.
        await log_audit_action(
            actor=_unverified_iss(token),
            action="ssf.set_refused",
            target_type="ssf_set",
            target_id=None,
            new_values={"err": e.err, "description": e.description},
        )
        log.info("ssf_set_refused", err=e.err, issuer=_unverified_iss(token))
        return _error_response(e.err, e.description)

    # Persist BEFORE responding (RFC 8935 §2: validate + persist, then 202).
    received_at = datetime.now(tz=timezone.utc).isoformat()
    event = NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=parsed.transmitter.issuer,
        event_category="identity",
        event_type="info",
        event_action=parsed.action,
        source="ssf",
        user_name=parsed.user_name,
        raw_data=set_to_event(parsed, received_at),
        severity=severity_for_event(parsed.action, parsed.event_payload),
    )
    await writer.write(event)

    # Post-ingest pipeline (correlation) — off the request path, per RFC §2.
    await trigger_correlation_coalesced()

    await log_audit_action(
        actor=parsed.transmitter.issuer,
        action="ssf.set_accepted",
        target_type="ssf_set",
        target_id=None,
        new_values={
            "event_uri": parsed.event_uri,
            "jti": parsed.claims.get("jti"),
            "action": parsed.action,
        },
    )
    log.info(
        "ssf_set_accepted",
        issuer=parsed.transmitter.issuer,
        event_uri=parsed.event_uri,
        action=parsed.action,
    )
    return Response(status_code=status.HTTP_202_ACCEPTED)
