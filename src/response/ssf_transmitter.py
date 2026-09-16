"""SSF/CAEP transmitter (W1.4) — the SIEM's verified containment propagates
to configured IdP-layer receivers as signed CAEP SETs.

Standard anchors (verified against the published specs, 2026-09-16):
  - CAEP session-revoked
    (https://schemas.openid.net/secevent/caep/event-type/session-revoked):
    no event-specific required claims; optional claims carried where real
    (initiating_entity=system, reason_admin, event_timestamp).
  - SSF SET profile: explicit typing ("typ": "secevent+jwt"), NO "sub"
    claim, NO "exp" claim, top-level "sub_id" (RFC 9493 — our SIEM-local
    usernames are opaque), jti + iat REQUIRED, txn SHOULD (we set it to the
    response-action id so receivers can correlate SETs to one cause).
  - RFC 8935 push delivery (transmitter side): HTTP POST to the configured
    receiver endpoint_url, Content-Type application/secevent+jwt, 202 =
    delivered; 400 + {"err","description"} = refused; bounded retries are
    the receiver's business — a refused SET is audited and NOT retried.

Wiring: `maybe_propagate_session_revoked` is called from the response
executor's verified-outcome path (src/api/response.py) — ONLY after the
containment action's outcome is verify()-proven. Best-effort by doctrine:
emission failures are audited and logged, they NEVER fail or delay the
action itself (the containment already happened; propagation is the loop
closure, not the containment).
"""

from __future__ import annotations

import asyncio
import os
import time
import urllib.request
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, cast

from src.config.logging import get_logger
from src.ingestion.ssf import (
    CAEP_SESSION_REVOKED_URI,
    SSFConfig,
    SSFError,
    load_ssf_config,
    new_jti,
)

log = get_logger("response.ssf_transmitter")

# F-17 pattern: module-level references keep fire-and-forget tasks GC-alive.
_emit_tasks: set["asyncio.Task[None]"] = set()

SET_EMIT_TIMEOUT_SECONDS = 5.0
DEFAULT_ACTION_EVENT = {  # response action types that map to a CAEP event
    "disable_siem_user": CAEP_SESSION_REVOKED_URI,
    "disable_macos_user": CAEP_SESSION_REVOKED_URI,
}


@dataclass
class EmitOutcome:
    receiver: str
    ok: bool
    detail: str


def _load_key_pem(env_name: str) -> bytes:
    """The signing key, read from the environment AT USE TIME (the W1.7
    pattern: a missing env refuses the operation, audited — never an
    unconfigured send)."""
    pem = os.environ.get(env_name)
    if not pem:
        raise SSFError(
            "authentication_failed",
            f"env {env_name} is not set — the SSF transmitter refuses to sign",
        )
    return pem.encode("utf-8")


def build_session_revoked_set(
    cfg: SSFConfig,
    *,
    subject: str,
    reason: str,
    action_id: int,
    audience: str,
    now_epoch: int | None = None,
    key_pem: bytes | None = None,
) -> str:
    """Build + sign a CAEP session-revoked SET for ONE subject addressed to
    ONE receiver (the aud claim is that receiver's audience — a JWS has a
    single aud value, and receivers fail-closed-require it, so signing is
    per receiver). Returns the compact JWS (the raw wire body)."""
    from jose import jwt as jose_jwt

    if not cfg.transmitter_enabled or not cfg.tx_issuer:
        raise SSFError("access_denied", "SSF transmitter is not configured on this deployment")
    iat = now_epoch if now_epoch is not None else int(time.time())
    claims: dict[str, Any] = {
        "iss": cfg.tx_issuer,
        "aud": audience,
        "jti": new_jti(),
        "iat": iat,
        "txn": f"response-action-{action_id}",
        # SSF events use sub_id (RFC 9493); the JWT sub claim MUST NOT exist.
        "sub_id": {"format": "opaque", "id": subject},
        "events": {
            CAEP_SESSION_REVOKED_URI: {
                "initiating_entity": "system",
                "reason_admin": {"en": reason[:200]},
                "event_timestamp": iat,
            }
        },
    }
    if key_pem is None:
        key_pem = _load_key_pem(str(cfg.tx_signing_key_env))
    headers: dict[str, str] = {"typ": "secevent+jwt"}
    if cfg.tx_key_id:
        headers["kid"] = cfg.tx_key_id
    return cast(
        "str",
        jose_jwt.encode(claims, key_pem, algorithm="ES256", headers=headers),
    )


async def maybe_propagate_session_revoked(
    action_type: str, params: dict, action_id: int, verified: bool
) -> None:
    """The verified-outcome hook (called from src/api/response.py after the
    executor's verification): for action types that terminate a session,
    emit a signed CAEP session-revoked SET to every configured receiver.

    Fire-and-forget: never blocks, never fails the action. Every attempt is
    audited (ssf.emit_attempt); outcomes audited + logged.
    """
    if action_type not in DEFAULT_ACTION_EVENT:
        return  # only containment actions that end sessions propagate
    if not verified:
        return  # an unverifiable action is never propagated as verified
    try:
        cfg = load_ssf_config(_config_path())
    except SSFError as e:
        log.warning("ssf_transmitter_config_invalid", error=e.description)
        return
    if not cfg.transmitter_enabled:
        return  # off by default — silent no-op, the doctrine is in PRODUCTION.md
    subject = params.get("username")
    if not subject or not isinstance(subject, str):
        return
    detail = f"Response action {action_type} verified for user {subject} (action #{action_id})"
    task = asyncio.create_task(_emit_session_revoked(cfg, subject, detail, action_id))
    _emit_tasks.add(task)
    task.add_done_callback(_emit_tasks.discard)


def _config_path() -> Path:
    env = os.environ.get("SSF_CONFIG_PATH")
    root = Path(__file__).resolve().parent.parent.parent
    return Path(env) if env else root / "config" / "ssf.yaml"


async def _emit_session_revoked(cfg: SSFConfig, subject: str, reason: str, action_id: int) -> None:
    """Sign PER RECEIVER (a JWS carries a single aud claim, and each
    configured receiver has its own audience — the receiver will
    fail-closed-require it), POST to every configured receiver (RFC 8935
    transmitter side), audit every attempt. Bounded: one 5s timeout per
    receiver."""
    from src.api.audit import log_audit_action

    for receiver in cfg.tx_receivers:
        url = str(receiver.get("endpoint_url"))
        try:
            token = build_session_revoked_set(
                cfg,
                subject=subject,
                reason=reason,
                action_id=action_id,
                audience=str(receiver.get("audience") or ""),
            )
        except SSFError as e:
            await log_audit_action(
                actor="system",
                action="ssf.emit_attempt",
                target_type="response_action",
                target_id=action_id,
                new_values={
                    "status": "refused",
                    "err": e.err,
                    "description": e.description,
                    "receiver": url,
                },
            )
            log.warning("ssf_emit_refused", action_id=action_id, err=e.err, receiver=url)
            continue

        outcome = EmitOutcome(receiver=url, ok=False, detail="")
        try:
            headers = {
                "Content-Type": "application/secevent+jwt",
                "Accept": "application/json",
            }
            auth_env = receiver.get("authorization_header_env")
            if auth_env:
                auth_value = os.environ.get(str(auth_env))
                if not auth_value:
                    raise SSFError(
                        "authentication_failed", f"env {auth_env} is not set for this receiver"
                    )
                headers["Authorization"] = auth_value
            body = token.encode("utf-8")
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                partial(urllib.request.urlopen, req, timeout=SET_EMIT_TIMEOUT_SECONDS),  # noqa: S310
            )
            with resp:
                code = resp.status
            outcome.ok = code == 202
            outcome.detail = f"HTTP {code}"
        except SSFError as e:
            outcome.ok = False
            outcome.detail = e.description
        except Exception as e:  # noqa: BLE001 — emission must never crash the loop
            outcome.ok = False
            outcome.detail = f"transmission error: {e}"
        await log_audit_action(
            actor="system",
            action="ssf.emit_attempt",
            target_type="response_action",
            target_id=action_id,
            new_values={
                "receiver": url,
                "ok": outcome.ok,
                "detail": outcome.detail,
                "event_uri": CAEP_SESSION_REVOKED_URI,
            },
        )
        if outcome.ok:
            log.info("ssf_emit_ok", receiver=url, action_id=action_id)
        else:
            # Delivery reliability (RFC §4): no automatic retry — the
            # audited attempt is the honest record; retransmission policy
            # is an operator decision.
            log.warning("ssf_emit_failed", receiver=url, detail=outcome.detail)
