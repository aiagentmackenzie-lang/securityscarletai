"""Response action executors (V0.4 "Trusted Loop").

Each executor owns three phases for its action type:

  plan()     -- pre-flight: capability check + capture the BEFORE state
                (the re-query baseline of the source system)
  execute()  -- perform the state change (or refuse, fail-closed, with an
                honest reason when a required capability is absent)
  verify()   -- RE-QUERY the source system and compare against the
                intended state; the proof that the state actually changed

Non-negotiables:
- Containment actions never auto-execute: the API layer only calls
  execute() after a recorded HITL approval (four-eyes).
- Fail-closed capability gates: pf and pwpolicy need root, fleet isolation
  needs a configured fleet endpoint. Without the capability the executor
  REFUSES (execution_failed with an honest reason) -- it never simulates
  or fakes a state change, and an unverifiable action is never reported
  as verified.
- Every verification record carries its mode ("live" or "capability_
  refused") so an auditor can see exactly what was proven.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, cast

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("response.executors")


@dataclass
class ExecutionResult:
    ok: bool
    detail: str
    intended_state: dict = field(default_factory=dict)


@dataclass
class VerificationResult:
    verified: bool
    mode: str  # "live" | "capability_refused"
    before: Any = None
    after: Any = None
    detail: str = ""


class Executor:
    """Base class: one response action type."""

    action_type: str = ""
    default_rollback_note: str = ""

    async def plan(self, params: dict) -> dict:
        """Capture the BEFORE state of the source system (evidence)."""
        raise NotImplementedError

    async def execute(self, params: dict) -> ExecutionResult:
        raise NotImplementedError

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        raise NotImplementedError

    def validate_params(self, params: dict) -> str | None:
        """Return an error string if params are invalid, else None."""
        return None


# ───────────────────────────────────────────────────────────────
# SIEM-local executors: fully verifiable on this deployment
# ───────────────────────────────────────────────────────────────


class DisableSiemUserExecutor(Executor):
    action_type = "disable_siem_user"
    default_rollback_note = (
        "Re-enable: UPDATE siem_users SET is_active = true WHERE username = <user>."
    )

    def validate_params(self, params: dict) -> str | None:
        username = params.get("username")
        if not username or not isinstance(username, str):
            return "params.username (str) is required"
        return None

    async def _is_active(self, username: str) -> bool | None:
        pool = await get_pool()
        async with pool.acquire() as conn:
            return cast(
                "bool | None",
                await conn.fetchval(
                    "SELECT is_active FROM siem_users WHERE username = $1", username
                ),
            )

    async def plan(self, params: dict) -> dict:
        username = params["username"]
        return {"before_is_active": await self._is_active(username)}

    async def execute(self, params: dict) -> ExecutionResult:
        username = params["username"]
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE siem_users SET is_active = false "
                "WHERE username = $1 RETURNING username, is_active",
                username,
            )
        if row is None:
            return ExecutionResult(
                ok=False,
                detail=f"siem user '{username}' not found; nothing changed",
            )
        # AUD-050: deactivation alone leaves the user's ALREADY-ISSUED tokens
        # valid until natural expiry (15 min access / 7 days refresh) — the
        # account reads "disabled" while the session lives. The users.py PATCH
        # path sets the Redis user_revoke marker on deactivation; containment
        # MUST do the same. Best-effort and never blocking: a Redis outage
        # cannot fail the deactivation itself, but the honest limitation is
        # recorded in the execution detail (and so in the action's evidence).
        try:
            from src.api.users import _revoke_user_tokens

            revoked = await _revoke_user_tokens(username)
        except Exception as e:  # pragma: no cover — set_user_revoke_marker already swallows
            log.warning("containment_token_revocation_failed", username=username, error=str(e))
            revoked = False
        revoke_note = (
            "live tokens revoked (user_revoke marker set)"
            if revoked
            else (
                "WARNING: token revocation unavailable (Redis down) — the account is "
                "deactivated but existing JWTs remain valid until natural expiry"
            )
        )
        return ExecutionResult(
            ok=True,
            detail=f"siem user '{username}' deactivated; {revoke_note}",
            intended_state={"username": username, "is_active": False},
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        username = params["username"]
        after = await self._is_active(username)
        verified = after is False
        return VerificationResult(
            verified=verified,
            mode="live",
            before=before,
            after={"username": username, "is_active": after},
            detail=(
                "re-query confirms the account is deactivated"
                if verified
                else f"re-query shows is_active={after!r}; intended state NOT reached"
            ),
        )


class QuarantineHostExecutor(Executor):
    action_type = "quarantine_host"
    default_rollback_note = "Lift: DELETE FROM quarantined_hosts WHERE host_name = <host>."

    def validate_params(self, params: dict) -> str | None:
        host = params.get("host_name")
        if not host or not isinstance(host, str):
            return "params.host_name (str) is required"
        return None

    async def _is_quarantined(self, host_name: str) -> dict | None:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT host_name, quarantined_at FROM quarantined_hosts WHERE host_name = $1",
                host_name,
            )
        return dict(row) if row else None

    async def plan(self, params: dict) -> dict:
        host = params["host_name"]
        existing = await self._is_quarantined(host)
        return {"before_quarantined": existing is not None}

    async def execute(self, params: dict) -> ExecutionResult:
        host = params["host_name"]
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO quarantined_hosts (host_name, reason, quarantined_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (host_name) DO NOTHING
                """,
                host,
                params.get("reason", "quarantine_host action"),
                params.get("requested_by", "system"),
            )
        return ExecutionResult(
            ok=True,
            detail=f"host '{host}' quarantined: ingest refuses its telemetry",
            intended_state={"host_name": host, "quarantined": True},
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        host = params["host_name"]
        row = await self._is_quarantined(host)
        verified = row is not None
        return VerificationResult(
            verified=verified,
            mode="live",
            before=before,
            after=row or {"host_name": host, "quarantined": False},
            detail=(
                "re-query confirms the host is on the quarantine list (ingest rejects its events)"
                if verified
                else f"re-query shows host '{host}' NOT quarantined; intended state NOT reached"
            ),
        )


class NotifySlackExecutor(Executor):
    action_type = "notify_slack"
    default_rollback_note = "Not applicable: notifications are not state changes."

    def validate_params(self, params: dict) -> str | None:
        if not params.get("message"):
            return "params.message (str) is required"
        return None

    async def plan(self, params: dict) -> dict:
        return {"before": None}

    async def execute(self, params: dict) -> ExecutionResult:
        from src.response.notifications import send_slack_notification

        sent = await send_slack_notification(str(params["message"]), params.get("channel"))
        return ExecutionResult(
            ok=sent,
            detail=(
                "slack webhook accepted the message"
                if sent
                else "slack delivery failed (unconfigured or webhook error); action failed closed"
            ),
            intended_state={"delivered": True},
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        # The execution result IS the delivery receipt (HTTP 200 from the
        # webhook). Re-delivering to "verify" would spam the channel; the
        # verification records the delivery receipt honestly.
        delivered = bool(execution and getattr(execution, "ok", False))
        return VerificationResult(
            verified=delivered,
            mode="live",
            before=before,
            after={"delivered": delivered},
            detail=(
                "verified by the slack webhook delivery receipt (HTTP 200)"
                if delivered
                else "no delivery receipt: notification was not confirmed delivered"
            ),
        )


# ───────────────────────────────────────────────────────────────
# Capability-gated executors -- fail closed without privileges
# ───────────────────────────────────────────────────────────────


def _refused(executor: str, capability: str) -> ExecutionResult:
    return ExecutionResult(
        ok=False,
        detail=(
            f"{executor} refused (fail-closed): {capability} is not available "
            "in this deployment posture; the action was NOT simulated"
        ),
    )


class PfBlockIpExecutor(Executor):
    """pf-based IP block. Root required: /dev/pf is root-only. Without
    root this refuses with an honest reason instead of pretending."""

    action_type = "pf_block_ip"
    default_rollback_note = "Lift: pfctl -a com.scarletai -t scarletai_block -T delete <ip>."

    def validate_params(self, params: dict) -> str | None:
        ip = params.get("ip")
        if not ip or not isinstance(ip, str):
            return "params.ip (str) is required"
        return None

    def _capabilities(self) -> str | None:
        """Return the missing-capability reason, or None if able."""
        if os.geteuid() != 0:
            return "root privileges required for pf"
        if shutil.which("pfctl") is None:
            return "pfctl binary not found"
        return None

    async def plan(self, params: dict) -> dict:
        cap = self._capabilities()
        if cap:
            return {"capability": cap, "before": None}
        proc = await _run_pf(["-a", "com.scarletai", "-t", "scarletai_block", "-T", "show"])
        return {"capability": None, "before": proc}

    async def execute(self, params: dict) -> ExecutionResult:
        cap = self._capabilities()
        if cap:
            return _refused("pf_block_ip", cap)
        proc = await _run_pf(
            ["-a", "com.scarletai", "-t", "scarletai_block", "-T", "add", params["ip"]]
        )
        if proc is None:
            return _refused("pf_block_ip", "pfctl execution failed")
        return ExecutionResult(
            ok=True,
            detail=f"pf table add returned: {proc.strip()}",
            intended_state={"ip": params["ip"], "in_block_table": True},
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        cap = self._capabilities()
        if cap:
            return VerificationResult(
                verified=False,
                mode="capability_refused",
                before=before,
                after=None,
                detail=f"verification unavailable: {cap}",
            )
        table = await _run_pf(["-a", "com.scarletai", "-t", "scarletai_block", "-T", "show"])
        verified = table is not None and params["ip"] in table
        return VerificationResult(
            verified=verified,
            mode="live",
            before=before,
            after=(table or "").splitlines(),
            detail=(
                "pfctl table listing contains the IP"
                if verified
                else "pfctl table listing does NOT contain the IP"
            ),
        )


class DisableMacosUserExecutor(Executor):
    """pwpolicy isDisabled on a local macOS account. Root required.
    Without root this refuses with an honest reason."""

    action_type = "disable_macos_user"
    default_rollback_note = "Lift: pwpolicy -u <user> -setpolicy 'isDisabled=0' after review."

    def validate_params(self, params: dict) -> str | None:
        username = params.get("username")
        if not username or not isinstance(username, str):
            return "params.username (str) is required"
        return None

    def _capabilities(self) -> str | None:
        if os.geteuid() != 0:
            return "root privileges required for pwpolicy"
        if shutil.which("pwpolicy") is None:
            return "pwpolicy binary not found"
        return None

    async def plan(self, params: dict) -> dict:
        cap = self._capabilities()
        if cap:
            return {"capability": cap, "before": None}
        proc = await _run_cmd(["pwpolicy", "-u", params["username"], "-getpolicy"])
        return {"capability": None, "before": proc}

    async def execute(self, params: dict) -> ExecutionResult:
        cap = self._capabilities()
        if cap:
            return _refused("disable_macos_user", cap)
        proc = await _run_cmd(["pwpolicy", "-u", params["username"], "-setpolicy", "isDisabled=1"])
        if proc is None:
            return _refused("disable_macos_user", "pwpolicy execution failed")
        return ExecutionResult(
            ok=True,
            detail=f"pwpolicy set isDisabled=1 for '{params['username']}'",
            intended_state={"username": params["username"], "disabled": True},
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        cap = self._capabilities()
        if cap:
            return VerificationResult(
                verified=False,
                mode="capability_refused",
                before=before,
                after=None,
                detail=f"verification unavailable: {cap}",
            )
        policy = await _run_cmd(["pwpolicy", "-u", params["username"], "-getpolicy"])
        verified = policy is not None and "isDisabled=1" in policy
        return VerificationResult(
            verified=verified,
            mode="live",
            before=before,
            after=policy,
            detail=(
                "pwpolicy reports isDisabled=1"
                if verified
                else "pwpolicy does NOT report isDisabled=1"
            ),
        )


class IsolateHostFleetExecutor(Executor):
    """Isolation via the osquery fleet endpoint. Fail-closed without
    OSQUERY_FLEET_URL: this deployment runs a standalone osqueryd, and a
    standalone agent has no distributed-query channel to act through."""

    action_type = "isolate_host_fleet"
    default_rollback_note = "Lift the fleet isolation for the host through the fleet console/API."

    def validate_params(self, params: dict) -> str | None:
        host = params.get("host_name")
        if not host or not isinstance(host, str):
            return "params.host_name (str) is required"
        return None

    def _capabilities(self) -> str | None:
        if not getattr(settings, "osquery_fleet_url", ""):
            return "no osquery fleet endpoint configured (OSQUERY_FLEET_URL unset)"
        return None

    async def plan(self, params: dict) -> dict:
        return {"capability": self._capabilities(), "before": None}

    async def execute(self, params: dict) -> ExecutionResult:
        cap = self._capabilities()
        if cap:
            return _refused("isolate_host_fleet", cap)
        # Fleet isolation requires the fleet API integration; until it is
        # configured AND implemented against a real fleet, refuse rather
        # than pretend. The capability gate above keeps this branch dead in
        # the current posture.
        return _refused(
            "isolate_host_fleet", "fleet isolation not implemented for this fleet version"
        )

    async def verify(
        self, params: dict, before: Any = None, execution: Any = None
    ) -> VerificationResult:
        cap = self._capabilities()
        if cap:
            return VerificationResult(
                verified=False,
                mode="capability_refused",
                before=before,
                after=None,
                detail=f"verification unavailable: {cap}",
            )
        return VerificationResult(
            verified=False,
            mode="capability_refused",
            before=before,
            after=None,
            detail="fleet isolation not implemented for this fleet version",
        )


# ───────────────────────────────────────────────────────────────
# Registry
# ───────────────────────────────────────────────────────────────

EXECUTORS: dict[str, Executor] = {
    e.action_type: e
    for e in (
        DisableSiemUserExecutor(),
        QuarantineHostExecutor(),
        NotifySlackExecutor(),
        PfBlockIpExecutor(),
        DisableMacosUserExecutor(),
        IsolateHostFleetExecutor(),
    )
}


def get_executor(action_type: str) -> Executor | None:
    """Unknown action type -> None -> the API refuses (fail-closed)."""
    return EXECUTORS.get(action_type)


# ───────────────────────────────────────────────────────────────
# Subprocess helpers (bounded, capture-only, no shell)
# ───────────────────────────────────────────────────────────────


async def _run_pf(args: list[str]) -> str | None:
    """Run pfctl with explicit args (no shell). Returns stdout, or None."""
    return await _run_cmd(["pfctl", *args])


async def _run_cmd(argv: list[str], timeout: float = 15.0) -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as e:
        log.warning("response_executor_cmd_failed", argv=argv[0], error=str(e))
        # W3-E: wait_for cancels communicate() but the child was never
        # killed — a hung pfctl/pwpolicy process leaked on every timed-out
        # execution. Kill (best-effort) and reap so no PID lingers.
        try:
            proc.kill()  # already-exited child raises ProcessLookupError (an OSError)
        except OSError:
            pass
        try:
            await proc.wait()
        except OSError:
            pass
        return None
    except OSError as e:
        log.warning("response_executor_cmd_failed", argv=argv[0], error=str(e))
        return None
    if proc.returncode != 0:
        log.warning("response_executor_cmd_failed", argv=argv[0], rc=proc.returncode)
        return None
    return (out or b"").decode(errors="replace")
