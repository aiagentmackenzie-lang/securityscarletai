"""
Log ingestion endpoint — receives events via HTTP POST.

Security:
- Authenticated with bearer token
- Input validated with Pydantic (rejects malformed events)
- Field length limits prevent memory exhaustion attacks
- No raw SQL — everything goes through the writer
- Rate limited (Epic 4) to LIMIT_INGEST per IP
"""

import asyncio
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from src.api.audit import log_audit_action
from src.api.auth import get_ingest_client
from src.api.rate_limit import LIMIT_INGEST, limiter
from src.config.logging import get_logger
from src.db.connection import get_pool

# AUD-016: CORRELATION_MAX_CONCURRENT / _correlation_semaphore were imported
# here with a stale "kept for tests" noqa but referenced NOWHERE in this
# file — the live cap lives inside correlation.py itself. Only the shared
# trigger is needed.
from src.detection.correlation import trigger_correlation_coalesced
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["ingestion"])
log = get_logger("api.ingest")

# F-10 (plan phase 5): bounds for the background post-processing work.
# run_all_correlations hits the DB with 7 heavy window/JOIN queries per
# batch, fire-and-forget, with NO cap: an ingest burst collapses the pool.
# - Semaphore: at most CORRELATION_MAX_CONCURRENT runs at once.
# - Coalescing: while a run is in flight, new batches skip their own run --
#   every run scans the whole lookback anyway, so queued duplicates only
#   pile up queries and rows.
# F-17: module-level references keep the fire-and-forget tasks GC-alive
# (an unreferenced task can be garbage-collected mid-flight by CPython).
# The coalescing state lives in src.detection.correlation (imported above) so
# the scheduler's periodic sweep shares the SAME inflight guard as the
# established ingest-path names.

_post_process_tasks: set["asyncio.Task[None]"] = set()


async def _trigger_correlation_coalesced() -> None:
    """Ingest-path name for the shared trigger (kept for callers + tests):
    while one run is in flight, new batches skip -- the scheduler sweep
    covers the rest (see trigger_correlation_coalesced)."""
    await trigger_correlation_coalesced()


class IngestEvent(BaseModel):
    """Schema for HTTP-ingested events. Stricter than internal events."""

    timestamp: datetime = Field(alias="@timestamp")
    host_name: str = Field(max_length=253)
    source: str = Field(max_length=100)
    event_category: str = Field(max_length=50)
    event_type: str = Field(max_length=50)
    event_action: str | None = Field(None, max_length=100)
    raw_data: dict = Field(default_factory=dict)
    # Optional fields
    user_name: str | None = Field(None, max_length=256)
    process_name: str | None = Field(None, max_length=256)
    process_cmdline: str | None = Field(None, max_length=4096)
    process_path: str | None = Field(None, max_length=1024)
    process_pid: int | None = Field(None)
    host_ip: str | None = Field(None, max_length=45)
    source_ip: str | None = Field(None, max_length=45)
    destination_ip: str | None = Field(None, max_length=45)
    destination_port: int | None = Field(None)
    file_path: str | None = Field(None, max_length=1024)
    file_hash: str | None = Field(None, max_length=128)
    severity: str | None = Field(None, max_length=20)

    @field_validator("host_ip", "source_ip", "destination_ip", mode="before")
    @classmethod
    def _empty_ip_to_none(cls, v: str | None) -> str | None:
        """\"\" is not an IP — the logs INET columns reject it and one such
        event dead-letters its whole batch (2026-09-07 live finding).
        NULL is the honest value for \"no address\"."""
        if v == "":
            return None
        return v

    @field_validator("host_name")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        """Prevent log injection via hostname field."""
        # Strip control characters and newlines
        return "".join(c for c in v if c.isprintable() and c not in "\n\r\t")


class IngestResponse(BaseModel):
    accepted: int
    message: str
    rejected_quarantine: int = 0  # V0.4: events refused because their host is quarantined


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(LIMIT_INGEST)
async def ingest_events(
    request: Request,  # slowapi needs Request to derive the rate-limit key
    response: Response,  # slowapi injects X-RateLimit-* headers here
    events: list[IngestEvent],
    # P2.6: ingest-scoped dependency — additionally honors the optional
    # INGEST_BEARER_TOKEN as viewer-class; a leaked ingest token cannot
    # browse the SIEM (every other endpoint uses get_current_user).
    _token: Annotated[dict, Depends(get_ingest_client)],
):
    """Ingest one or more security events.

    Requires: Bearer token in Authorization header.
    Rate limited to LIMIT_INGEST (100/minute by IP).

    Size bounds (AUD-008, documented per decision): the request body is
    capped at 1MB by RequestValidationMiddleware (Content-Length AND
    chunked both abort over the cap — the raw_data vector is bounded at
    the request level), and the batch is capped at 1000 events (413
    below). Residual gap, honestly stated: per-event size WITHIN a batch
    is not separately capped — a single event may approach the whole 1MB
    request budget.

    V0.5a fleet binding: a fleet-enrollment token may ONLY deliver events
    for its own enrolled host_name (identity.kind == "fleet" carries
    fleet_host). Any other host in the batch refuses the WHOLE batch with
    403 — fail-closed, and the refusal is audited (spoof attempt).
    """
    if len(events) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Maximum 1000 events per batch",
        )

    # V0.5a: fleet tokens are host-bound. Enforced per batch, fail-closed.
    # (Shape-safe: the dependency yields a dict identity through FastAPI;
    # direct-call tests may pass a raw token string.)
    fleet_host: str | None = None
    if isinstance(_token, dict) and _token.get("kind") == "fleet":
        fleet_host = _token.get("fleet_host")
        rogue = sorted({e.host_name for e in events if e.host_name != fleet_host})
        if rogue:
            try:
                await log_audit_action(
                    actor=_token.get("username") or "fleet:unknown",
                    action="fleet.host_spoof_refused",
                    target_type="fleet_enrollment",
                    new_values={"fleet_host": fleet_host, "claimed_hosts": rogue},
                )
            except Exception as e:  # audit outage must not block the refusal
                log.warning("fleet_spoof_audit_write_failed", error=str(e))
            log.warning(
                "ingest_fleet_host_binding_violation",
                fleet_host=fleet_host,
                claimed_hosts=rogue,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"fleet token may only ingest events for host '{fleet_host}'"),
            )

    # Import here to avoid circular dependency
    # W2.2 durable mode: fail-closed BEFORE any event of the batch is taken
    # when Redis is unavailable — the SIEM does not half-accept a batch it
    # cannot durably queue (the quarantine doctrine shape).
    from src.ingestion.durable import (
        DurableIngestUnavailable,
        durable_mode,
        durable_redis_probe,
        persist_event,
    )

    if durable_mode():
        if not await durable_redis_probe():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "durable ingest buffer unavailable — refusing events "
                    "(fail-closed; the SIEM does not accept at-most-once while "
                    "promising durability)"
                ),
            )

    # V0.4 quarantine enforcement: the ingest endpoint refuses events from
    # hosts on the quarantine list (fail-closed: a quarantined host's
    # telemetry does not enter the pipeline). The check re-queries the
    # enforcement table per batch; a DB outage here must NOT silently accept
    # quarantined telemetry, so a lookup failure refuses the whole batch.
    quarantined_hosts: set[str] = set()
    try:
        pool_q = await get_pool()
        async with pool_q.acquire() as conn_q:
            quarantined_hosts = {
                r["host_name"]
                for r in await conn_q.fetch("SELECT host_name FROM quarantined_hosts")
            }
    except Exception as e:
        # AUD-001 fail-closed: a DB outage leaves quarantine enforcement
        # UNKNOWN — the batch is refused, exactly like /ingest/osquery below.
        # The old behavior warned and accepted (fail-open): with the lookup
        # down and the writer alive, a quarantined host's telemetry entered
        # the pipeline silently. Containment enforcement never guesses.
        log.warning("quarantine_lookup_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="quarantine enforcement unavailable; batch refused",
        ) from e

    count = 0
    rejected_quarantine = 0
    hosts_in_batch: set[str] = set()
    batch_events: list[NormalizedEvent] = []  # P2.4: broadcast happens in the background
    for event_data in events:
        event = NormalizedEvent(
            **event_data.model_dump(by_alias=True),
            enrichment={},
        )
        if event.host_name and event.host_name in quarantined_hosts:
            rejected_quarantine += 1
            log.warning(
                "ingest_event_refused_quarantined_host",
                host_name=event.host_name,
                source=event.source,
            )
            continue
        try:
            await persist_event(event)
        except DurableIngestUnavailable as e:
            # Fail closed: events enqueued so far stay durable in the stream
            # (they will be persisted by the consumer); the REST is refused.
            log.error(
                "ingest_durable_enqueue_failed",
                accepted=count,
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"durable ingest buffer unavailable — {count} events durably "
                    "queued, remainder refused (fail-closed)"
                ),
            ) from e
        if event.host_name:
            hosts_in_batch.add(event.host_name)
        # P2.4: broadcast MOVED OUT of the ingest hot path — it now runs in
        # the per-batch _post_process task below. WS delivery is presentation,
        # not ingestion: awaiting a send loop per event (with no send timeout)
        # let one slow dashboard socket stall the ingest request.
        batch_events.append(event)
        count += 1

    # P3.3: metrics — events accepted (counter; no high-cardinality labels).
    from src.api.metrics import ingest_accepted_total

    ingest_accepted_total.inc(count)

    # Epic 9: fire-and-forget enrichment + correlation per batch.
    # We do NOT await these — the HTTP request has already returned 202 to
    # the agent. If enrichment is slow, ingestion must not be slow. If
    # enrichment raises, the request is already on the wire, so we just
    # log and move on.
    if count > 0:
        try:
            # W1.8 shared-builder doctrine: the enrichment write-back is the
            # SAME function the W2.2 durable consumer uses (no drift
            # possible). Flush-first (P1-07) + F-18 keying documented in
            # write_back_enrichment.
            from src.enrichment.pipeline import write_back_enrichment

            async def _enrich_and_writeback():
                """Enrich the batch and write back. Best-effort: a failure
                here never affects ingestion — the events are already
                persisted and the HTTP 202 is on the wire."""
                try:
                    await write_back_enrichment(batch_events)
                except Exception as e:  # pragma: no cover — defensive
                    log.warning("ingest_enrichment_loop_failed", error=str(e))

            async def _run_correlation_coalesced():
                """Coalescing lives in the module-level
                _trigger_correlation_coalesced (shared with /ingest/osquery)."""
                await _trigger_correlation_coalesced()

            async def _post_process():
                try:
                    # P2.4: broadcast the persisted batch off the hot path.
                    # Best-effort (P1-13) — a failure here never affects
                    # ingestion, and broadcast_event itself time-caps each
                    # send (slow clients get evicted, not waited on).
                    for event in batch_events:
                        try:
                            from src.api.websocket import broadcast_event

                            await broadcast_event(event)
                        except Exception as e:  # pragma: no cover — defensive
                            log.debug("ws_broadcast_failed", error=str(e))
                    await _enrich_and_writeback()
                    # Correlation seam (Agent A owns correlation.py; this call
                    # is the integration point). Runs across all rules and
                    # persists matches as alerts — under the F-10 gate.
                    if hosts_in_batch:
                        await _run_correlation_coalesced()
                except Exception as e:  # pragma: no cover — defensive
                    log.warning("ingest_post_processing_failed", error=str(e))

            task = asyncio.create_task(_post_process())
            _post_process_tasks.add(task)
            task.add_done_callback(_post_process_tasks.discard)  # F-17
        except Exception as e:
            # Best-effort — if we can't even schedule the task, log it
            # and return success to the agent (events are already written).
            get_logger("api.ingest").warning("enrichment_schedule_failed", error=str(e))

    return IngestResponse(
        accepted=count,
        message=f"Accepted {count} events"
        + (
            f", refused {rejected_quarantine} from quarantined host(s)"
            if rejected_quarantine
            else ""
        ),
        rejected_quarantine=rejected_quarantine,
    )


# ───────────────────────────────────────────────────────────────
# V0.5b "Fleet & Scale" — raw osquery fleet ingest
#
# Remote fleet shippers tail their host's osquery results log and POST the
# RAW differential lines here. Parsing stays server-side through the SAME
# parse_osquery_line the local FileShipper uses — the ECS mapping and the
# closed event vocabulary live in exactly ONE place, and fleet shippers
# stay dumb (tail, batch, checkpoint, POST). Auth: get_ingest_client —
# admin JWT, the scoped ingest token, or a V0.5a fleet token. Fleet tokens
# are HOST-BOUND exactly like POST /ingest: a line whose hostIdentifier is
# not the token's enrolled host refuses the WHOLE batch (fail-closed,
# audited).
#
# Detection parity with the local shipper path: parsed events go through
# the same LogWriter batch and trigger the same coalesced correlation run.
# No enrichment writeback (identical to the local shipper contract).
# ───────────────────────────────────────────────────────────────


class OsqueryIngestRequest(BaseModel):
    """Raw osquery differential result lines, one JSON object per line."""

    lines: list[str] = Field(max_length=2000)


class OsqueryIngestResponse(BaseModel):
    accepted: int
    rejected_parse: int
    rejected_quarantine: int
    message: str


@router.post(
    "/ingest/osquery",
    response_model=OsqueryIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit(LIMIT_INGEST)
async def ingest_osquery_lines(
    request: Request,
    response: Response,
    payload: OsqueryIngestRequest,
    _token: Annotated[dict, Depends(get_ingest_client)],
):
    """Ingest RAW osquery result-log lines from a fleet shipper.

    Server-side parsing keeps one ECS-mapping truth. Quarantine enforcement
    is fail-closed per batch (lookup outage refuses everything). Fleet
    host binding: every parsed line's hostIdentifier must match the
    token's enrolled host.
    """
    from src.ingestion.durable import DurableIngestUnavailable, persist_event
    from src.ingestion.parser import parse_osquery_line

    if not payload.lines:
        return OsqueryIngestResponse(
            accepted=0, rejected_parse=0, rejected_quarantine=0, message="no lines"
        )

    # Parse first — binding checks the PARSED host identity (never trust a
    # self-declared field the parser didn't validate).
    parsed: list[NormalizedEvent] = []
    rejected_parse = 0
    for line in payload.lines:
        event = parse_osquery_line(line)
        if event is None:
            rejected_parse += 1
        else:
            parsed.append(event)

    # V0.5a host binding (same contract as POST /ingest), fail-closed.
    fleet_host: str | None = None
    if isinstance(_token, dict) and _token.get("kind") == "fleet":
        fleet_host = _token.get("fleet_host")
        rogue = sorted({e.host_name for e in parsed if e.host_name != fleet_host})
        if rogue:
            try:
                await log_audit_action(
                    actor=_token.get("username") or "fleet:unknown",
                    action="fleet.host_spoof_refused",
                    target_type="fleet_enrollment",
                    new_values={
                        "fleet_host": fleet_host,
                        "claimed_hosts": rogue,
                        "endpoint": "/ingest/osquery",
                    },
                )
            except Exception as e:  # audit outage must not block the refusal
                log.warning("fleet_spoof_audit_write_failed", error=str(e))
            log.warning(
                "ingest_osquery_host_binding_violation",
                fleet_host=fleet_host,
                claimed_hosts=rogue,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"fleet token may only ingest events for host '{fleet_host}'",
            )

    # Quarantine enforcement, fail-closed on lookup outage (same contract
    # as POST /ingest: a DB outage here must NOT silently accept telemetry).
    quarantined_hosts: set[str] = set()
    try:
        pool_q = await get_pool()
        async with pool_q.acquire() as conn_q:
            quarantined_hosts = {
                r["host_name"]
                for r in await conn_q.fetch("SELECT host_name FROM quarantined_hosts")
            }
    except Exception as e:  # pragma: no cover - defensive
        log.warning("quarantine_lookup_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="quarantine enforcement unavailable; batch refused",
        ) from e

    # W2.2 durable mode: fail-closed BEFORE any event is taken (same shape
    # as the quarantine 503 — a DB/Redis outage must NOT silently accept).
    from src.ingestion.durable import durable_mode, durable_redis_probe

    if durable_mode() and not await durable_redis_probe():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="durable ingest buffer unavailable; batch refused",
        )

    accepted = 0
    rejected_quarantine = 0
    for event in parsed:
        if event.host_name and event.host_name in quarantined_hosts:
            rejected_quarantine += 1
            log.warning(
                "ingest_osquery_event_refused_quarantined_host",
                host_name=event.host_name,
                source=event.source,
            )
            continue
        try:
            await persist_event(event)
        except DurableIngestUnavailable as e:
            log.error(
                "ingest_osquery_durable_enqueue_failed",
                accepted=accepted,
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"durable ingest buffer unavailable — {accepted} events durably "
                    "queued, remainder refused (fail-closed)"
                ),
            ) from e
        accepted += 1

    if accepted:
        # Same detection footing as the local shipper / POST /ingest.
        task = asyncio.create_task(_trigger_correlation_coalesced())
        _post_process_tasks.add(task)
        task.add_done_callback(_post_process_tasks.discard)

    return OsqueryIngestResponse(
        accepted=accepted,
        rejected_parse=rejected_parse,
        rejected_quarantine=rejected_quarantine,
        message=(
            f"Accepted {accepted} osquery events"
            + (f", {rejected_parse} unparseable" if rejected_parse else "")
            + (
                f", refused {rejected_quarantine} from quarantined host(s)"
                if rejected_quarantine
                else ""
            )
        ),
    )
