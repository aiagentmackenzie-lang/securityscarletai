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

from src.api.auth import get_current_user
from src.api.rate_limit import LIMIT_INGEST, limiter
from src.config.logging import get_logger
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["ingestion"])
log = get_logger("api.ingest")

# F-10 (plan phase 5): bounds for the background post-processing work.
# run_all_correlations hits the DB with 7 heavy window/JOIN queries per
# batch, fire-and-forget, with NO cap: an ingest burst collapses the pool.
# - Semaphore: at most CORRELATION_MAX_CONCURRENT runs at once.
# - Coalescing: while a run is in flight, new batches skip their own run —
#   every run scans the whole lookback anyway, so queued duplicates only
#   pile up queries and rows.
# F-17: module-level references keep the fire-and-forget tasks GC-alive
# (an unreferenced task can be garbage-collected mid-flight by CPython).
CORRELATION_MAX_CONCURRENT = 2
_correlation_semaphore = asyncio.Semaphore(CORRELATION_MAX_CONCURRENT)
_correlation_inflight = False
_correlation_inflight_lock = asyncio.Lock()
_post_process_tasks: set["asyncio.Task[None]"] = set()


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

    @field_validator("host_name")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        """Prevent log injection via hostname field."""
        # Strip control characters and newlines
        return "".join(c for c in v if c.isprintable() and c not in "\n\r\t")


class IngestResponse(BaseModel):
    accepted: int
    message: str


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(LIMIT_INGEST)
async def ingest_events(
    request: Request,  # slowapi needs Request to derive the rate-limit key
    response: Response,  # slowapi injects X-RateLimit-* headers here
    events: list[IngestEvent],
    _token: Annotated[dict, Depends(get_current_user)],
):
    """Ingest one or more security events.

    Requires: Bearer token in Authorization header.
    Rate limited to LIMIT_INGEST (100/minute by IP).
    """
    if len(events) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Maximum 1000 events per batch",
        )

    # Import here to avoid circular dependency
    from src.services.writer import writer

    count = 0
    hosts_in_batch: set[str] = set()
    batch_events: list[NormalizedEvent] = []  # P2.4: broadcast happens in the background
    for event_data in events:
        event = NormalizedEvent(
            **event_data.model_dump(by_alias=True),
            enrichment={},
        )
        await writer.write(event)
        if event.host_name:
            hosts_in_batch.add(event.host_name)
        # P2.4: broadcast MOVED OUT of the ingest hot path — it now runs in
        # the per-batch _post_process task below. WS delivery is presentation,
        # not ingestion: awaiting a send loop per event (with no send timeout)
        # let one slow dashboard socket stall the ingest request.
        batch_events.append(event)
        count += 1

    # Epic 9: fire-and-forget enrichment + correlation per batch.
    # We do NOT await these — the HTTP request has already returned 202 to
    # the agent. If enrichment is slow, ingestion must not be slow. If
    # enrichment raises, the request is already on the wire, so we just
    # log and move on.
    if count > 0:
        try:
            from src.enrichment.pipeline import enrich_event_dict

            async def _enrich_and_writeback():
                """Enrich the batch and write back, keyed on the natural key
                plus BOTH endpoint ips (F-18: the tuple-only UPDATE could land
                one event's enrichment on a later, different-IP event sharing
                the same natural key. The inputs to enrichment ARE the ips —
                keying on them leaves an overlap only between fully-identical
                events, which share enrichment legitimately)."""
                try:
                    # Persist the just-written batch so the enrichment
                    # write-back below can find the rows. The writer is batched
                    # (flush every ~2s); force a flush now (P1-07).
                    await writer.flush()

                    import json as _json

                    from src.db.connection import get_pool

                    pool = await get_pool()
                    # Enrichment pipeline (GeoIP, DNS, threat intel) for public
                    # IPs in the batch. Writes into logs.enrichment. Best-effort:
                    # a failure here never affects ingestion — the events are
                    # already persisted and the HTTP 202 is on the wire.
                    async with pool.acquire() as conn:
                        for event_data in events:
                            try:
                                enrichment = await enrich_event_dict(
                                    event_data.model_dump(by_alias=True)
                                )
                                if enrichment:
                                    await conn.execute(
                                        """UPDATE logs SET enrichment = $1::jsonb
                                           WHERE time = $2 AND host_name = $3
                                             AND source = $4 AND event_category = $5
                                             AND event_type = $6
                                             AND source_ip::text
                                               = COALESCE($7::text, source_ip::text)
                                             AND destination_ip::text
                                               = COALESCE($8::text,
                                                          destination_ip::text)""",
                                        _json.dumps(enrichment),
                                        event_data.timestamp,
                                        event_data.host_name,
                                        event_data.source,
                                        event_data.event_category,
                                        event_data.event_type,
                                        event_data.source_ip,
                                        event_data.destination_ip,
                                    )
                                    log.debug(
                                        "ingest_enrichment_persisted",
                                        host=event_data.host_name,
                                        keys=list(enrichment.keys()),
                                    )
                            except Exception as e:  # pragma: no cover — defensive
                                log.warning(
                                    "ingest_enrichment_failed",
                                    host=getattr(event_data, "host_name", None),
                                    error=str(e),
                                )
                except Exception as e:  # pragma: no cover — defensive
                    log.warning("ingest_enrichment_loop_failed", error=str(e))

            async def _run_correlation_coalesced():
                """F-10: cap concurrency AND coalesce — while one run is in
                flight, new batches skip (each run covers the full lookback)."""
                from src.detection.correlation import run_all_correlations

                global _correlation_inflight
                async with _correlation_semaphore:
                    if _correlation_inflight:
                        log.debug("correlation_run_coalesced_skip")
                        return
                    async with _correlation_inflight_lock:
                        if _correlation_inflight:
                            return
                        _correlation_inflight = True
                        try:
                            await run_all_correlations(persist=True)
                        finally:
                            _correlation_inflight = False

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
            get_logger("api.ingest").warning(
                "enrichment_schedule_failed", error=str(e)
            )

    return IngestResponse(accepted=count, message=f"Accepted {count} events")
