"""
Log ingestion endpoint — receives events via HTTP POST.

Security:
- Authenticated with bearer token
- Input validated with Pydantic (rejects malformed events)
- Field length limits prevent memory exhaustion attacks
- No raw SQL — everything goes through the writer
- Rate limited (Epic 4) to LIMIT_INGEST per IP
"""
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from src.api.auth import get_current_user
from src.api.rate_limit import LIMIT_INGEST, limiter
from src.config.logging import get_logger
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["ingestion"])
log = get_logger("api.ingest")


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
    process_pid: int | None = Field(None)
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
    for event_data in events:
        event = NormalizedEvent(
            **event_data.model_dump(by_alias=True),
            enrichment={},
        )
        await writer.write(event)
        if event.host_name:
            hosts_in_batch.add(event.host_name)
        count += 1

    # Epic 9: fire-and-forget enrichment + correlation per batch.
    # We do NOT await these — the HTTP request has already returned 202 to
    # the agent. If enrichment is slow, ingestion must not be slow. If
    # enrichment raises, the request is already on the wire, so we just
    # log and move on.
    if count > 0:
        try:
            import asyncio

            from src.detection.correlation import run_all_correlations
            from src.enrichment.pipeline import enrich_event_dict

            async def _enrich_and_correlate():
                try:
                    # Enrichment pipeline (GeoIP, DNS, threat intel) for
                    # public IPs in the batch. Writes back into the
                    # logs.enrichment JSONB column.
                    for event_data in events:
                        try:
                            enrichment = await enrich_event_dict(
                                event_data.model_dump(by_alias=True)
                            )
                            if enrichment:
                                log.debug(
                                    "ingest_enrichment_done",
                                    host=event_data.host_name,
                                    keys=list(enrichment.keys()),
                                )
                        except Exception as e:  # pragma: no cover — defensive
                            log.warning(
                                "ingest_enrichment_failed",
                                host=getattr(event_data, "host_name", None),
                                error=str(e),
                            )

                    # Correlation seam (Agent A owns correlation.py; this
                    # call is the integration point). Runs across all rules
                    # and persists any matches as alerts.
                    if hosts_in_batch:
                        await run_all_correlations(persist=True)
                except Exception as e:  # pragma: no cover — defensive
                    log.warning("ingest_post_processing_failed", error=str(e))

            asyncio.create_task(_enrich_and_correlate())
        except Exception as e:
            # Best-effort — if we can't even schedule the task, log it
            # and return success to the agent (events are already written).
            from src.config.logging import get_logger
            get_logger("api.ingest").warning(
                "enrichment_schedule_failed", error=str(e)
            )

    return IngestResponse(accepted=count, message=f"Accepted {count} events")
