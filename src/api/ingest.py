"""
Log ingestion endpoint — receives events via HTTP POST.

Security:
- Authenticated with bearer token
- Input validated with Pydantic (rejects malformed events)
- Field length limits prevent memory exhaustion attacks
- No raw SQL — everything goes through the writer
"""
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

from src.api.auth import verify_bearer_token
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["ingestion"])


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
async def ingest_events(
    events: list[IngestEvent],
    _token: Annotated[str, Depends(verify_bearer_token)],
):
    """Ingest one or more security events.
    
    Requires: Bearer token in Authorization header.
    """
    if len(events) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Maximum 1000 events per batch",
        )

    # Import here to avoid circular dependency
    from src.api.main import writer

    count = 0
    for event_data in events:
        event = NormalizedEvent(
            **event_data.model_dump(by_alias=True),
            enrichment={},
        )
        await writer.write(event)
        count += 1

    return IngestResponse(accepted=count, message=f"Accepted {count} events")
