"""
NL→SQL Query API endpoint.

POST /api/v1/query — Convert natural language to SQL and execute
GET  /api/v1/query/templates — List available query templates
"""
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.auth import require_role
from src.ai.nl2sql import (
    get_available_templates,
    nl_query,
    nl_to_sql,
)
from src.config.logging import get_logger

log = get_logger("api.query")

router = APIRouter(tags=["query"])


class NLQueryRequest(BaseModel):
    """Natural language query request."""

    question: str = Field(
        ..., min_length=1, max_length=500,
        description="Plain English security question",
    )
    session_id: Optional[str] = Field(
        None,
        description="Conversation session ID for follow-up queries",
    )
    execute: bool = Field(
        True,
        description="Whether to execute the generated SQL (false = dry run)",
    )


class NLQueryResponse(BaseModel):
    """Response for NL→SQL query."""

    success: bool
    sql: Optional[str] = None
    results: Optional[list] = None
    row_count: Optional[int] = None
    truncated: Optional[bool] = None
    template_used: Optional[bool] = None
    estimated_rows: Optional[int] = None
    session_id: Optional[str] = None
    elapsed_ms: Optional[int] = None
    execution_ms: Optional[int] = None
    error: Optional[str] = None
    warnings: Optional[list] = None


class TemplateResponse(BaseModel):
    """Query template metadata."""

    id: str
    description: str
    keywords: list[str]


@router.post(
    "/query",
    response_model=NLQueryResponse,
    summary="Natural Language → SQL Query",
    description=(
        "Ask a security question in plain English. "
        "The system converts it to safe SQL and returns results."
    ),
)
async def query_nl(
    request: NLQueryRequest,
    _user: dict = Depends(require_role("analyst")),
):
    """Convert natural language question to SQL and execute."""
    log.info(
        "nl_query_request",
        question=request.question[:50],
        session_id=request.session_id,
    )

    if request.execute:
        result = await nl_query(request.question, request.session_id)
    else:
        # Dry run — generate SQL but don't execute
        result = await nl_to_sql(request.question, request.session_id)

    return NLQueryResponse(
        **{k: v for k, v in result.items() if k in NLQueryResponse.model_fields}
    )


@router.get(
    "/query/templates",
    response_model=list[TemplateResponse],
    summary="Available Query Templates",
    description="List pre-built query templates for common security questions.",
)
async def list_templates(
    _user: dict = Depends(require_role("viewer")),
):
    """List available query templates."""
    return get_available_templates()
