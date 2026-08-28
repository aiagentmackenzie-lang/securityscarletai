"""
AI Chat API endpoint.

POST /api/v1/ai/chat — Context-aware security chat
"""
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from src.ai.chat import chat
from src.api.auth import require_role
from src.api.rate_limit import LIMIT_LLM, limiter, user_or_ip_key
from src.config.logging import get_logger

log = get_logger("api.chat")

router = APIRouter(tags=["ai"])


class ChatRequest(BaseModel):
    """Chat message request."""
    message: str = Field(
        ..., min_length=1, max_length=1000,
        description="Security question or command",
    )
    session_id: str | None = Field(
        None,
        description="Session ID for request correlation (multi-turn memory not yet implemented)",
    )


class ChatResponse(BaseModel):
    """Chat response."""
    response: str
    context_used: bool
    warnings: list[str] | None = None
    ai_generated: bool = False


@router.post(
    "/ai/chat",
    response_model=ChatResponse,
    summary="Security Chat",
    description=(
        "Ask a security question in natural language. "
        "The system provides context-aware responses based on "
        "current alerts and threat data. Per-user LLM quota applies."
    ),
)
@limiter.limit(LIMIT_LLM, key_func=user_or_ip_key)
async def chat_endpoint(
    request: Request,  # slowapi requires this exact name
    response: Response,  # slowapi injects X-RateLimit-* headers here
    chat_request: ChatRequest,
    _user: dict = Depends(require_role("analyst")),
):
    """Process a security chat message."""
    log.info(
        "chat_request",
        message=chat_request.message[:50],
        user=_user.get("sub"),
        session_id=chat_request.session_id,
    )

    # P2-26: forward the authenticated analyst so cost tracking attributes the
    # call to a real user (was user=None -> "system"), and thread session_id
    # through as a correlation key.
    result = await chat(
        chat_request.message,
        session_id=chat_request.session_id,
        user=_user.get("sub"),
    )

    return ChatResponse(
        response=result["response"],
        context_used=result["context_used"],
        warnings=result.get("warnings"),
        ai_generated=result.get("ai_generated", False),
    )
