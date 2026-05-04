"""
AI Chat API endpoint.

POST /api/v1/ai/chat — Context-aware security chat
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.auth import require_role
from src.ai.chat import chat
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
        None, description="Session ID for conversation continuity",
    )


class ChatResponse(BaseModel):
    """Chat response."""
    response: str
    context_used: bool
    warnings: list[str] | None = None


@router.post(
    "/ai/chat",
    response_model=ChatResponse,
    summary="Security Chat",
    description=(
        "Ask a security question in natural language. "
        "The system provides context-aware responses based on "
        "current alerts and threat data."
    ),
)
async def chat_endpoint(
    request: ChatRequest,
    _user: dict = Depends(require_role("analyst")),
):
    """Process a security chat message."""
    log.info(
        "chat_request",
        message=request.message[:50],
        user=_user.get("sub"),
    )

    result = await chat(request.message, request.session_id)

    return ChatResponse(
        response=result["response"],
        context_used=result["context_used"],
        warnings=result.get("warnings"),
    )
