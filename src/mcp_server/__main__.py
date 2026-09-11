"""Entry point: python -m src.mcp_server

Runs the MCP server (uvicorn) on settings.mcp_port. The compose service
sets DB_USER/DB_PASSWORD to the SCOPED READ-ONLY role before this runs;
the app refuses tool calls unless the boot-time scope check passes.
"""

from __future__ import annotations

import uvicorn

from src.config.settings import settings

if __name__ == "__main__":
    uvicorn.run(
        "src.mcp_server.app:app",
        # Bind inside the container is 0.0.0.0 by design: the publish side is
        # loopback-only in the prod overlay (127.0.0.1:8002). Same posture as
        # the API service.
        host="0.0.0.0",  # noqa: S104 -- container-internal bind; publish is loopback
        port=settings.mcp_port,
        log_config=None,  # structlog owns logging config
    )
