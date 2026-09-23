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
        # Bind inside the container is 0.0.0.0 by design: what reaches the
        # network is decided by the publish side of the compose overlay.
        # W5-C postures: the internet-prod overlay publishes NOTHING for mcp
        # (ports: !reset [] — Caddy owns the only published ports); the
        # local-prod overlay publishes 127.0.0.1:8002. uvicorn's own
        # forwarded-allow default (127.0.0.1) also means container peers are
        # NOT trusted proxies — no X-Forwarded-For spoofing from the network.
        host="0.0.0.0",  # noqa: S104 -- container-internal bind; publish side is overlay-controlled
        port=settings.mcp_port,
        log_config=None,  # structlog owns logging config
    )
