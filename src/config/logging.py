"""
Structured logging setup using structlog.
Every log line is JSON with: timestamp, level, component, message, and context.
This lets you grep/jq your own SIEM's logs when something breaks.
"""
import logging
import sys

import structlog

from src.config.settings import settings


def setup_logging() -> None:
    """Call once at startup (main.py, shipper.py, etc.)."""

    # Choose renderer based on environment
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(component: str) -> structlog.BoundLogger:
    """Get a logger bound to a specific component name.
    
    Usage:
        log = get_logger("shipper")
        log.info("started tailing", path="/var/log/osquery/results.log")
        log.error("parse failed", raw_line=line, error=str(e))
    """
    return structlog.get_logger(component=component)
