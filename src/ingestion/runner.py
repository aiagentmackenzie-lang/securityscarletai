"""Lifespan helper — starts the osquery FileShipper when enabled.

Keeps the startup/shutdown wiring in ``src.api.main`` thin and makes the
enable/disable gate unit-testable without spinning up the whole FastAPI
lifespan (which needs a Postgres pool).
"""
from __future__ import annotations

from pathlib import Path

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.writer import LogWriter
from src.ingestion.shipper import FileShipper

log = get_logger("ingestion.runner")


def maybe_create_shipper(writer: LogWriter) -> FileShipper | None:
    """Return a FileShipper iff the telemetry pipe is enabled, else None.

    Disabled is the default — the SIEM keeps working on POSTed/synthetic
    events. Enable via ``ENABLE_INGESTION_SHIPPER=true`` to tail
    ``settings.osquery_log_path`` and feed detection live.

    The checkpoint is stored at ``settings.shipper_checkpoint_path`` (a
    persistent, writable path — the mounted ``data/`` volume in Docker), NOT at
    ``Path.home()``: in the API container HOME does not exist and is ephemeral,
    so a home-dir checkpoint never saved and restarts re-ingested the whole log
    (duplicate events). Found live, 2026-09-04.
    """
    if not settings.enable_ingestion_shipper:
        log.info("shipper_disabled")
        return None
    shipper = FileShipper(
        settings.osquery_log_path,
        writer,
        checkpoint_path=Path(settings.shipper_checkpoint_path),
    )
    log.info("shipper_enabled", path=settings.osquery_log_path)
    return shipper
