"""
FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.config.logging import setup_logging, get_logger
from src.db.connection import get_pool, close_pool
from src.db.writer import LogWriter
from src.api.ingest import router as ingest_router
from src.api.health import router as health_router
from src.api.rules import router as rules_router
from src.api.alerts import router as alerts_router
from src.api.websocket import router as websocket_router

log = get_logger("api")

# Shared writer instance
writer = LogWriter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    setup_logging()
    log.info("starting_api", host=settings.api_host, port=settings.api_port)
    await get_pool()
    await writer.start()
    yield
    await writer.stop()
    await close_pool()
    log.info("api_shutdown_complete")


app = FastAPI(
    title="SecurityScarletAI",
    description="AI-Native SIEM — Log Ingestion & Detection API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(ingest_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/api/v1")
