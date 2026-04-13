"""
FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from pathlib import Path
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

RULES_DIR = Path("/Users/main/Security Apps/SecurityScarletAI/rules/sigma")


async def load_sigma_rules():
    """Load Sigma YAML rules from disk into the database if not already present."""
    import yaml
    pool = await get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchval("SELECT COUNT(*) FROM rules")
        if existing > 0:
            log.info("rules_already_loaded", count=existing)
            return

        loaded = 0
        for rule_file in sorted(RULES_DIR.glob("*.yml")):
            try:
                yaml_content = rule_file.read_text()
                data = yaml.safe_load(yaml_content)
                
                # Extract MITRE tags
                tags = data.get("tags", [])
                mitre_tactics = [t.replace("attack.", "") for t in tags if t.startswith("attack.t") and len(t) == 8]
                mitre_techniques = [t.replace("attack.", "") for t in tags if t.startswith("attack.t") and len(t) > 8]
                
                from datetime import timedelta
                
                await conn.execute(
                    """
                    INSERT INTO rules (
                        name, description, sigma_yaml, severity, enabled,
                        run_interval, lookback, threshold, mitre_tactics, mitre_techniques
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (name) DO NOTHING
                    """,
                    data.get("title", rule_file.stem),
                    data.get("description", ""),
                    yaml_content,
                    data.get("level", "medium"),
                    True,
                    timedelta(seconds=60),
                    timedelta(minutes=5),
                    1,
                    mitre_tactics,
                    mitre_techniques,
                )
                loaded += 1
            except Exception as e:
                log.error("rule_load_failed", file=str(rule_file), error=str(e))

        log.info("rules_loaded", count=loaded)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    setup_logging()
    log.info("starting_api", host=settings.api_host, port=settings.api_port)
    await get_pool()
    await writer.start()
    
    # Load Sigma rules from disk
    await load_sigma_rules()
    
    # Start detection scheduler
    from src.detection.scheduler import schedule_rules
    await schedule_rules()
    
    yield
    
    # Stop scheduler
    from src.detection.scheduler import stop_scheduler
    await stop_scheduler()
    
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