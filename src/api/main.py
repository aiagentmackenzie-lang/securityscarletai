"""
FastAPI application entry point.
"""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from src.api.ai import router as ai_router
from src.api.alerts import router as alerts_router
from src.api.audit import router as audit_router
from src.api.auth_login import router as auth_login_router
from src.api.cases import router as cases_router
from src.api.chat import router as chat_router
from src.api.correlation import router as correlation_router
from src.api.health import router as health_router
from src.api.hunt import router as hunt_router
from src.api.ingest import router as ingest_router
from src.api.logs import router as logs_router
from src.api.metrics import MetricsMiddleware
from src.api.metrics import router as metrics_router
from src.api.middleware import AuditLogMiddleware, RequestValidationMiddleware
from src.api.query import router as query_router
from src.api.rate_limit import (
    RateLimitHeadersMiddleware,
    limiter,
    rate_limit_exceeded_handler,
)
from src.api.rules import router as rules_router
from src.api.threat_intel import router as threat_intel_router
from src.api.users import router as users_router
from src.api.websocket import router as websocket_router
from src.config.logging import get_logger, setup_logging
from src.config.settings import settings
from src.db.connection import close_pool, get_pool
from src.services.writer import writer

log = get_logger("api")

# Shared writer instance

RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "sigma"


def _docs_urls() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (docs_url, redoc_url, openapi_url) gated by settings.docs_enabled.

    When docs are disabled (prod), all three are None so FastAPI serves no
    Swagger UI, no ReDoc, and no openapi.json schema. Extracted to a helper so
    the gating is unit-testable without rebuilding the module-level app.
    """
    if settings.docs_enabled:
        return ("/api/docs", "/api/redoc", "/openapi.json")
    return (None, None, None)


async def load_sigma_rules():
    """Reconcile Sigma YAML rules on disk into the rules table (P1-05).

    Runs on every boot. Upserts by name: new disk rules are inserted (enabled);
    existing rules have their content fields refreshed (sigma_yaml, description,
    severity, mitre_*, run_interval, lookback, threshold) while operator-set
    state (enabled, last_run, last_match, match_count) is preserved. DB rows not
    present on disk are left untouched — they may be operator-created via the
    rules API and cannot be distinguished from disk rules that were removed.
    """
    from datetime import timedelta

    import yaml

    from src.detection.sigma import _extract_mitre_tags

    # alert_severity enum values; clamp unknown Sigma levels to 'medium'.
    _VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    pool = await get_pool()
    async with pool.acquire() as conn:
        disk_names: set[str] = set()
        inserted = 0
        updated = 0
        for rule_file in sorted(RULES_DIR.rglob("*.yml")):
            try:
                yaml_content = rule_file.read_text()
                data = yaml.safe_load(yaml_content)

                name = data.get("title", rule_file.stem)
                disk_names.add(name)

                tags = data.get("tags", [])
                mitre_tactics, mitre_techniques = _extract_mitre_tags(tags)

                level = str(data.get("level", "medium")).lower()
                if level not in _VALID_SEVERITIES:
                    level = "medium"

                result = await conn.execute(
                    """
                    INSERT INTO rules (
                        name, description, sigma_yaml, severity, enabled,
                        run_interval, lookback, threshold, mitre_tactics, mitre_techniques
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (name) DO UPDATE SET
                        description      = EXCLUDED.description,
                        sigma_yaml       = EXCLUDED.sigma_yaml,
                        severity         = EXCLUDED.severity,
                        run_interval     = EXCLUDED.run_interval,
                        lookback         = EXCLUDED.lookback,
                        threshold        = EXCLUDED.threshold,
                        mitre_tactics    = EXCLUDED.mitre_tactics,
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        updated_at       = NOW()
                    """,
                    name,
                    data.get("description", ""),
                    yaml_content,
                    level,
                    True,
                    timedelta(seconds=60),
                    timedelta(minutes=5),
                    1,
                    mitre_tactics,
                    mitre_techniques,
                )
                # asyncpg command tag: 'INSERT 0 1' vs 'UPDATE 1'.
                if result.startswith("UPDATE"):
                    updated += 1
                else:
                    inserted += 1
            except Exception as e:
                log.error("rule_load_failed", file=str(rule_file), error=str(e))

        db_names = {r["name"] for r in await conn.fetch("SELECT name FROM rules")}
        orphaned = db_names - disk_names
        log.info(
            "rules_reconciled",
            inserted=inserted,
            updated=updated,
            on_disk=len(disk_names),
            in_db=len(db_names),
            db_only=len(orphaned),
        )
        if orphaned:
            log.warning(
                "rules_in_db_not_on_disk",
                count=len(orphaned),
                names=sorted(orphaned)[:10],
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    setup_logging()
    log.info("starting_api", host=settings.api_host, port=settings.api_port)
    await get_pool()
    await writer.start()

    # Load Sigma rules from disk
    await load_sigma_rules()

    # Start ingestion shipper (osquery tail) if enabled. OFF by default.
    from src.ingestion.runner import maybe_create_shipper

    shipper = maybe_create_shipper(writer)
    shipper_task: Optional[asyncio.Task] = None
    if shipper is not None:
        shipper_task = asyncio.create_task(shipper.run())

    # Start detection scheduler
    from src.detection.scheduler import schedule_rules
    await schedule_rules()

    # Start threat intel refresh scheduler
    from src.intel.threat_intel import start_threat_intel_scheduler
    await start_threat_intel_scheduler()

    # P1-D: start the data-retention scheduler (bounded storage). Hourly by
    # default; deletes rows older than env-configured windows in batched
    # parameterized DELETEs. 0 retention = keep forever.
    from src.services.retention import start_retention_scheduler
    await start_retention_scheduler()

    # P2-16: warn (don't block) if the configured Ollama model isn't available.
    # /health caches the probe (P2-34); this is a one-time startup notice so a
    # misconfigured model is surfaced to the operator instead of silently
    # falling back to templates.
    from src.ai.ollama_client import validate_ollama_model
    try:
        _ok, _model, err = await validate_ollama_model()
        if not _ok and err:
            log.warning("ollama_model_unavailable_at_startup", error=err)
    except Exception as e:
        log.warning("ollama_startup_check_failed", error=str(e))

    yield

    # Stop scheduler
    from src.detection.scheduler import stop_scheduler
    await stop_scheduler()

    # Stop the ingestion shipper if it was started
    if shipper is not None:
        shipper.stop()
    if shipper_task is not None:
        shipper_task.cancel()
        try:
            await shipper_task
        except asyncio.CancelledError:
            pass

    # Stop threat intel scheduler
    from src.intel.threat_intel import stop_threat_intel_scheduler
    await stop_threat_intel_scheduler()

    # P1-D: stop the retention scheduler.
    from src.services.retention import stop_retention_scheduler
    await stop_retention_scheduler()

    # P2-12: close the MaxMind GeoIP reader handle on shutdown.
    from src.enrichment.pipeline import close_geoip_reader
    close_geoip_reader()

    await writer.stop()
    await close_pool()
    log.info("api_shutdown_complete")


_docs_url, _redoc_url, _openapi_url = _docs_urls()

app = FastAPI(
    title="SecurityScarletAI",
    description="AI-Native SIEM — Log Ingestion & Detection API",
    version="0.2.0",  # matches the git tag (was stale 0.1.0 — caught by read-through, not grep)
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    # Restrict request headers to the two the API actually uses. Bearer
    # tokens (not cookies) so CSRF is moot, but tighten anyway — never
    # advertise "any header" in a security product.
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(ingest_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(correlation_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(chat_router, prefix="/api/v1")
app.include_router(hunt_router, prefix="/api/v1")
app.include_router(auth_login_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(query_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(metrics_router, prefix="/api/v1")

# Add middleware for request validation and audit logging
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(AuditLogMiddleware)

# Rate limiting state — Redis-backed via src.api.rate_limit
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)  # type: ignore[arg-type]  # slowapi handler sig vs Starlette
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RateLimitHeadersMiddleware)

# P3.3: HTTP request count + latency metrics. Added LAST so it is the
# outermost middleware — rate-limit 429s and validation 4xx are counted too.
app.add_middleware(MetricsMiddleware)
