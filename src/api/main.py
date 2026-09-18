"""
FastAPI application entry point.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from src.api.agents import router as agents_router
from src.api.ai import router as ai_router
from src.api.alerts import router as alerts_router
from src.api.audit import router as audit_router
from src.api.auth_login import router as auth_login_router
from src.api.cases import router as cases_router
from src.api.chat import router as chat_router
from src.api.compliance import router as compliance_router
from src.api.correlation import router as correlation_router
from src.api.decisions import router as decisions_router
from src.api.detection import router as detection_router
from src.api.fleet import router as fleet_router
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
from src.api.response import router as response_router
from src.api.rules import router as rules_router
from src.api.ssf import router as ssf_router
from src.api.threat_intel import router as threat_intel_router
from src.api.users import router as users_router
from src.api.websocket import router as websocket_router
from src.config.logging import get_logger, setup_logging
from src.config.settings import settings
from src.config.version import APP_VERSION
from src.db.connection import close_pool, get_pool
from src.services.writer import writer

log = get_logger("api")

# W1.8 scheduled-report config path (boot-time verification).
SCHEDULES_YAML = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "scheduled_reports.yaml"
)

# Shared writer instance

RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "sigma"
# W2.2: the durable-ingest config default (DURABLE_INGEST_CONFIG env overrides).
DURABLE_INGEST_CONFIG = Path(__file__).parent.parent.parent / "config" / "durable_ingest.yaml"


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

    Runs on every boot. Upserts by name: new disk rules are inserted (enabled
    unless the rule's frontmatter carries `enabled: false` — the W2.1 import
    extension that keeps promoted SigmaHQ rules from arming before an
    operator arms them); CHANGED rules have their content fields refreshed
    (sigma_yaml, description, severity, mitre_*, run_interval, lookback,
    threshold) while operator-set state (enabled, last_run, last_match,
    match_count) is preserved. UNCHANGED rules (byte-identical sigma_yaml)
    are not written at all — the boot no longer rewrites every row (nor its
    updated_at) on every restart (AUD-012). DB rows not present on disk are
    left untouched -- they may be operator-created via the rules API and
    cannot be distinguished from disk rules that were removed.
    """
    from datetime import timedelta

    import yaml

    from src.detection.sigma import _extract_mitre_tags, _timeframe_to_seconds

    # alert_severity enum values; clamp unknown Sigma levels to 'medium'.
    _VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Pre-fetch name -> sigma_yaml. sigma_yaml is a sufficient proxy for
        # "content unchanged": every refreshed field (description, severity,
        # mitre_*, run_interval, lookback, threshold) is derived from the same
        # YAML text, so byte-identical YAML means byte-identical fields.
        pre: dict[str, str | None] = {
            r["name"]: r["sigma_yaml"]
            for r in await conn.fetch("SELECT name, sigma_yaml FROM rules")
        }
        disk_names: set[str] = set()
        batch: list[tuple] = []
        unchanged = 0
        for rule_file in sorted(RULES_DIR.rglob("*.yml")):
            try:
                yaml_content = rule_file.read_text()
                data = yaml.safe_load(yaml_content)

                name = data.get("title", rule_file.stem)
                disk_names.add(name)

                # AUD-012: skip byte-identical rules — no upsert, no
                # updated_at churn, no write amplification on every boot.
                if name in pre and pre[name] == yaml_content:
                    unchanged += 1
                    continue

                tags = data.get("tags", [])
                mitre_tactics, mitre_techniques = _extract_mitre_tags(tags)

                level = str(data.get("level", "medium")).lower()
                if level not in _VALID_SEVERITIES:
                    level = "medium"

                batch.append(
                    (
                        name,
                        data.get("description", ""),
                        yaml_content,
                        level,
                        # W2.1 import extension: a disk rule born `enabled: false`
                        # (promoted SigmaHQ imports) inserts DISABLED — arming is
                        # always an explicit operator decision. Shipped rules
                        # carry no `enabled` key and default to True (unchanged).
                        bool(data.get("enabled", True)),
                        timedelta(seconds=60),
                        # AUD-007: the DB lookback column is the rule's scan
                        # window and the run path now compiles from it — keep it
                        # in sync with the YAML timeframe instead of a hardcoded
                        # 5 minutes, so the override is a no-op for shipped rules
                        # (byte-identical) and honest for API rules.
                        timedelta(seconds=_timeframe_to_seconds(data.get("timeframe"))),
                        1,
                        mitre_tactics,
                        mitre_techniques,
                    )
                )
            except Exception as e:
                log.error("rule_load_failed", file=str(rule_file), error=str(e))

        # AUD-012: ONE pipeline round-trip for the whole batch (was one
        # sequential execute per rule, ~116 round-trips per boot). Per-row
        # fallback preserves the old robustness contract: one malformed row
        # costs its row, never the whole reconcile (the Wave-7
        # cache_iocs_bulk shape).
        if batch:
            try:
                await conn.executemany(
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
                    batch,
                )
            except Exception:
                log.warning("rules_reconcile_bulk_failed_falling_back_per_row", rows=len(batch))
                for params in batch:
                    try:
                        await conn.execute(
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
                            *params,
                        )
                    except Exception as e:
                        log.error("rule_load_failed", rule=params[0], error=str(e))

        db_names = {r["name"] for r in await conn.fetch("SELECT name FROM rules")}
        inserted = len({p[0] for p in batch} - pre.keys())
        updated = len(batch) - inserted
        orphaned = db_names - disk_names
        log.info(
            "rules_reconciled",
            inserted=inserted,
            updated=updated,
            unchanged=unchanged,
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

    # W2.2 durable ingest buffer — versioned config, OFF by default. Boot-time
    # verification (the W1.7 pattern): an INVALID config fails the boot
    # (fail-closed); the feature being off is the valid default. The consumer
    # survives Redis outages by design; the API path 503s (fail-closed) while
    # Redis is down — the SIEM never accepts at-most-once while promising
    # durability.
    durable_instance = None
    durable_consumer_task: Optional[asyncio.Task] = None
    durable_stop = asyncio.Event()
    try:
        from src.ingestion.durable import DurableIngest, load_durable_config

        durable_cfg = load_durable_config(
            Path(os.environ["DURABLE_INGEST_CONFIG"])
            if os.environ.get("DURABLE_INGEST_CONFIG")
            else DURABLE_INGEST_CONFIG
        )
        if durable_cfg.enabled:
            from src.api.redis_client import _get_client

            durable_instance = DurableIngest(durable_cfg, client_factory=_get_client)
            durable_consumer_task = asyncio.create_task(durable_instance.run(durable_stop))
            log.info(
                "durable_ingest_enabled",
                stream=durable_cfg.stream,
                group=durable_cfg.consumer_group,
                max_stream_length=durable_cfg.max_stream_length,
            )
    except Exception as e:
        log.error("durable_ingest_config_invalid", error=str(e))
        raise  # fail-closed: an invalid config never boots
    from src.ingestion.durable import configure_durable

    configure_durable(durable_instance)

    # Load Sigma rules from disk
    await load_sigma_rules()

    # Start ingestion shipper (osquery tail) if enabled. OFF by default.
    from src.ingestion.runner import (
        maybe_create_auth_shipper,
        maybe_create_deception_shipper,
        maybe_create_shipper,
    )

    shipper = maybe_create_shipper(writer)
    shipper_task: Optional[asyncio.Task] = None
    if shipper is not None:
        shipper_task = asyncio.create_task(shipper.run())

    # Start auth shipper (V0.3 identity telemetry) if enabled. OFF by default.
    auth_shipper = maybe_create_auth_shipper(writer)
    auth_shipper_task: Optional[asyncio.Task] = None
    if auth_shipper is not None:
        auth_shipper_task = asyncio.create_task(auth_shipper.run())

    # Start deception shipper (W1.5: HONEYTRAP/canary telemetry) if enabled.
    # OFF by default -- the deception rules report DORMANT-BY-SOURCE without
    # it (honest, not silent).
    deception_shipper = maybe_create_deception_shipper(writer)
    deception_shipper_task: Optional[asyncio.Task] = None
    if deception_shipper is not None:
        deception_shipper_task = asyncio.create_task(deception_shipper.run())

    # Start detection scheduler
    from src.detection.scheduler import schedule_rules

    await schedule_rules()

    # W1.7/W1.8: boot-time notification + report config verification (the
    # existing posture pattern): log per-channel status loudly at startup so
    # a misconfigured channel (missing env, bad type) is surfaced instead of
    # silently never delivering. Never blocks the boot.
    from src.response.notification_channels import load_effective_channels

    try:
        channels = await load_effective_channels()
        log.info(
            "notification_channels_loaded",
            channels=[
                {"name": c.name, "type": c.type, "severities": list(c.severities)} for c in channels
            ],
        )
    except Exception as e:
        log.warning("notification_channels_boot_check_failed", error=str(e))
    from src.response.scheduled_reports import load_schedules_file

    try:
        schedules = load_schedules_file(SCHEDULES_YAML)
        log.info(
            "scheduled_reports_loaded",
            schedules=[
                {"name": s.name, "report": s.report, "channels": list(s.channels)}
                for s in schedules
            ],
        )
    except Exception as e:
        log.warning("scheduled_reports_boot_check_failed", error=str(e))

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

    # Stop the ingestion shippers if they were started
    if shipper is not None:
        shipper.stop()
    if shipper_task is not None:
        shipper_task.cancel()
        try:
            await shipper_task
        except asyncio.CancelledError:
            pass
    if auth_shipper is not None:
        auth_shipper.stop()
    if auth_shipper_task is not None:
        auth_shipper_task.cancel()
        try:
            await auth_shipper_task
        except asyncio.CancelledError:
            pass
    if deception_shipper is not None:
        deception_shipper.stop()
    if deception_shipper_task is not None:
        deception_shipper_task.cancel()
        try:
            await deception_shipper_task
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

    # W2.2: stop the durable consumer (if it was started) BEFORE the writer —
    # AUD-019: the code had drifted (writer stopped first); the comment's
    # order is the correct drain: stop INGESTING first (in-flight claimed
    # messages stay PEL and are reclaimed by the next boot's consumer),
    # then flush the writer's remaining buffers with no competing writer.
    if durable_consumer_task is not None:
        durable_stop.set()
        try:
            await asyncio.wait_for(durable_consumer_task, timeout=10.0)
        except Exception as e:  # noqa: BLE001 — shutdown must complete
            durable_consumer_task.cancel()
            log.warning("durable_consumer_stop_forced", error=str(e))

    await writer.stop()
    await close_pool()
    log.info("api_shutdown_complete")


_docs_url, _redoc_url, _openapi_url = _docs_urls()

app = FastAPI(
    title="SecurityScarletAI",
    description="AI-Native SIEM -- Log Ingestion & Detection API",
    # AUD-010: the version is the single-sourced APP_VERSION (Wave-5 seam;
    # pyproject-sync is CI-enforced by tests/unit/test_version.py). The old
    # hardcoded "0.2.0" carried a comment claiming it "matches the git tag"
    # while pyproject was at 0.8.0 — the comment was the lie, and OpenAPI
    # served the stale version.
    version=APP_VERSION,
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
    # tokens (not cookies) so CSRF is moot, but tighten anyway -- never
    # advertise "any header" in a security product.
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(ingest_router, prefix="/api/v1")
app.include_router(ssf_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(correlation_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(chat_router, prefix="/api/v1")
app.include_router(hunt_router, prefix="/api/v1")
app.include_router(auth_login_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(response_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(query_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(detection_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(fleet_router, prefix="/api/v1")
app.include_router(compliance_router, prefix="/api/v1")
app.include_router(metrics_router, prefix="/api/v1")

# Add middleware for request validation and audit logging
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(AuditLogMiddleware)

# Rate limiting state -- Redis-backed via src.api.rate_limit
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)  # type: ignore[arg-type]  # slowapi handler sig vs Starlette
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RateLimitHeadersMiddleware)

# P3.3: HTTP request count + latency metrics. Added LAST so it is the
# outermost middleware -- rate-limit 429s and validation 4xx are counted too.
app.add_middleware(MetricsMiddleware)
