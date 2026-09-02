"""
Prometheus /metrics endpoint — in-process registry, zero new dependencies.

Exposes GET /api/v1/metrics in the Prometheus text format (v0.0.4):
- HTTP request count + latency histogram by method + path-class
- Ingest accepted events count
- Writer buffer depth + backpressure events (live gauges, read at scrape)
- DB pool in-use / size (live gauges, read at scrape)
- Correlation run duration histogram
- Retention sweep rows-deleted / errors counters

Design decisions:
- Tiny hand-rolled registry (Counter/Gauge/Histogram + Registry.render()).
  No prometheus_client dependency. NOT a general-purpose implementation:
  covers what this app needs (counters, gauges, one histogram shape).
- Single-event-loop safety: all mutations happen on the asyncio event loop
  with no awaits between read-modify-write steps, so plain dict ops are
  race-free for our purposes. The scrape handler renders synchronously.
- Cardinality control: path classes normalize numeric IDs, UUIDs, and
  user-name segments (anything containing '@' or '.') to {id} so the label
  space stays bounded. High-cardinality labels (raw paths, usernames) are
  a known Prometheus outage cause — never add them.
- Access model (fail-closed):
    * METRICS_BEARER_TOKEN set → matching `Authorization: Bearer` works
      from anywhere (constant-time compare); analyst JWT also works.
    * Unset → localhost scrapes work unauthenticated (Prometheus-on-same-
      host pattern); anything remote needs an analyst-or-above JWT.
  /health is unchanged (unauthenticated liveness stays separate).
"""
import hmac
import re
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from src.config.logging import get_logger

log = get_logger("api.metrics")

router = APIRouter(tags=["metrics"])

_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


# ───────────────────────────────────────────────────────────────
# Registry primitives
# ───────────────────────────────────────────────────────────────


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


class Counter:
    """Monotonic counter with optional labels. values maps label-tuple -> float."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help = help_text
        self.values: dict[tuple[tuple[str, str], ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        self.values[key] = self.values.get(key, 0.0) + amount

    def render(self) -> list[str]:
        lines = [
            f"# HELP {self.name} {_escape_help(self.help)}",
            f"# TYPE {self.name} counter",
        ]
        for key in sorted(self.values):
            amount = self.values[key]
            label_str = _labels_str(dict(key))
            lines.append(f"{self.name}{label_str} {_fmt(amount)}")
        return lines


class Gauge:
    """Point-in-time value with optional labels."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help = help_text
        self.values: dict[tuple[tuple[str, str], ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        self.values[key] = float(value)

    def render(self) -> list[str]:
        lines = [
            f"# HELP {self.name} {_escape_help(self.help)}",
            f"# TYPE {self.name} gauge",
        ]
        for key in sorted(self.values):
            label_str = _labels_str(dict(key))
            lines.append(f"{self.name}{label_str} {_fmt(self.values[key])}")
        return lines


class Histogram:
    """Fixed-bucket histogram with optional labels (cumulative buckets + sum + count)."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self, name: str, help_text: str, buckets: Optional[tuple[float, ...]] = None):
        self.name = name
        self.help = help_text
        self.buckets = tuple(sorted(buckets or self.DEFAULT_BUCKETS))
        # label-tuple -> {"buckets": [counts per bucket], "sum": float, "count": int}
        self.data: dict[tuple[tuple[str, str], ...], dict[str, Any]] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        entry = self.data.setdefault(
            key, {"buckets": [0] * len(self.buckets), "sum": 0.0, "count": 0}
        )
        # A value increments exactly ONE bucket (the smallest upper bound it
        # fits under). Cumulative counts are computed at render time —
        # incrementing every fitting bucket here would double-count.
        for i, upper in enumerate(self.buckets):
            if value <= upper:
                entry["buckets"][i] += 1
                break
        entry["sum"] += value
        entry["count"] += 1

    def render(self) -> list[str]:
        lines = [
            f"# HELP {self.name} {_escape_help(self.help)}",
            f"# TYPE {self.name} histogram",
        ]
        for key in sorted(self.data):
            entry = self.data[key]
            cumulative = 0
            for i, upper in enumerate(self.buckets):
                cumulative = sum(entry["buckets"][: i + 1])
                labels = dict(key)
                labels["le"] = _fmt(upper)
                lines.append(
                    f"{self.name}_bucket{_labels_str(labels)} {cumulative}"
                )
            inf_labels = dict(key)
            inf_labels["le"] = "+Inf"
            lines.append(f"{self.name}_bucket{_labels_str(inf_labels)} {entry['count']}")
            lines.append(f"{self.name}_sum{_labels_str(dict(key))} {_fmt(entry['sum'])}")
            lines.append(f"{self.name}_count{_labels_str(dict(key))} {entry['count']}")
        return lines


def _fmt(v: float) -> str:
    if v == int(v) and abs(v) < 1e15:
        return str(int(v))
    return repr(v)


def _labels_str(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape_label(str(v))}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class Registry:
    """Minimal registry — renders metrics in Prometheus text format."""

    def __init__(self) -> None:
        self._metrics: dict[str, Counter | Gauge | Histogram] = {}

    def counter(self, name: str, help_text: str) -> Counter:
        c = Counter(name, help_text)
        self._metrics[name] = c
        return c

    def gauge(self, name: str, help_text: str) -> Gauge:
        g = Gauge(name, help_text)
        self._metrics[name] = g
        return g

    def histogram(self, name: str, help_text: str) -> Histogram:
        h = Histogram(name, help_text)
        self._metrics[name] = h
        return h

    def render(self) -> str:
        lines: list[str] = []
        for name in sorted(self._metrics):
            lines.extend(self._metrics[name].render())
        return "\n".join(lines) + "\n"


# Module-level singleton. Import and mutate from anywhere on the event loop:
#   from src.api.metrics import METRICS
#   METRICS.http_requests_total.inc(method="POST", path_class="/api/v1/ingest", status="202")
METRICS = Registry()

http_requests_total = METRICS.counter(
    "scarletai_http_requests_total",
    "Total HTTP requests by method, path class, and status code.",
)
http_request_duration = METRICS.histogram(
    "scarletai_http_request_duration_seconds",
    "HTTP request latency in seconds by method and path class.",
)
ingest_accepted_total = METRICS.counter(
    "scarletai_ingest_accepted_total", "Security events accepted by the ingest endpoint."
)
writer_buffer_depth = METRICS.gauge(
    "scarletai_writer_buffer_depth", "Events currently buffered in the log writer."
)
writer_backpressure_total = METRICS.counter(
    "scarletai_writer_backpressure_events_total",
    "Times the writer buffer hit its cap and flushed under backpressure.",
)
db_pool_in_use = METRICS.gauge(
    "scarletai_db_pool_in_use", "PostgreSQL pool connections currently checked out."
)
db_pool_size = METRICS.gauge(
    "scarletai_db_pool_size", "PostgreSQL connection pool size (open connections)."
)
correlation_run_duration = METRICS.histogram(
    "scarletai_correlation_run_duration_seconds",
    "Duration of full correlation runs (all 7 rules).",
)
retention_rows_deleted = METRICS.counter(
    "scarletai_retention_rows_deleted_total", "Rows deleted by retention sweeps, per table."
)
retention_errors = METRICS.counter(
    "scarletai_retention_errors_total", "Retention sweep errors, per table."
)


# ───────────────────────────────────────────────────────────────
# Path classification (cardinality control)
# ───────────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def path_class(path: str) -> str:
    """Normalize a URL path to a low-cardinality label value.

    Numeric and UUID segments become {id}; segments containing '@' or '.'
    (usernames, emails) become {user}. Everything else is kept literally.
    """
    parts: list[str] = []
    for seg in path.split("/"):
        if seg.isdigit() or _UUID_RE.match(seg):
            parts.append("{id}")
        elif "@" in seg or "." in seg:
            parts.append("{user}")
        else:
            parts.append(seg)
    return "/".join(parts)


# ───────────────────────────────────────────────────────────────
# Live source sync + endpoint
# ───────────────────────────────────────────────────────────────


def _sync_live_sources() -> None:
    """Refresh gauges that read live process state at scrape time.

    Every source is best-effort: if the object isn't there yet (writer not
    started) or the pool is down, the metric keeps its last value / stays
    absent rather than breaking the scrape.
    """
    try:
        from src.services.writer import writer

        writer_buffer_depth.set(writer.buffer_depth)
        # Mirrored source counter: only ever increases, so "inc by delta"
        # keeps the counter monotonic (Counter has no set()).
        synced = writer_backpressure_total.values.get((), 0.0)
        if writer.backpressure_events > synced:
            writer_backpressure_total.inc(writer.backpressure_events - synced)
    except Exception as e:  # pragma: no cover — defensive
        log.debug("metrics_writer_source_failed", error=str(e))

    try:
        pool = get_pool_nowait()
    except Exception:
        pool = None
    if pool is not None:
        try:
            db_pool_in_use.set(pool.get_size() - pool.get_idle_size())
            db_pool_size.set(pool.get_size())
        except Exception as e:  # pragma: no cover — defensive
            log.debug("metrics_pool_source_failed", error=str(e))


def get_pool_nowait():
    """Return the singleton pool if already created, else None (never creates)."""
    import src.db.connection as _conn

    return getattr(_conn, "_pool", None)


@router.get("/metrics")
async def prometheus_metrics(request: Request):
    """Prometheus scrape endpoint (text/plain v0.0.4).

    Access model (fail-closed):
    - METRICS_BEARER_TOKEN set → valid scrape token (constant-time compare)
      or analyst-or-above JWT.
    - Unset → analyst-or-above JWT, or unauthenticated from localhost only.
    """
    await _authorize_metrics(request)

    _sync_live_sources()
    payload = METRICS.render()
    return Response(content=payload, media_type=_CONTENT_TYPE)


async def _authorize_metrics(request: Request) -> None:
    """Raise HTTPException (401/403) unless the request may scrape metrics."""
    from jose import JWTError

    from src.api.auth import ROLE_HIERARCHY, _decode_access_jwt
    from src.config.settings import settings

    token_cfg = settings.metrics_bearer_token
    auth = request.headers.get("Authorization", "")
    provided = auth[7:] if auth.startswith("Bearer ") else None

    # 1. Scrape token (constant-time compare).
    if token_cfg is not None and provided is not None:
        if hmac.compare_digest(provided, token_cfg.get_secret_value()):
            return

    # 2. Analyst-or-above JWT. JWTError covers malformed/expired tokens
    # (python-jose raises JWSError, a JWTError subclass, for junk like
    # "not-a-jwt" — without catching it here a malformed bearer would 500).
    if provided is not None:
        try:
            payload = await _decode_access_jwt(provided)
        except (HTTPException, JWTError, ValueError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid metrics credentials",
            ) from e
        if ROLE_HIERARCHY.get(payload.get("role", "viewer"), 0) >= ROLE_HIERARCHY["analyst"]:
            return
        # Valid JWT, insufficient role — 403, distinct from 401.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Metrics require analyst role or a scrape token",
        )

    # 3. Localhost scrape, only when no token is configured.
    client_host = request.client.host if request.client else ""
    if token_cfg is None and client_host in ("127.0.0.1", "::1"):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Metrics require authentication (scrape token or analyst JWT)",
    )


# ───────────────────────────────────────────────────────────────
# Middleware — request count + latency
# ───────────────────────────────────────────────────────────────


class MetricsMiddleware(BaseHTTPMiddleware):
    """Count every HTTP request and observe its latency.

    Outermost app middleware, so rate-limit 429s and validation 4xx/413s are
    counted too. Failures inside the metrics path must never break requests —
    the observe calls are wrapped.
    """

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            try:
                elapsed = time.monotonic() - start
                p_class = path_class(request.url.path)
                # When call_next raised (or returned nothing), count 500 —
                # honest, and latency is still observed.
                status_code = getattr(response, "status_code", 500)
                http_requests_total.inc(
                    method=request.method, path_class=p_class, status=str(status_code)
                )
                http_request_duration.observe(elapsed, method=request.method, path_class=p_class)
            except Exception as e:  # pragma: no cover — metrics must not break requests
                log.debug("metrics_observe_failed", error=str(e))
