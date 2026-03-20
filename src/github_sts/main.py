"""
github-sts: Security Token Service for GitHub API using OIDC federation.
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from . import metrics
from .audit import create_audit_logger
from .config import get_settings
from .jti_cache import create_jti_cache
from .logging_config import setup_logging
from .rate_limit import RateLimitPoller, ReachabilityProber
from .request_context import set_trace_id
from .routes import exchange, health

# Bootstrap with a minimal stdout logger until setup_logging() runs in lifespan
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)
access_logger = logging.getLogger("github_sts.access")

# OpenAPI tags metadata for better API documentation
TAGS_METADATA = [
    {
        "name": "exchange",
        "description": "OIDC token exchange endpoints - Convert OIDC tokens to GitHub installation tokens",
    },
    {
        "name": "health",
        "description": "Health check endpoints for container orchestration and monitoring",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    logger.info("github-sts starting up")

    # Initialize settings and configure structured logging
    settings = get_settings()
    log_cfg = settings.server.logging
    # Backward compat: legacy log_level seeds logging.level
    if settings.server.log_level != "INFO" and log_cfg.level == "INFO":
        log_cfg = log_cfg.model_copy(update={"level": settings.server.log_level})
    setup_logging(
        level=log_cfg.level,
        access_level=log_cfg.access_level,
        suppress_health_logs=log_cfg.suppress_health_logs,
        audit_file_enabled=log_cfg.audit_file_enabled,
        audit_file_path=log_cfg.audit_file_path,
        audit_file_max_bytes=log_cfg.audit_file_max_bytes,
        audit_file_backup_count=log_cfg.audit_file_backup_count,
    )

    # Log policy resolution configuration
    base_path = settings.policy.base_path
    app_names = settings.app_names
    logger.info(
        "Policy base_path=%s, configured apps=%s",
        base_path,
        app_names,
    )
    for name in app_names:
        logger.info(
            "  App %r: policy path = <repo>/%s/%s/<identity>.sts.yaml",
            name,
            base_path,
            name,
        )

    if not settings.oidc.allowed_issuers:
        logger.warning(
            "No OIDC allowed_issuers configured — any issuer will be accepted. "
            "Set oidc.allowed_issuers in config or PYGITHUBSTS_OIDC_ALLOWED_ISSUERS env var."
        )
    else:
        logger.info("OIDC allowed_issuers=%s", settings.oidc.allowed_issuers)

    # Initialize JTI cache for replay prevention
    try:
        jti_cache = await create_jti_cache(
            backend=settings.jti.backend,
            redis_url=settings.jti.redis_url,
            ttl_seconds=settings.jti.ttl_seconds,
        )
        app.state.jti_cache = jti_cache
        logger.info("JTI cache initialized: backend=%s", settings.jti.backend)
    except Exception as exc:
        logger.error("Failed to initialize JTI cache: %s", exc)
        raise

    # Initialize audit logger
    try:
        audit_logger = await create_audit_logger(
            "file",
            log_path=settings.audit.file_path,
            rotation_policy=settings.audit.rotation_policy,
            rotation_size_bytes=settings.audit.rotation_size_bytes,
        )
        app.state.audit_logger = audit_logger
        logger.info("Audit logger initialized: file=%s", settings.audit.file_path)
    except Exception as exc:
        logger.error("Failed to initialize audit logger: %s", exc)
        raise

    # Start event loop lag monitor
    async def _monitor_loop_lag():
        loop = asyncio.get_event_loop()
        while True:
            t0 = loop.time()
            await asyncio.sleep(0.1)
            lag = loop.time() - t0 - 0.1
            metrics.EVENT_LOOP_LAG.set(max(0, lag))

    app.state.loop_lag_task = asyncio.create_task(_monitor_loop_lag())

    # Start rate limit poller
    if settings.metrics.rate_limit_poll_enabled and settings.apps:
        poller = RateLimitPoller(
            apps={name: settings.get_app(name) for name in settings.app_names},
            interval_seconds=settings.metrics.rate_limit_poll_interval_seconds,
        )
        await poller.start()
        app.state.rate_limit_poller = poller

    # Start reachability prober
    if settings.metrics.reachability_probe_enabled and settings.apps:
        prober = ReachabilityProber(
            apps={name: settings.get_app(name) for name in settings.app_names},
            interval_seconds=settings.metrics.reachability_probe_interval_seconds,
        )
        await prober.start()
        app.state.reachability_prober = prober

    # Mark instance as ready
    app.state.ready = True
    metrics.READY.set(1)
    logger.info("github-sts ready")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    app.state.ready = False
    metrics.READY.set(0)
    logger.info("github-sts shutting down")

    # Cancel event loop lag monitor
    if hasattr(app.state, "loop_lag_task"):
        app.state.loop_lag_task.cancel()

    # Stop rate limit poller
    if hasattr(app.state, "rate_limit_poller"):
        try:
            await app.state.rate_limit_poller.stop()
            logger.info("Rate limit poller stopped")
        except Exception as exc:
            logger.error("Error stopping rate limit poller: %s", exc)

    # Stop reachability prober
    if hasattr(app.state, "reachability_prober"):
        try:
            await app.state.reachability_prober.stop()
            logger.info("Reachability prober stopped")
        except Exception as exc:
            logger.error("Error stopping reachability prober: %s", exc)

    # Clean up JTI cache
    if hasattr(app.state, "jti_cache"):
        try:
            await app.state.jti_cache.cleanup()
            logger.info("JTI cache cleaned up")
        except Exception as exc:
            logger.error("Error cleaning up JTI cache: %s", exc)

    # Clean up audit logger
    if hasattr(app.state, "audit_logger"):
        try:
            await app.state.audit_logger.cleanup()
            logger.info("Audit logger cleaned up")
        except Exception as exc:
            logger.error("Error cleaning up audit logger: %s", exc)


app = FastAPI(
    title="GitHub Security Token Service (github-sts)",
    description="A Security Token Service (STS) for the GitHub API using OIDC federation. "
    "Exchanges workload OIDC tokens for short-lived, scoped GitHub installation tokens. "
    "Supports any OIDC-compliant issuer (GitHub Actions, GCP, AWS, Kubernetes, Okta, etc.)",
    version="0.1.0",
    lifespan=lifespan,
    openapi_tags=TAGS_METADATA,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url=None,
)


# Prometheus metrics endpoint at /metrics
@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
        headers={"Cache-Control": "no-store"},
    )


# Include routers
app.include_router(exchange.router, prefix="/sts", tags=["exchange"])
app.include_router(health.router, tags=["health"])


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    """Assign a server-generated trace ID to every request.

    Always generates a random UUID-hex — client-supplied headers are
    intentionally ignored to prevent trace-ID spoofing in logs and
    audit records.  The trace ID is set on the ``ContextVar`` so that
    every ``logger.*`` call in any module automatically includes it via
    the ``JSONFormatter``.
    """
    trace_id = uuid.uuid4().hex
    set_trace_id(trace_id)
    response = await call_next(request)
    response.headers["X-Trace-ID"] = trace_id
    return response


@app.middleware("http")
async def access_logging_middleware(request: Request, call_next):
    """Log every HTTP request on the access channel."""
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - start) * 1000, 2)

    access_logger.info(
        "%s %s %d",
        request.method,
        request.url.path,
        response.status_code,
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Track request count, latency, and in-flight requests."""
    path = request.url.path
    method = request.method

    # Skip metrics endpoint itself
    if path == "/metrics":
        return await call_next(request)

    metrics.IN_FLIGHT.inc()
    start = time.time()
    try:
        response = await call_next(request)
        status = str(response.status_code)
        metrics.REQUEST_COUNT.labels(method=method, path=path, status=status).inc()
        return response
    except Exception as exc:
        metrics.REQUEST_COUNT.labels(method=method, path=path, status="500").inc()
        raise exc
    finally:
        metrics.REQUEST_LATENCY.labels(method=method, path=path).observe(
            time.time() - start
        )
        metrics.IN_FLIGHT.dec()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "internal server error"})
