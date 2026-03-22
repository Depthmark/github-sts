"""Health check routes."""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)
router = APIRouter()


# Response Models for OpenAPI Documentation
class HealthResponse(BaseModel):
    """API health status response."""

    status: str = Field(..., description="Health status")

    model_config = ConfigDict(json_schema_extra={"examples": [{"status": "ok"}]})


class ReadinessResponse(BaseModel):
    """API readiness status response."""

    ready: bool = Field(..., description="Whether the API is ready to accept requests")

    model_config = ConfigDict(json_schema_extra={"examples": [{"ready": True}]})


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Check if the API is running and responding to requests. "
    "Used by container orchestration for liveness probes.",
)
async def health_check():
    """
    Perform a basic health check.

    Returns OK if the API is running. Use this endpoint with container orchestration
    systems (Kubernetes, Docker, etc.) for liveness probes to detect if the
    application is still responsive.

    Returns:
        - status == "ok" if healthy
    """
    return {"status": "ok"}


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness Check",
    description="Check if the API is ready to accept requests. "
    "Used by container orchestration for readiness probes. "
    "Returns 503 until all startup tasks (JTI cache, audit logger, pollers) complete.",
    responses={503: {"description": "Service not yet ready"}},
)
async def readiness_check(request: Request):
    """
    Perform a readiness check.

    Returns true if the API is ready to accept requests. Use this endpoint with
    container orchestration systems (Kubernetes, Docker, etc.) for readiness probes
    to determine when traffic can be routed to this instance.

    Returns 503 with ready=false during startup and shutdown.

    Returns:
        - ready == true (200) if ready to handle requests
        - ready == false (503) if not yet ready
    """
    ready = getattr(request.app.state, "ready", False)
    if not ready:
        return JSONResponse(status_code=503, content={"ready": False})
    return {"ready": True}
