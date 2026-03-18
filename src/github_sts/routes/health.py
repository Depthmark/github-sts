"""Health check routes."""

import logging
from typing import ClassVar

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter()


# Response Models for OpenAPI Documentation
class HealthResponse(BaseModel):
    """API health status response."""

    status: str = Field(..., description="Health status")

    class Config:
        json_schema_extra: ClassVar[dict] = {"example": {"status": "ok"}}


class ReadinessResponse(BaseModel):
    """API readiness status response."""

    ready: bool = Field(..., description="Whether the API is ready to accept requests")

    class Config:
        json_schema_extra: ClassVar[dict] = {"example": {"ready": True}}


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
    "Used by container orchestration for readiness probes.",
)
async def readiness_check():
    """
    Perform a readiness check.

    Returns true if the API is ready to accept requests. Use this endpoint with
    container orchestration systems (Kubernetes, Docker, etc.) for readiness probes
    to determine when traffic can be routed to this instance.

    Returns:
        - ready == true if ready to handle requests
    """
    return {"ready": True}
