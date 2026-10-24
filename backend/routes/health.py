"""Health check routes.

/health reports only that the process responds. Use it for a hosting
platform's frequent health checks: it never touches the database, so it does
not keep a scale-to-zero Neon compute awake. /health/ready also runs
"SELECT 1", for checking a deployment by hand. Neither reveals any detail.
"""

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from backend.database import get_engine

logger = logging.getLogger("leaktrace.health")

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    message: str


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", message="LeakTrace running")


class ReadyResponse(BaseModel):
    status: str
    database: str


@router.get("/health/ready", response_model=ReadyResponse, responses={503: {"model": ReadyResponse}})
def ready():
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # any failure means "not ready"; log the type only
        logger.error("Readiness check failed: %s", type(exc).__name__)
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "unavailable"})
    return ReadyResponse(status="ok", database="ok")
