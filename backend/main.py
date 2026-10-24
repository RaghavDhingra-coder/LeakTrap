"""LeakTrace API entry point.

Run from the project root with:
    uvicorn backend.main:app --reload
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import OperationalError

from backend.config import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    configuration_problems,
    mask_database_url,
    settings,
)
from backend.database import DatabaseNotConfiguredError
from backend.routes import health, ingest

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("leaktrace")

# Outside development, refuse to start with an unusable configuration, so a
# deployment fails its health check instead of silently rejecting email.
_problems = configuration_problems(settings)
if _problems and settings.environment != "development":
    raise RuntimeError("Invalid LeakTrace configuration: " + "; ".join(_problems))
for _problem in _problems:
    logger.warning("Configuration: %s", _problem)


class RootResponse(BaseModel):
    application: str
    status: str
    version: str


# The public ingest deployment publishes no API documentation.
_docs = {"docs_url": None, "redoc_url": None, "openapi_url": None} if settings.app_mode == "ingest" else {}
app = FastAPI(
    title=f"{APP_NAME} API",
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    **_docs,
)

# Register routers here. Future phases add their routers alongside this one.
# A public "ingest" deployment serves only what Cloudflare's email Worker needs;
# accounts, the extension API and the dashboard stay on this machine.
# The other routers are imported only in full mode, so an ingest deployment
# never loads account, session or dashboard code.
if settings.app_mode == "ingest":
    ROUTERS = (health.router, ingest.router)
else:
    from backend.routes import auth, autofill, consent_receipts, dashboard, extension, matcher, signups, sms

    ROUTERS = (
        health.router, auth.router, auth.account_router, extension.router, signups.router, matcher.router,
        ingest.router, dashboard.router, sms.router, consent_receipts.router, autofill.router,
    )
for _router in ROUTERS:
    app.include_router(_router)


@app.exception_handler(DatabaseNotConfiguredError)
def database_not_configured(request: Request, exc: DatabaseNotConfiguredError) -> JSONResponse:
    logger.error("Database not configured: %s", exc)
    return JSONResponse(status_code=503, content={"detail": "Database is not configured."})


@app.exception_handler(OperationalError)
def database_unavailable(request: Request, exc: OperationalError) -> JSONResponse:
    # Log only the error type: messages can include host names or SQL.
    logger.error("Database unavailable: %s", type(exc.orig).__name__)
    return JSONResponse(status_code=503, content={"detail": "Database is unavailable."})


@app.get("/", response_model=RootResponse, tags=["root"])
def root() -> RootResponse:
    return RootResponse(application=APP_NAME, status="running", version=APP_VERSION)


logger.info("%s API %s initialised (environment=%s, mode=%s)", APP_NAME, APP_VERSION, settings.environment,
            settings.app_mode)
# Log only the masked URL. No connection is opened here; sessions are created
# on demand through backend.database.get_db.
logger.info("Database: %s", mask_database_url(settings.database_url))
