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
    parse_forwarded_allow_ips,
    settings,
)
from backend.database import DatabaseNotConfiguredError
from backend.mobile_http import MobileResponseHeaders, ProxyDiagnostics, install_access_log_privacy
from backend.routes import health

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("leaktrace")

# Outside development, refuse to start with an unusable configuration, so a
# deployment fails its health check instead of silently rejecting email.
# Mobile mode exists only to be deployed publicly, so it is refused everywhere.
_problems = configuration_problems(settings)
if parse_forwarded_allow_ips(settings.forwarded_allow_ips) is None:
    raise RuntimeError("Invalid LeakTrace configuration: FORWARDED_ALLOW_IPS must be an explicit IP/CIDR allowlist")
if settings.dashboard_public and _problems:
    raise RuntimeError("Invalid LeakTrace configuration: " + "; ".join(_problems))
if _problems and (settings.environment != "development" or settings.app_mode == "mobile"):
    raise RuntimeError("Invalid LeakTrace configuration: " + "; ".join(_problems))
for _problem in _problems:
    logger.warning("Configuration: %s", _problem)


class RootResponse(BaseModel):
    application: str
    status: str
    version: str


# The public ingest and mobile deployments publish no API documentation.
_public = settings.app_mode in ("ingest", "mobile")
_docs = {"docs_url": None, "redoc_url": None, "openapi_url": None} if _public else {}
app = FastAPI(
    title=f"{APP_NAME} API",
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    **_docs,
)

# Register routers here. Future phases add their routers alongside this one.
# A public "ingest" deployment serves only what Cloudflare's email Worker needs;
# a public "mobile" deployment serves only the mobile app's /mobile/v1 API.
# Accounts and the extension API are served in full mode. The dashboard stays
# loopback-only unless its explicit HTTPS public-origin mode is configured.
# Routers are imported only in the modes that serve them, so a public deployment
# never loads code it does not serve.
if settings.app_mode == "ingest":
    from backend.routes import ingest

    ROUTERS = (health.router, ingest.router)
elif settings.app_mode == "mobile":
    from backend.routes import mobile

    ROUTERS = (health.router, mobile.router)
else:
    from backend.routes import (
        auth, autofill, consent_receipts, dashboard, domain_verification, extension, ingest, matcher, mobile, mobile_devices, signups, sms, website_reports,
    )

    ROUTERS = (
        health.router, auth.router, auth.account_router, extension.router, signups.router, matcher.router,
        ingest.router, dashboard.router, domain_verification.router, sms.router, consent_receipts.router, autofill.router,
        mobile.router, mobile_devices.router, website_reports.router,
    )
for _router in ROUTERS:
    app.include_router(_router)

# Mobile API responses are never cached and never content-sniffed, in every mode.
app.add_middleware(MobileResponseHeaders)
if settings.dashboard_public:
    from backend.security import PublicDashboardOriginGuard

    app.add_middleware(PublicDashboardOriginGuard, origin=settings.dashboard_public_origin)
# Access logs never record query strings of mobile API requests (in mobile mode: of any request).
install_access_log_privacy(strip_all=settings.app_mode == "mobile")
if settings.app_mode == "mobile" and settings.proxy_diagnostics:  # refused in production at startup
    app.add_middleware(ProxyDiagnostics)
    logger.warning("Proxy diagnostics are on: marked /health requests log their forwarding headers")


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
