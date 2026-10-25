"""Mobile app connection: dashboard-approved device pairing and device tokens.

The app never sees the user's password or web session. It pairs like the
browser extension does (see backend.services.pairing), but its pairings and
tokens are of kind "mobile": they cannot be approved, exchanged or used as
extension ones, or the other way round.

- /mobile/v1/*: called by the app. Pairing is public (bound to the app's secret);
  everything else needs the device's Bearer token (require_mobile) with the
  route's scope. They return exactly what the dashboard API returns for the
  same user: websites, email and timeline through backend.routes.dashboard_views,
  SMS investigations through backend.routes.sms_shared (same analysis, limits,
  redaction and storage, including store_text defaulting to false).
- SMS analysis and SMS changes also count against per-user hourly limits.

This module is all a mobile-mode deployment serves besides the health checks, so
it imports no other router. The dashboard's device routes are in mobile_devices.
"""

import unicodedata
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import User, UserSession
from backend.routes import dashboard_views as views
from backend.routes import sms_shared
from backend.routes.common import TOO_MANY, parse_json
from backend.schemas.dashboard import (
    DashboardEmailDetail, DashboardEmailPage, DashboardSignupPage, SignupDetailResponse, Timeline,
)
from backend.schemas.signup import MAX_BIGINT
from backend.schemas.sms import SmsAnalysis, SmsInvestigation, SmsInvestigationPage, SmsSaveResponse
from backend.security import client_ip, require_mobile
from backend.services import auth as auth_service
from backend.services import pairing
from backend.services.auth import AuthContext, RateLimited

router = APIRouter(prefix="/mobile/v1", tags=["mobile"])

MAX_LABEL = 64
MAX_BODY = 8 * 1024  # pairing bodies; SMS bodies use sms_shared's own limit


async def parse(request: Request, model):
    return await parse_json(request, model, MAX_BODY)


def _count(db: Session, auth: AuthContext, kind: str) -> None:
    """Count this request against the device owner's hourly limit (429 once it is used up)."""
    try:
        auth_service.limit_user(db, kind, auth.user_id)
    except RateLimited:
        raise TOO_MANY from None


class MobilePairingStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret_hash: str = Field(description="SHA-256 (hex) of a random secret the app keeps.", max_length=64)
    device_label: str | None = Field(default=None, max_length=MAX_LABEL,
                                     description="A name for this device, shown to the user before approval.")

    @field_validator("device_label")
    @classmethod
    def check_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = " ".join(value.split())
        if any(unicodedata.category(ch).startswith("C") for ch in value):
            raise ValueError("device_label cannot contain control or formatting characters")
        return value or None


class MobilePairingStarted(BaseModel):
    pairing_id: int
    code: str = Field(description="Show this to the user; they approve it in the dashboard as a mobile device.")
    expires_at: datetime


class MobilePairingExchange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: str = Field(min_length=20, max_length=200)


class MobileToken(BaseModel):
    token: str
    expires_at: datetime
    email: str
    scopes: list[str]


class MobileDevice(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    label: str | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime


class MobileMe(BaseModel):
    email: str
    email_verified: bool
    scopes: list[str]
    device: MobileDevice


# ---------- called by the app ----------

@router.post("/pairings", status_code=201, response_model=MobilePairingStarted, responses={422: {}, 429: {}})
async def start_pairing(request: Request, db: Session = Depends(get_db)) -> MobilePairingStarted:
    data = await parse(request, MobilePairingStart)
    try:
        started = await run_in_threadpool(pairing.start, db, data.secret_hash.lower(), client_ip(request),
                                          "mobile", data.device_label)
    except ValueError as exc:
        raise HTTPException(422, [{"loc": ["secret_hash"], "msg": str(exc)}]) from None
    except RateLimited:
        raise TOO_MANY from None
    return MobilePairingStarted(pairing_id=started.pairing_id, code=started.code, expires_at=started.expires_at)


@router.post("/pairings/{pairing_id}/token", response_model=MobileToken,
             responses={202: {"description": "Not approved yet"}, 404: {}, 410: {}, 429: {}})
async def exchange_pairing(request: Request, response: Response, pairing_id: int = Path(gt=0, le=MAX_BIGINT),
                           db: Session = Depends(get_db)):
    data = await parse(request, MobilePairingExchange)
    try:
        issued = await run_in_threadpool(pairing.exchange, db, pairing_id, data.secret, client_ip(request), "mobile")
    except pairing.PairingPending:
        return JSONResponse({"detail": "Waiting for approval in the dashboard."}, status_code=202,
                            headers={"Cache-Control": "no-store"})
    except pairing.PairingExpired:
        raise HTTPException(410, "This pairing expired or was already used. Start again.") from None
    except pairing.PairingNotFound:
        raise HTTPException(404, "Unknown pairing.") from None
    except RateLimited:
        raise TOO_MANY from None
    response.headers["Cache-Control"] = "no-store"
    return MobileToken(token=issued.token, expires_at=issued.expires_at, email=issued.email, scopes=list(issued.scopes))


@router.get("/me", response_model=MobileMe, responses={401: {}, 403: {}})
def me(auth: AuthContext = Depends(require_mobile("account:read")), db: Session = Depends(get_db)) -> MobileMe:
    user = db.get(User, auth.user_id)
    return MobileMe(email=user.email, email_verified=user.email_verified_at is not None, scopes=sorted(auth.scopes),
                    device=MobileDevice.model_validate(db.get(UserSession, auth.session_id)))


@router.post("/logout", status_code=204, responses={401: {}})
def logout(auth: AuthContext = Depends(require_mobile()), db: Session = Depends(get_db)) -> Response:
    """Revoke this device's own token."""
    auth_service.revoke_session(db, auth.session_id, auth.user_id)
    return Response(status_code=204)


# ---------- read routes: the device owner's records only ----------

@router.get("/websites", response_model=DashboardSignupPage, responses={401: {}, 403: {}})
def list_websites(
    limit: int = views.Limit,
    offset: int = views.Offset,
    q: str | None = views.SignupSearch,
    filter: views.SignupFilter = "all",
    auth: AuthContext = Depends(require_mobile("websites:read")),
    db: Session = Depends(get_db),
) -> DashboardSignupPage:
    return views.signup_page(db, auth.user_id, limit, offset, q, filter)


@router.get("/websites/{website_id}", response_model=SignupDetailResponse, responses={401: {}, 403: {}, 404: {}})
def get_website(
    website_id: int = Path(gt=0, le=MAX_BIGINT),
    auth: AuthContext = Depends(require_mobile("websites:read")),
    db: Session = Depends(get_db),
) -> SignupDetailResponse:
    detail = views.signup_detail(db, auth.user_id, website_id)
    if detail is None:  # another user's, unowned or missing: indistinguishable
        raise HTTPException(404, views.SIGNUP_NOT_FOUND)
    return detail


@router.get("/emails", response_model=DashboardEmailPage, responses={401: {}, 403: {}})
def list_emails(
    limit: int = views.Limit,
    offset: int = views.Offset,
    status: views.EmailStatus | None = None,
    auth: AuthContext = Depends(require_mobile("email:read")),
    db: Session = Depends(get_db),
) -> DashboardEmailPage:
    return views.email_page(db, auth.user_id, limit, offset, status)


@router.get("/emails/{email_id}", response_model=DashboardEmailDetail, responses={401: {}, 403: {}, 404: {}})
def get_email(
    email_id: int = Path(gt=0, le=MAX_BIGINT),
    auth: AuthContext = Depends(require_mobile("email:read")),
    db: Session = Depends(get_db),
) -> DashboardEmailDetail:
    detail = views.email_detail(db, auth.user_id, email_id)
    if detail is None:
        raise HTTPException(404, views.EMAIL_NOT_FOUND)
    return detail


@router.get("/timeline", response_model=Timeline, responses={401: {}, 403: {}})
def get_timeline(
    limit: int = views.TimelineLimit,
    auth: AuthContext = Depends(require_mobile("timeline:read")),
    db: Session = Depends(get_db),
) -> Timeline:
    """Your email and saved SMS investigations, newest first."""
    return views.timeline(db, auth.user_id, limit)


# ---------- SMS investigations: the device owner's records only ----------

InvestigationId = Path(gt=0, le=MAX_BIGINT)


@router.post("/sms/analyze", response_model=SmsAnalysis, responses={401: {}, 403: {}, 413: {}, 415: {}, 422: {}},
             openapi_extra=sms_shared.ANALYZE_BODY)
async def analyze_sms(request: Request, auth: AuthContext = Depends(require_mobile("sms:analyze")),
                      db: Session = Depends(get_db)) -> SmsAnalysis:
    """Extract details and suggest a source. Stores nothing."""
    await run_in_threadpool(_count, db, auth, "sms_analyze_user")
    return await sms_shared.analyze(request, db, auth, settings.alias_domain)


@router.get("/sms/investigations", response_model=SmsInvestigationPage, responses={401: {}, 403: {}})
def list_sms_investigations(
    limit: int = sms_shared.Limit, offset: int = sms_shared.Offset,
    auth: AuthContext = Depends(require_mobile("sms:analyze")), db: Session = Depends(get_db),
) -> SmsInvestigationPage:
    return sms_shared.list_page(db, auth, limit, offset)


@router.get("/sms/investigations/{investigation_id}", response_model=SmsInvestigation,
            responses={401: {}, 403: {}, 404: {}})
def get_sms_investigation(investigation_id: int = InvestigationId,
                          auth: AuthContext = Depends(require_mobile("sms:analyze")),
                          db: Session = Depends(get_db)) -> SmsInvestigation:
    return sms_shared.get_one(db, auth, investigation_id)


@router.post("/sms/investigations", response_model=SmsSaveResponse, status_code=201,
             responses={200: {"description": "Already saved; nothing new was stored"}, 401: {}, 403: {}, 413: {},
                        415: {}, 422: {}},
             openapi_extra=sms_shared.SAVE_BODY)
async def save_sms_investigation(request: Request, auth: AuthContext = Depends(require_mobile("sms:write")),
                                 db: Session = Depends(get_db)):
    """Analyse again on the server (client results are never trusted) and save."""
    await run_in_threadpool(_count, db, auth, "sms_write_user")
    return await sms_shared.save(request, db, auth, settings.alias_domain)


@router.post("/sms/investigations/{investigation_id}/actions", response_model=SmsInvestigation,
             responses={401: {}, 403: {}, 404: {}, 422: {}})
async def sms_investigation_action(request: Request, investigation_id: int = InvestigationId,
                                   auth: AuthContext = Depends(require_mobile("sms:write")),
                                   db: Session = Depends(get_db)) -> SmsInvestigation:
    """Confirm or reject a suggested source, link a website by hand, or mark as reviewed."""
    await run_in_threadpool(_count, db, auth, "sms_write_user")
    return await sms_shared.act(request, db, auth, investigation_id)


@router.delete("/sms/investigations/{investigation_id}", status_code=204, responses={401: {}, 403: {}, 404: {}})
def delete_sms_investigation(investigation_id: int = InvestigationId,
                             auth: AuthContext = Depends(require_mobile("sms:write")),
                             db: Session = Depends(get_db)) -> Response:
    _count(db, auth, "sms_write_user")
    return sms_shared.delete(db, auth, investigation_id)
