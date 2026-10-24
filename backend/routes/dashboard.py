"""Personal dashboard: a static page plus JSON endpoints for the signed-in user.

Every data endpoint requires a signed-in web session and returns only that
user's records. As an extra layer while LeakTrace is not deployed, every route
also only answers requests from this machine (loopback) and only when
LEAKTRACE_DASHBOARD_ENABLED is on. A reverse proxy on the same machine would
defeat the loopback check, so do not put this behind one or expose it.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.routes.common import read_limited_body, require_json, validation_error
from backend.schemas.dashboard import (
    DashboardEmail,
    DashboardEmailDetail,
    DashboardEmailPage,
    DashboardSignup,
    DashboardSignupPage,
    InboxItem,
    InboxPage,
    InboxReadAllResponse,
    InboxReadRequest,
    InboxUpdates,
    Investigation,
    InvestigationPage,
    OverviewResponse,
    SignupDetailResponse,
    SignupReceipt,
)
from backend.schemas.signup import MAX_BIGINT
from backend.security import require_user
from backend.services import dashboard, matcher
from backend.services.auth import AuthContext

STATIC_DIR = Path(__file__).resolve().parent.parent / "dashboard"
STATIC_FILES = {"app.js": "text/javascript", "styles.css": "text/css"}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MAX_PAGE_SIZE = 100
MAX_BODY_BYTES = 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool


def get_dashboard_config() -> DashboardConfig:
    return DashboardConfig(enabled=settings.dashboard_enabled)


def require_local_dashboard(
    request: Request, config: DashboardConfig = Depends(get_dashboard_config)
) -> None:
    if not config.enabled:
        raise HTTPException(404, "Not Found")
    host = request.client.host if request.client else None
    if host not in LOOPBACK_HOSTS:
        raise HTTPException(403, "The dashboard is only available from this machine.")


router = APIRouter(
    prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_local_dashboard)]
)

Limit = Query(20, ge=1, le=MAX_PAGE_SIZE)
Offset = Query(0, ge=0, le=MAX_BIGINT)
NOT_FOUND = HTTPException(404, "Not found")


@router.get("", include_in_schema=False)
def page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html", headers=SECURITY_HEADERS)


@router.get("/static/{name}", include_in_schema=False)
def static_file(name: str) -> FileResponse:
    if name not in STATIC_FILES:
        raise HTTPException(404, "Not Found")
    return FileResponse(STATIC_DIR / name, media_type=STATIC_FILES[name], headers=SECURITY_HEADERS)


@router.get("/api/overview", response_model=OverviewResponse)
def get_overview(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> OverviewResponse:
    return OverviewResponse(**vars(dashboard.overview(db, auth.user_id)))


@router.get("/api/signups", response_model=DashboardSignupPage)
def get_signups(
    limit: int = Limit,
    offset: int = Offset,
    q: str | None = Query(None, max_length=100, description="Search site name, domain, alias or nickname."),
    filter: Literal["all", "with_receipts", "with_emails", "real_name"] = "all",
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> DashboardSignupPage:
    items, total = dashboard.list_signups(db, auth.user_id, limit, offset, q, filter)
    return DashboardSignupPage(items=[DashboardSignup.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


@router.get("/api/signups/{signup_id}", response_model=SignupDetailResponse, responses={404: {}})
def get_signup(
    signup_id: int = PathParam(gt=0, le=MAX_BIGINT),
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> SignupDetailResponse:
    detail = dashboard.get_signup_detail(db, auth.user_id, signup_id)
    if detail is None:
        raise NOT_FOUND
    s = detail.signup
    return SignupDetailResponse(
        id=s.id, site_name=s.site_name, site_domain=s.site_domain, alias=s.alias, nickname=s.nickname,
        surname_variant=s.surname_variant, real_name_required=s.real_name_required, real_name_used=s.real_name_used,
        created_at=s.created_at,
        receipts=[SignupReceipt(
            id=r.id, action=r.action, evidence_basis="user_reported" if r.capture_source == "manual" else "unknown",
            recorded_at=r.created_at, reported_occurred_at=r.reported_occurred_at, source_url=r.source_url,
        ) for r in detail.receipts],
        emails=[DashboardEmail.model_validate(e) for e in detail.emails],
    )


@router.get("/api/emails", response_model=DashboardEmailPage)
def get_emails(
    limit: int = Limit,
    offset: int = Offset,
    status: Literal["matched", "ambiguous", "no_match", "unprocessed"] | None = None,
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> DashboardEmailPage:
    items, total = dashboard.list_emails(db, auth.user_id, limit, offset, status)
    return DashboardEmailPage(items=[DashboardEmail.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


@router.get("/api/emails/{mail_log_id}", response_model=DashboardEmailDetail, responses={404: {}})
def get_email(
    mail_log_id: int = PathParam(gt=0, le=MAX_BIGINT),
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> DashboardEmailDetail:
    row = dashboard.get_email(db, auth.user_id, mail_log_id)
    if row is None:
        raise HTTPException(404, "Email record not found")
    return DashboardEmailDetail(**vars(row), limitations=list(matcher.LIMITATIONS))


@router.get("/api/investigations", response_model=InvestigationPage)
def get_investigations(
    limit: int = Limit, offset: int = Offset,
    auth: AuthContext = Depends(require_user), db: Session = Depends(get_db),
) -> InvestigationPage:
    items, total = dashboard.list_investigations(db, auth.user_id, limit, offset)
    return InvestigationPage(items=[Investigation.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


# ---------- inbox ----------

MailLogId = PathParam(gt=0, le=MAX_BIGINT)
INBOX_NOT_FOUND = HTTPException(404, "Email not found")


@router.get("/api/inbox", response_model=InboxPage)
def get_inbox(
    limit: int = Limit,
    offset: int = Offset,
    filter: Literal["all", "unread", "matched", "unmatched", "failed"] = "all",
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> InboxPage:
    """Email received at your aliases, newest first, with the unread count."""
    items, total, unread = dashboard.list_inbox(db, auth.user_id, limit, offset, filter)
    return InboxPage(items=[InboxItem.model_validate(i) for i in items], total=total, limit=limit,
                     offset=offset, unread=unread)


@router.get("/api/inbox/updates", response_model=InboxUpdates)
def get_inbox_updates(
    after_id: int | None = Query(None, ge=0, le=MAX_BIGINT, description="latest_id from the previous poll."),
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> InboxUpdates:
    """For polling: the unread count and messages recorded since the last poll."""
    updates = dashboard.inbox_updates(db, auth.user_id, after_id)
    return InboxUpdates(unread=updates.unread, latest_id=updates.latest_id,
                        new=[InboxItem.model_validate(i) for i in updates.new])


@router.post("/api/inbox/read-all", response_model=InboxReadAllResponse)
def read_all(auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> InboxReadAllResponse:
    marked = dashboard.mark_all_read(db, auth.user_id)
    return InboxReadAllResponse(marked=marked, unread=dashboard.unread_count(db, auth.user_id))


@router.get("/api/inbox/{mail_log_id}", response_model=InboxItem, responses={404: {}})
def get_inbox_item(
    mail_log_id: int = MailLogId, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db),
) -> InboxItem:
    """One message. Reading it does not mark it read; use the read endpoint."""
    row = dashboard.get_inbox_item(db, auth.user_id, mail_log_id)
    if row is None:
        raise INBOX_NOT_FOUND
    return InboxItem.model_validate(row)


@router.post("/api/inbox/{mail_log_id}/read", response_model=InboxItem, responses={404: {}})
async def set_inbox_read(
    request: Request,
    mail_log_id: int = MailLogId,
    auth: AuthContext = Depends(require_user),
    db: Session = Depends(get_db),
) -> InboxItem:
    """Mark a message read ({"read": true}) or unread ({"read": false})."""
    require_json(request)
    try:
        body = InboxReadRequest.model_validate_json(await read_limited_body(request, MAX_BODY_BYTES))
    except ValidationError as exc:
        raise validation_error(exc) from None
    row = await run_in_threadpool(dashboard.set_read, db, auth.user_id, mail_log_id, body.read)
    if row is None:
        raise INBOX_NOT_FOUND
    return InboxItem.model_validate(row)
