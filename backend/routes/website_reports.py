"""Authenticated community leads about websites, never confirmed breach claims."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import MailLog, Report, Signup, User
from backend.routes.common import parse_json
from backend.security import get_auth_context, require_user
from backend.services.auth import AuthContext, RateLimited, limit_user
from backend.services.domains import normalize_domain, parent_domains
from backend.services.email_attribution import alias_link
from backend.services.sender_classification import classify
from backend.services.sms_extract import registrable_domain

router = APIRouter(prefix="/website-reports", tags=["website reports"])
CATEGORY = "possible_data_exposure"
ACTIVE = ("community_reported", "under_review")


class SubmitReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email_id: int = Field(gt=0)
    confirmed_domain: str = Field(min_length=3, max_length=253)


class ReviewReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str


def _domain(value: str) -> str:
    try:
        return normalize_domain(value)
    except ValueError:
        raise HTTPException(422, "Enter a valid website domain.") from None


def _summary(row: Report) -> dict:
    return {"id": row.id, "domain": row.site_domain, "category": row.category,
            "status": row.status, "created_at": row.created_at, "updated_at": row.updated_at}


def _reputation_user(auth: AuthContext | None = Depends(get_auth_context)) -> AuthContext:
    if auth is None or auth.kind not in ("web", "extension"):
        raise HTTPException(401, "Sign in to view community reports.")
    return auth


@router.post("", status_code=201)
async def submit(request: Request, auth: AuthContext = Depends(require_user),
                 db: Session = Depends(get_db)) -> dict:
    data = await parse_json(request, SubmitReport, 1024)
    linked = db.execute(select(MailLog, Signup).join(Signup, alias_link(auth.user_id))
                        .where(MailLog.id == data.email_id, MailLog.user_id == auth.user_id)).one_or_none()
    if linked is None:
        raise HTTPException(404, "Eligible email not found.")
    log, signup = linked
    if not signup.site_domain:
        raise HTTPException(422, "This website has no valid domain.")
    website_domain = _domain(signup.site_domain)
    if _domain(data.confirmed_domain) != website_domain:
        raise HTTPException(422, "Confirm the registered website domain shown with this email.")
    assessment = log.sender_attribution if isinstance(log.sender_attribution, dict) else classify(
        site_name=signup.site_name, site_domain=signup.site_domain, alias=log.alias,
        sender_domain=log.sender_domain, auth_results=log.auth_results,
        alias_matched=True, evaluated_at=log.received_at)
    if assessment.get("status") not in ("Suspicious", "Unknown", "Possible Third-Party Exposure"):
        raise HTTPException(422, "This email is not eligible for a community report.")
    existing = db.scalar(select(Report).where(Report.user_id == auth.user_id,
                                               Report.site_domain == website_domain))
    if existing:
        raise HTTPException(409, "You have already reported this website.")
    try:
        limit_user(db, "website_report_user", auth.user_id)
    except RateLimited:
        raise HTTPException(429, "Report limit reached. Try again later.") from None
    row = Report(user_id=auth.user_id, site_name=signup.site_name,
                 site_domain=website_domain, category=CATEGORY, status="community_reported")
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "You have already reported this website.") from None
    db.refresh(row)
    return _summary(row)


@router.get("/my")
def mine(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
         auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    where = (Report.user_id == auth.user_id, Report.site_domain.is_not(None))
    total = db.scalar(select(func.count()).select_from(Report).where(*where)) or 0
    rows = db.scalars(select(Report).where(*where).order_by(Report.created_at.desc(), Report.id.desc())
                      .limit(limit).offset(offset)).all()
    return {"items": [_summary(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/reputation")
def reputation(domain: str = Query(min_length=3, max_length=253),
               auth: AuthContext = Depends(_reputation_user), db: Session = Depends(get_db)) -> dict:
    visited = _domain(domain)
    # A report for example.com applies to www.example.com, but never to
    # notexample.com or to an unrelated sibling. Use the most specific match.
    registrable = registrable_domain(visited)
    for candidate in parent_domains(visited):
        if candidate != registrable and not candidate.endswith("." + registrable):
            continue
        count, latest, reviewing = db.execute(
            select(func.count(func.distinct(Report.user_id)), func.max(Report.created_at),
                   func.count().filter(Report.status == "under_review"))
            .where(Report.site_domain == candidate, Report.status.in_(ACTIVE),
                   Report.user_id.is_not(None))
        ).one()
        if count:
            return {"domain": visited, "reported_domain": candidate,
                    "unique_reporters": count, "status": "under_review" if reviewing else "community_reported",
                    "last_reported_at": latest}
    return {"domain": visited, "reported_domain": None, "unique_reporters": 0,
            "status": "no_reports", "last_reported_at": None}


def _admin(auth: AuthContext, db: Session) -> None:
    user = db.get(User, auth.user_id)
    if (auth.kind != "web" or not auth.email or auth.email.lower() not in settings.domain_verification_admin_emails
            or user is None or user.email_verified_at is None):
        raise HTTPException(403, "Administrator access required.")


@router.get("/review")
def review_queue(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                 auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    _admin(auth, db)
    where = (Report.site_domain.is_not(None), Report.status.in_((*ACTIVE, "dismissed")))
    total = db.scalar(select(func.count()).select_from(Report).where(*where)) or 0
    rows = db.scalars(select(Report).where(*where).order_by(Report.created_at.desc(), Report.id.desc())
                      .limit(limit).offset(offset)).all()
    return {"items": [_summary(row) for row in rows], "total": total}


@router.patch("/{report_id}/review")
async def review(report_id: int, request: Request, auth: AuthContext = Depends(require_user),
                 db: Session = Depends(get_db)) -> dict:
    _admin(auth, db)
    data = await parse_json(request, ReviewReport, 256)
    if data.status not in ("under_review", "dismissed", "community_reported"):
        raise HTTPException(422, "Unsupported review status.")
    row = db.get(Report, report_id)
    if row is None or row.site_domain is None:
        raise HTTPException(404, "Report not found.")
    row.status = data.status
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return _summary(row)
