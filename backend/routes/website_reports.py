"""Authenticated community observations and exact-hostname reputation."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import WebsiteReport
from backend.routes.common import parse_json, TOO_MANY
from backend.security import client_ip, get_auth_context, require_scope
from backend.services import auth as auth_service
from backend.services.auth import AuthContext, RateLimited
from backend.services.domains import normalize_domain
from backend.models.website_report import CATEGORIES

router = APIRouter(prefix="/website-reports", tags=["website reports"])


def normalize_report_domain(value: str) -> str:
    """Treat the conventional www host and its base as one reported website.

    Other subdomains remain distinct, so a report for example.com does not
    attach to accounts.example.com.
    """
    domain = normalize_domain(value)
    return domain[4:] if domain.startswith("www.") else domain


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str
    category: str

    @field_validator("domain")
    @classmethod
    def domain_name(cls, value: str) -> str:
        return normalize_report_domain(value)

    @field_validator("category")
    @classmethod
    def category_name(cls, value: str) -> str:
        if value not in CATEGORIES:
            raise ValueError("Choose a supported finding category.")
        return value


def _reputation(db: Session, domain: str) -> dict:
    rows = db.execute(
        select(WebsiteReport.category, WebsiteReport.verification_status, func.count())
        .where(WebsiteReport.domain == domain, WebsiteReport.verification_status != "rejected")
        .group_by(WebsiteReport.category, WebsiteReport.verification_status)
    ).all()
    categories = []
    for category in CATEGORIES:
        unverified = sum(n for c, status, n in rows if c == category and status == "unverified")
        verified = sum(n for c, status, n in rows if c == category and status == "verified")
        if unverified or verified:
            categories.append({"category": category, "unverified_count": unverified, "verified_count": verified})
    reporter_count = db.scalar(select(func.count(func.distinct(WebsiteReport.reporter_user_id))).where(
        WebsiteReport.domain == domain, WebsiteReport.verification_status != "rejected")) or 0
    return {"domain": domain, "report_count": sum(c["unverified_count"] + c["verified_count"] for c in categories),
            "reporter_count": reporter_count,
            "unverified_count": sum(c["unverified_count"] for c in categories),
            "verified_count": sum(c["verified_count"] for c in categories), "categories": categories}


def require_reputation_auth(auth: AuthContext | None = Depends(get_auth_context)) -> AuthContext:
    if auth is None or auth.kind not in ("web", "extension"):
        raise HTTPException(401, "Sign in required.")
    return auth


@router.get("/reputation")
def reputation(response: Response, auth: AuthContext = Depends(require_reputation_auth),
               domain: str = Query(max_length=253), db: Session = Depends(get_db)) -> dict:
    try:
        domain = normalize_report_domain(domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    response.headers["Cache-Control"] = "no-store"
    return _reputation(db, domain)


@router.post("", status_code=201)
async def submit(request: Request, response: Response, auth: AuthContext = Depends(require_scope("reports:create")),
                 db: Session = Depends(get_db)) -> dict:
    data = await parse_json(request, Submission, 1024)
    existing = db.scalar(select(WebsiteReport).where(
        WebsiteReport.reporter_user_id == auth.user_id, WebsiteReport.domain == data.domain,
        WebsiteReport.category == data.category))
    if existing is not None:
        response.status_code = 200
        response.headers["Cache-Control"] = "no-store"
        return {"id": existing.id, "domain": data.domain, "category": data.category,
                "verification_status": existing.verification_status, "already_reported": True}
    try:
        auth_service.check_rate(db, "website_report_user", str(auth.user_id))
        auth_service.check_rate(db, "website_report_ip", client_ip(request))
    except RateLimited:
        raise TOO_MANY from None
    row = WebsiteReport(domain=data.domain, category=data.category, reporter_user_id=auth.user_id,
                        verification_status="unverified")
    db.add(row)
    try:
        db.flush()
        auth_service.record_event(db, "website_report_user", str(auth.user_id))
        auth_service.record_event(db, "website_report_ip", client_ip(request))
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(WebsiteReport).where(
            WebsiteReport.reporter_user_id == auth.user_id, WebsiteReport.domain == data.domain,
            WebsiteReport.category == data.category))
        if existing is None:
            raise
        response.status_code = 200
        response.headers["Cache-Control"] = "no-store"
        return {"id": existing.id, "domain": data.domain, "category": data.category,
                "verification_status": existing.verification_status, "already_reported": True}
    response.headers["Cache-Control"] = "no-store"
    return {"id": row.id, "domain": row.domain, "category": row.category,
            "verification_status": row.verification_status, "already_reported": False}
