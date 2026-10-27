"""Responses shared by the dashboard API and the mobile API.

Both serve the signed-in user's websites, email activity and timeline in the
same shapes, so the query parameters, the fields returned and every decision
about what is left out live here once. Callers authenticate the request; each
function takes the authenticated user id and the services filter by it.

This module imports no router, so it adds no routes and no local-only checks.
"""

from typing import Literal

from fastapi import Query
from sqlalchemy.orm import Session

from backend.schemas.dashboard import (
    DashboardEmail,
    DashboardEmailDetail,
    DashboardEmailPage,
    DashboardSignup,
    DashboardSignupPage,
    SignupDetailResponse,
    SignupReceipt,
    SignupSms,
    Timeline,
    TimelineItem,
)
from backend.schemas.signup import MAX_BIGINT
from backend.services import dashboard, matcher

MAX_PAGE_SIZE = 100

Limit = Query(20, ge=1, le=MAX_PAGE_SIZE)
Offset = Query(0, ge=0, le=MAX_BIGINT)
TimelineLimit = Query(30, ge=1, le=MAX_PAGE_SIZE)
SignupSearch = Query(None, max_length=100, description="Search site name, domain, alias or nickname.")
SignupFilter = Literal["all", "with_receipts", "with_emails", "real_name"]
EmailStatus = Literal["matched", "unmatched", "failed", "unprocessed", "ambiguous", "no_match"]

SIGNUP_NOT_FOUND = "Not found"
EMAIL_NOT_FOUND = "Email record not found"


def signup_page(db: Session, user_id: int, limit: int, offset: int, q: str | None,
                filter_: SignupFilter) -> DashboardSignupPage:
    items, total = dashboard.list_signups(db, user_id, limit, offset, q, filter_)
    return DashboardSignupPage(items=[DashboardSignup.model_validate(i) for i in items], total=total, limit=limit,
                               offset=offset)


def signup_detail(db: Session, user_id: int, signup_id: int) -> SignupDetailResponse | None:
    detail = dashboard.get_signup_detail(db, user_id, signup_id)
    if detail is None:
        return None
    s = detail.signup
    return SignupDetailResponse(
        id=s.id, site_name=s.site_name, site_domain=s.site_domain, alias_status=s.alias_status,
        alias_status_changed_at=s.alias_status_changed_at,
        block_promotional_emails=s.block_promotional_emails, alias=s.alias, nickname=s.nickname,
        surname_variant=s.surname_variant, real_name_required=s.real_name_required, real_name_used=s.real_name_used,
        created_at=s.created_at,
        receipts=[SignupReceipt(
            id=r.id, action=r.action, evidence_basis="user_reported" if r.capture_source == "manual" else "unknown",
            recorded_at=r.created_at, reported_occurred_at=r.reported_occurred_at, source_url=r.source_url,
        ) for r in detail.receipts],
        emails=[DashboardEmail.model_validate(e) for e in detail.emails],
        sms_investigations=[SignupSms(
            id=i.id, created_at=i.created_at, status=i.result,
            confirmed=((i.evidence or {}).get("confirmed") or {}).get("signup_id") == s.id,
        ) for i in detail.sms],
    )


def email_page(db: Session, user_id: int, limit: int, offset: int, status: EmailStatus | None) -> DashboardEmailPage:
    items, total = dashboard.list_emails(db, user_id, limit, offset, status)
    return DashboardEmailPage(items=[DashboardEmail.model_validate(i) for i in items], total=total, limit=limit,
                              offset=offset)


def email_detail(db: Session, user_id: int, mail_log_id: int) -> DashboardEmailDetail | None:
    row = dashboard.get_email(db, user_id, mail_log_id)
    if row is None:
        return None
    return DashboardEmailDetail(**vars(row), limitations=list(matcher.LIMITATIONS))


def timeline(db: Session, user_id: int, limit: int) -> Timeline:
    return Timeline(items=[TimelineItem.model_validate(i) for i in dashboard.timeline(db, user_id, limit)])
