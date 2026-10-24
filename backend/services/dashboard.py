"""Queries for the personal dashboard.

Every query is limited to the authenticated user's own records (owned_by);
records without an owner are never returned. List queries use grouped
subqueries for counts, so the number of queries does not grow with rows.
The only writes are the inbox read state of the user's own messages.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.orm import Session

from backend.models import ConsentReceipt, Incident, MailLog, Signup
from backend.services.ownership import owned_by

MATCH_STATUSES = ("matched", "ambiguous", "no_match")
SIGNUP_FILTERS = ("all", "with_receipts", "with_emails", "real_name")


# ---------- overview ----------

@dataclass(frozen=True)
class Overview:
    websites: int
    aliases: int
    nicknames: int
    receipts: int
    emails_total: int
    matched: int
    ambiguous: int
    no_match: int
    unprocessed: int
    investigations: int
    unread: int


def overview(session: Session, user_id: int) -> Overview:
    s = session.execute(
        select(func.count(), func.count(Signup.alias), func.count(Signup.nickname))
        .where(owned_by(Signup.user_id, user_id))
    ).one()
    receipts = session.scalar(select(func.count()).select_from(ConsentReceipt).where(owned_by(ConsentReceipt.user_id, user_id)))
    investigations = session.scalar(select(func.count()).select_from(Incident).where(owned_by(Incident.user_id, user_id)))
    rows = session.execute(
        select(MailLog.match_status, func.count()).where(owned_by(MailLog.user_id, user_id)).group_by(MailLog.match_status)
    ).all()
    counts = {status: count for status, count in rows}
    known = {status: counts.get(status, 0) for status in MATCH_STATUSES}
    unprocessed = sum(c for status, c in counts.items() if status not in MATCH_STATUSES)
    return Overview(
        websites=s[0], aliases=s[1], nicknames=s[2], receipts=receipts or 0, emails_total=sum(counts.values()),
        **known, unprocessed=unprocessed, investigations=investigations or 0,
        unread=unread_count(session, user_id),
    )


# ---------- My Websites ----------

@dataclass(frozen=True)
class SignupRow:
    id: int
    site_name: str
    site_domain: str | None
    alias: str | None
    nickname: str | None
    real_name_required: bool
    receipt_count: int
    email_count: int
    created_at: datetime


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _counts_subqueries(user_id: int):
    receipts = (
        select(ConsentReceipt.signup_id, func.count().label("n"))
        .where(owned_by(ConsentReceipt.user_id, user_id), ConsentReceipt.signup_id.is_not(None))
        .group_by(ConsentReceipt.signup_id).subquery()
    )
    emails = (
        select(MailLog.signup_id, func.count().label("n"))
        .where(owned_by(MailLog.user_id, user_id), MailLog.signup_id.is_not(None))
        .group_by(MailLog.signup_id).subquery()
    )
    return receipts, emails


def list_signups(
    session: Session, user_id: int, limit: int, offset: int, q: str | None = None, filter_: str = "all"
) -> tuple[list[SignupRow], int]:
    receipts, emails = _counts_subqueries(user_id)
    receipt_n = func.coalesce(receipts.c.n, 0)
    email_n = func.coalesce(emails.c.n, 0)
    query = (
        select(Signup, receipt_n, email_n)
        .outerjoin(receipts, receipts.c.signup_id == Signup.id)
        .outerjoin(emails, emails.c.signup_id == Signup.id)
        .where(owned_by(Signup.user_id, user_id))
    )
    if q:
        pattern = f"%{_escape_like(q.strip().lower())}%"
        query = query.where(or_(*(func.lower(col).like(pattern, escape="\\") for col in
                                  (Signup.site_name, Signup.site_domain, Signup.alias, Signup.nickname))))
    if filter_ == "with_receipts":
        query = query.where(receipt_n > 0)
    elif filter_ == "with_emails":
        query = query.where(email_n > 0)
    elif filter_ == "real_name":
        query = query.where(Signup.real_name_required.is_(True))
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.execute(
        query.order_by(Signup.created_at.desc(), Signup.id.desc()).limit(limit).offset(offset)
    ).all()
    items = [
        SignupRow(id=s.id, site_name=s.site_name, site_domain=s.site_domain, alias=s.alias, nickname=s.nickname,
                  real_name_required=s.real_name_required, receipt_count=r, email_count=e, created_at=s.created_at)
        for s, r, e in rows
    ]
    return items, total or 0


@dataclass(frozen=True)
class SignupDetail:
    signup: Signup
    receipts: list[ConsentReceipt]
    emails: list["EmailRow"]


def get_signup_detail(session: Session, user_id: int, signup_id: int, recent: int = 20) -> SignupDetail | None:
    signup = session.scalar(select(Signup).where(Signup.id == signup_id, owned_by(Signup.user_id, user_id)))
    if signup is None:
        return None
    receipts = session.scalars(
        select(ConsentReceipt)
        .where(owned_by(ConsentReceipt.user_id, user_id), ConsentReceipt.signup_id == signup.id)
        .order_by(ConsentReceipt.created_at.desc(), ConsentReceipt.id.desc()).limit(recent)
    ).all()
    emails = session.execute(
        _email_query(user_id).where(MailLog.signup_id == signup.id)
        .order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(recent)
    ).all()
    return SignupDetail(signup, list(receipts), [_email_row(*row) for row in emails])


# ---------- email activity ----------

@dataclass(frozen=True)
class EmailRow:
    id: int
    received_at: datetime
    created_at: datetime
    match_status: str | None
    match_confidence: str | None
    recipient_known: bool
    signup_id: int | None
    site_name: str | None
    site_domain: str | None
    sender_domain: str | None


def _email_query(user_id: int):
    return (
        select(MailLog, Signup.site_name, Signup.site_domain)
        .outerjoin(Signup, MailLog.signup_id == Signup.id)
        .where(owned_by(MailLog.user_id, user_id))
    )


def _email_row(log: MailLog, site_name: str | None, site_domain: str | None) -> EmailRow:
    return EmailRow(
        id=log.id, received_at=log.received_at, created_at=log.created_at,
        match_status=log.match_status, match_confidence=log.match_confidence,
        recipient_known=log.signup_id is not None, signup_id=log.signup_id,
        site_name=site_name, site_domain=site_domain, sender_domain=log.sender_domain,
    )


def list_emails(
    session: Session, user_id: int, limit: int, offset: int, status: str | None = None
) -> tuple[list[EmailRow], int]:
    query = _email_query(user_id)
    if status == "unprocessed":
        query = query.where(MailLog.match_status.is_(None))
    elif status is not None:
        query = query.where(MailLog.match_status == status)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows: Sequence = session.execute(
        query.order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(limit).offset(offset)
    ).all()
    return [_email_row(*row) for row in rows], total or 0


def get_email(session: Session, user_id: int, mail_log_id: int) -> EmailRow | None:
    row = session.execute(_email_query(user_id).where(MailLog.id == mail_log_id)).first()
    return _email_row(*row) if row else None


# ---------- leak investigations (matcher incidents the user chose to record) ----------

@dataclass(frozen=True)
class InvestigationRow:
    id: int
    created_at: datetime
    channel: str
    result: str | None
    confidence: str | None
    matched_site: str | None
    recipient_alias_matched: bool
    sender_domain: str | None
    candidate_count: int
    signal_types: list[str]


def _summary(evidence: dict[str, Any] | None) -> tuple[bool, str | None, int, list[str]]:
    evidence = evidence if isinstance(evidence, dict) else {}
    candidates = evidence.get("candidates") if isinstance(evidence.get("candidates"), list) else []
    signals = sorted({s for c in candidates if isinstance(c, dict) for s in (c.get("signals") or []) if isinstance(s, str)})
    sender = evidence.get("sender_domain")
    return (evidence.get("recipient_alias_matched") is True, sender if isinstance(sender, str) else None,
            len(candidates), signals)


def list_investigations(session: Session, user_id: int, limit: int, offset: int) -> tuple[list[InvestigationRow], int]:
    query = select(Incident).where(owned_by(Incident.user_id, user_id))
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit).offset(offset)).all()
    items = []
    for i in rows:
        alias_matched, sender, n, signals = _summary(i.evidence)
        items.append(InvestigationRow(
            id=i.id, created_at=i.created_at, channel=i.channel, result=i.result, confidence=i.confidence,
            matched_site=i.matched_site, recipient_alias_matched=alias_matched, sender_domain=sender,
            candidate_count=n, signal_types=signals,
        ))
    return items, total or 0


# ---------- inbox (email received at the user's aliases) ----------

INBOX_FILTERS = ("all", "unread", "matched", "unmatched", "failed")

# Linked to one of the user's signups. The join also requires the signup to be
# the user's own, so a mismatched link never reveals another account's signup.
_linked = Signup.id.is_not(None)
_tracked = MailLog.ingest_status.is_not(None)
_unread = and_(MailLog.read_at.is_(None), _tracked)
_status = case((~_linked, "unmatched"), (MailLog.ingest_status == "failed", "failed"), else_="matched")


@dataclass(frozen=True)
class InboxRow:
    id: int
    received_at: datetime
    status: str
    status_reason: str | None
    tracked: bool
    unread: bool
    read_at: datetime | None
    alias: str | None
    signup_id: int | None
    site_name: str | None
    site_domain: str | None
    identity: str | None
    identity_kind: str
    sender_name: str | None
    sender_email: str | None
    sender_domain: str | None
    subject: str | None
    auth_results: str | None
    match_status: str | None
    match_confidence: str | None


def identity_label(nickname: str | None, surname: str | None, real_name_used: bool) -> tuple[str | None, str]:
    """The name a site knows the user by, and what kind of name it is."""
    name = " ".join(part for part in (nickname, surname) if part)
    if name:
        return name, "nickname"
    if real_name_used:
        return None, "real_name"  # the real name itself is never stored
    return None, "none"


def _inbox_query(user_id: int):
    return (
        select(MailLog, Signup)
        .outerjoin(Signup, and_(MailLog.signup_id == Signup.id, owned_by(Signup.user_id, user_id)))
        .where(owned_by(MailLog.user_id, user_id))
    )


def _inbox_row(log: MailLog, signup: Signup | None) -> InboxRow:
    tracked = log.ingest_status is not None
    if signup is None:
        status, reason = "unmatched", log.status_reason or "not_linked"
    elif log.ingest_status == "failed":
        status, reason = "failed", log.status_reason or "analysis_failed"
    else:
        status, reason = "matched", None
    identity, kind = identity_label(signup.nickname, signup.surname_variant, signup.real_name_used) if signup else (None, "none")
    # Message details exist only for rows recorded by inbox tracking; older
    # rows may hold sender or subject values that were never meant to be shown.
    return InboxRow(
        id=log.id, received_at=log.received_at, status=status, status_reason=reason, tracked=tracked,
        unread=tracked and log.read_at is None, read_at=log.read_at, alias=log.alias,
        signup_id=signup.id if signup else None, site_name=signup.site_name if signup else None,
        site_domain=signup.site_domain if signup else None, identity=identity, identity_kind=kind,
        sender_name=log.sender_name if tracked else None, sender_email=log.sender if tracked else None,
        sender_domain=log.sender_domain, subject=log.subject if tracked else None,
        auth_results=log.auth_results if tracked else None,
        match_status=log.match_status, match_confidence=log.match_confidence,
    )


def unread_count(session: Session, user_id: int) -> int:
    return session.scalar(select(func.count()).select_from(MailLog).where(owned_by(MailLog.user_id, user_id), _unread)) or 0


def list_inbox(
    session: Session, user_id: int, limit: int, offset: int, filter_: str = "all"
) -> tuple[list[InboxRow], int, int]:
    """One page of the user's inbox, newest first, the filtered total, and the unread count."""
    query = _inbox_query(user_id)
    if filter_ == "unread":
        query = query.where(_unread)
    elif filter_ in ("matched", "unmatched", "failed"):
        query = query.where(_status == filter_)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.execute(query.order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(limit).offset(offset)).all()
    return [_inbox_row(*row) for row in rows], total or 0, unread_count(session, user_id)


def get_inbox_item(session: Session, user_id: int, mail_log_id: int) -> InboxRow | None:
    row = session.execute(_inbox_query(user_id).where(MailLog.id == mail_log_id)).first()
    return _inbox_row(*row) if row else None


def set_read(session: Session, user_id: int, mail_log_id: int, read: bool) -> InboxRow | None:
    """Mark one of the user's tracked messages read (keeping the first read
    time) or unread. None if it is not theirs or predates inbox tracking."""
    changed = session.execute(
        update(MailLog)
        .where(MailLog.id == mail_log_id, owned_by(MailLog.user_id, user_id), _tracked)
        .values(read_at=func.coalesce(MailLog.read_at, func.now()) if read else None)
        .returning(MailLog.id)
    ).first()
    if changed is None:
        session.rollback()
        return None
    session.commit()
    return get_inbox_item(session, user_id, mail_log_id)


def mark_all_read(session: Session, user_id: int) -> int:
    count = session.execute(
        update(MailLog).where(owned_by(MailLog.user_id, user_id), _unread).values(read_at=func.now())
    ).rowcount
    session.commit()
    return count or 0


@dataclass(frozen=True)
class InboxUpdates:
    unread: int
    latest_id: int
    new: list[InboxRow]


def inbox_updates(session: Session, user_id: int, after_id: int | None, limit: int = 10) -> InboxUpdates:
    """For polling: the unread count, the newest tracked message id, and the
    user's tracked messages recorded after `after_id` (none on the first poll)."""
    latest = session.scalar(
        select(func.max(MailLog.id)).where(owned_by(MailLog.user_id, user_id), _tracked)
    ) or 0
    new: list[InboxRow] = []
    if after_id is not None and latest > after_id:
        rows = session.execute(
            _inbox_query(user_id).where(_tracked, MailLog.id > after_id).order_by(MailLog.id.desc()).limit(limit)
        ).all()
        new = [_inbox_row(*row) for row in rows]
    return InboxUpdates(unread_count(session, user_id), latest, new)
