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
from backend.services import email_attribution
from backend.services.sender_classification import RULESET_VERSION, classify_for_email
from backend.services.sender_domain_match import assess as assess_sender_domain
from backend.services.email_attribution import alias_link as _alias_link
from backend.services.ownership import owned_by
from backend.services.sender_classification import classify as classify_sender

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
    unmatched: int
    failed: int
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
        select(_status, func.count()).select_from(MailLog).outerjoin(Signup, _alias_link(user_id))
        .where(owned_by(MailLog.user_id, user_id)).group_by(_status)
    ).all()
    counts = dict(rows)
    known = {status: counts.get(status, 0) for status in ("matched", "unmatched", "failed")}
    unprocessed = counts.get("unprocessed", 0)
    # Retained for older clients; these are source-analysis counts, not attribution.
    legacy = dict(session.execute(select(MailLog.match_status, func.count())
        .where(owned_by(MailLog.user_id, user_id)).group_by(MailLog.match_status)).all())
    return Overview(
        websites=s[0], aliases=s[1], nicknames=s[2], receipts=receipts or 0, emails_total=sum(counts.values()),
        **known, ambiguous=legacy.get("ambiguous", 0), no_match=legacy.get("no_match", 0), unprocessed=unprocessed, investigations=investigations or 0,
        unread=unread_count(session, user_id),
    )


# ---------- My Websites ----------

@dataclass(frozen=True)
class SignupRow:
    id: int
    site_name: str
    site_domain: str | None
    alias_status: str
    alias_status_changed_at: datetime
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
        select(MailLog.signup_id, func.count().label("n")).join(Signup, _alias_link(user_id))
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
        SignupRow(id=s.id, site_name=s.site_name, site_domain=s.site_domain,
                  alias_status=s.alias_status, alias_status_changed_at=s.alias_status_changed_at,
                  alias=s.alias, nickname=s.nickname,
                  real_name_required=s.real_name_required, receipt_count=r, email_count=e, created_at=s.created_at)
        for s, r, e in rows
    ]
    return items, total or 0


@dataclass(frozen=True)
class SignupDetail:
    signup: Signup
    receipts: list[ConsentReceipt]
    emails: list["EmailRow"]
    sms: list[Incident]


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
        _email_query(user_id).where(Signup.id == signup.id)
        .order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(recent)
    ).all()
    from backend.services.sms_investigations import linked_to_signup
    owned = _owned_signups(session, user_id)
    return SignupDetail(signup, list(receipts), [_email_row(*row, owned) for row in emails],
                        linked_to_signup(session, user_id, signup.id, recent))


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
    status: str
    status_reason: str | None
    alias: str | None
    unread: bool
    exposure: list[dict]
    tracked: bool
    subject: str | None
    sender_name: str | None
    sender_email: str | None
    auth_results: str | None
    sender_attribution: dict | None
    domain_match: dict


def _email_query(user_id: int):
    return (
        select(MailLog, Signup)
        .outerjoin(Signup, _alias_link(user_id))
        .where(owned_by(MailLog.user_id, user_id))
    )


def _email_row(log: MailLog, signup: Signup | None, owned_signups: list[Signup]) -> EmailRow:
    site_name = signup.site_name if signup else None
    site_domain = signup.site_domain if signup else None
    tracked = log.ingest_status is not None
    return EmailRow(
        id=log.id, received_at=log.received_at, created_at=log.created_at,
        match_status=log.match_status, match_confidence=log.match_confidence,
        recipient_known=site_name is not None, signup_id=log.signup_id if site_name is not None else None,
        site_name=site_name, site_domain=site_domain, sender_domain=log.sender_domain,
        status=_effective_status(log, site_name is not None),
        status_reason=_status_reason(log, site_name is not None), alias=log.alias,
        unread=log.ingest_status is not None and log.read_at is None,
        exposure=email_attribution.email_exposure(log, signup, owned_signups),
        tracked=tracked, subject=log.subject if tracked else None,
        sender_name=log.sender_name if tracked else None,
        sender_email=log.sender if tracked else None,
        auth_results=log.auth_results if tracked else None,
        sender_attribution=log.sender_attribution or classify_sender(
            site_name=site_name, site_domain=site_domain, alias=log.alias,
            sender_address=log.sender if tracked else None,
            sender_domain=log.sender_domain, auth_results=log.auth_results if tracked else None,
            alias_matched=site_name is not None and _effective_status(log, True) == "matched",
            evaluated_at=log.received_at,
        ),
        domain_match=assess_sender_domain(
            site_domain=site_domain, sender_address=log.sender if tracked else None,
            stored_sender_domain=log.sender_domain,
            alias_matched=bool(site_name and _effective_status(log, True) == "matched"),
        ),
    )


def _owned_signups(session: Session, user_id: int) -> list[Signup]:
    return list(session.scalars(select(Signup).where(owned_by(Signup.user_id, user_id))).all())


def list_emails(
    session: Session, user_id: int, limit: int, offset: int, status: str | None = None
) -> tuple[list[EmailRow], int]:
    query = _email_query(user_id)
    if status in ("matched", "unmatched", "failed", "unprocessed"):
        query = query.where(_status == status)
    elif status is not None:  # compatibility for old clients' analysis-only filters
        query = query.where(MailLog.match_status == status)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows: Sequence = session.execute(
        query.order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(limit).offset(offset)
    ).all()
    owned = _owned_signups(session, user_id)
    return [_email_row(*row, owned) for row in rows], total or 0


def get_email(session: Session, user_id: int, mail_log_id: int) -> EmailRow | None:
    row = session.execute(_email_query(user_id).where(MailLog.id == mail_log_id)).first()
    return _email_row(*row, _owned_signups(session, user_id)) if row else None


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

INBOX_FILTERS = ("all", "unread", "matched", "unmatched", "failed", "unprocessed")

# Linked to one of the user's signups. The join also requires the signup to be
# the user's own, so a mismatched link never reveals another account's signup.
_linked = Signup.id.is_not(None)
_tracked = MailLog.ingest_status.is_not(None)
_unread = and_(MailLog.read_at.is_(None), _tracked)
_status = case((MailLog.ingest_status == "failed", "failed"),
               (MailLog.ingest_status.is_(None), "unprocessed"),
               (and_(MailLog.ingest_status == "matched", _linked), "matched"), else_="unmatched")


def _effective_status(log: MailLog, linked: bool) -> str:
    return email_attribution.effective_status(log.ingest_status, linked)


def _status_reason(log: MailLog, linked: bool) -> str | None:
    return email_attribution.status_reason(log.ingest_status, linked, log.status_reason)


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
    exposure: list[dict]
    sender_attribution: dict | None
    domain_match: dict
    attribution_pending: bool


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
        .outerjoin(Signup, _alias_link(user_id))
        .where(owned_by(MailLog.user_id, user_id))
    )


def _inbox_row(log: MailLog, signup: Signup | None, owned_signups: list[Signup]) -> InboxRow:
    tracked = log.ingest_status is not None
    status = _effective_status(log, signup is not None)
    reason = _status_reason(log, signup is not None)
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
        exposure=email_attribution.email_exposure(log, signup, owned_signups),
        sender_attribution=log.sender_attribution or classify_sender(
            site_name=signup.site_name if signup else None,
            site_domain=signup.site_domain if signup else None, alias=log.alias,
            sender_address=log.sender if tracked else None,
            sender_domain=log.sender_domain, auth_results=log.auth_results if tracked else None,
            alias_matched=bool(signup and status == "matched"), evaluated_at=log.received_at,
        ),
        domain_match=assess_sender_domain(
            site_domain=signup.site_domain if signup else None,
            sender_address=log.sender if tracked else None,
            stored_sender_domain=log.sender_domain,
            alias_matched=bool(signup and status == "matched"),
        ),
        attribution_pending=bool(signup and status == "matched" and signup.site_domain
                                 and log.sender_domain and (not isinstance(log.sender_attribution, dict)
                                 or log.sender_attribution.get("ruleset_version") != RULESET_VERSION)),
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
    elif filter_ in ("matched", "unmatched", "failed", "unprocessed"):
        query = query.where(_status == filter_)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.execute(query.order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(limit).offset(offset)).all()
    owned = _owned_signups(session, user_id)
    return [_inbox_row(*row, owned) for row in rows], total or 0, unread_count(session, user_id)


def get_inbox_item(session: Session, user_id: int, mail_log_id: int) -> InboxRow | None:
    row = session.execute(_inbox_query(user_id).where(MailLog.id == mail_log_id)).first()
    return _inbox_row(*row, _owned_signups(session, user_id)) if row else None


def reevaluate_inbox(session: Session, user_id: int, limit: int, offset: int,
                     mail_log_ids: list[int] | None = None) -> dict:
    """Bounded, user-scoped refresh. Recent snapshots are reused for one hour."""
    from datetime import timedelta, timezone
    now = datetime.now(timezone.utc)
    query = _inbox_query(user_id).where(MailLog.ingest_status == "matched", _linked)
    if mail_log_ids is not None:
        query = query.where(MailLog.id.in_(mail_log_ids))
        offset = 0
    rows = session.execute(query.order_by(MailLog.received_at.desc(), MailLog.id.desc())
                           .limit(limit).offset(offset)).all()
    refreshed = skipped = 0
    for log, signup in rows:
        previous = log.sender_attribution if isinstance(log.sender_attribution, dict) else {}
        try:
            evaluated = datetime.fromisoformat(previous.get("evaluated_at", ""))
        except (ValueError, TypeError):
            evaluated = None
        if (previous.get("ruleset_version") == RULESET_VERSION and evaluated and
                evaluated.tzinfo and now - evaluated < timedelta(hours=1) and
                "Evidence expired" not in (previous.get("evidence_status") or {}).values()):
            skipped += 1
            continue
        log.sender_attribution = classify_for_email(
            session, site_name=signup.site_name, site_domain=signup.site_domain,
            alias=log.alias, sender_domain=log.sender_domain, sender_address=log.sender,
            auth_results=log.auth_results, alias_matched=True, evaluated_at=now,
            correlation_id=str(log.id),
        )
        refreshed += 1
    session.commit()
    return {"refreshed": refreshed, "skipped": skipped, "limit": limit, "offset": offset}


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
        owned = _owned_signups(session, user_id)
        new = [_inbox_row(*row, owned) for row in rows]
    return InboxUpdates(unread_count(session, user_id), latest, new)


# ---------- cross-channel timeline ----------

@dataclass(frozen=True)
class TimelineItem:
    channel: str
    id: int
    at: datetime
    title: str
    status: str | None
    site_name: str | None
    signup_id: int | None
    linked: bool


def timeline(session: Session, user_id: int, limit: int = 30) -> list[TimelineItem]:
    """The user's email and saved SMS investigations, newest first.

    An item is linked to a website only by an exact alias (email) or by the
    user's own confirmation (SMS); a shared company name never links records.
    """
    items: list[TimelineItem] = []
    mail = session.execute(
        select(MailLog, Signup).outerjoin(Signup, _alias_link(user_id))
        .where(owned_by(MailLog.user_id, user_id)).order_by(MailLog.received_at.desc(), MailLog.id.desc()).limit(limit)
    ).all()
    for log, signup in mail:
        items.append(TimelineItem(
            "email", log.id, log.received_at, f"Email to {log.alias}" if log.alias else "Email",
            _effective_status(log, signup is not None), signup.site_name if signup else None, signup.id if signup else None,
            signup is not None,
        ))
    sms = session.scalars(
        select(Incident).where(owned_by(Incident.user_id, user_id), Incident.channel == "sms",
                               Incident.evidence["source"].astext == "sms_analyzer")
        .order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit)
    ).all()
    for incident in sms:
        evidence = incident.evidence or {}
        confirmed = evidence.get("confirmed") or {}
        sender_type = (evidence.get("sender") or {}).get("type")
        title = {"phone": "SMS from a phone number", "short_code": "SMS from a short code",
                 "alphanumeric": f"SMS from {(evidence.get('sender') or {}).get('value')}",
                 "email": "SMS from an email address"}.get(sender_type, "SMS from an unknown sender")
        # When the user said they received it, else when it was saved.
        at = incident.created_at
        if evidence.get("received_at"):
            try:
                at = datetime.fromisoformat(evidence["received_at"])
            except ValueError:
                pass
        items.append(TimelineItem(
            "sms", incident.id, at, title, incident.result, incident.matched_site,
            confirmed.get("signup_id") if isinstance(confirmed.get("signup_id"), int) else None, bool(confirmed),
        ))
    items.sort(key=lambda i: (i.at, i.id), reverse=True)
    return items[:limit]
