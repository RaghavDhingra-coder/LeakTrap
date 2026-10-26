"""Investigate which website or service an SMS relates to.

Evidence comes only from the message text, the sender the user typed, and
the user's own LeakTrace records. Every candidate lists the signals behind it
and what remains unknown. Statuses:

- "confirmed": the user explicitly confirmed this source (saved investigations
  only; see sms_investigations.py);
- "strong": two or more independent kinds of evidence agree;
- "possible": one kind of evidence;
- "unknown": nothing reliable.

The sender delivered the message; it is never treated as the service that
collected the user's details. A match never shows how a service obtained a
phone number or whether data was leaked.
"""

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import Incident, MailLog, Signup
from backend.services import sms_extract
from backend.services.email_attribution import alias_link
from backend.services.domains import normalize_domain, normalize_email, parent_domains
from backend.services.ownership import owned_by
from backend.services.sms_extract import Entity, Extraction

logger = logging.getLogger("leaktrace.sms")

STATUS_ORDER = ("unknown", "possible", "strong", "confirmed")
MAX_CANDIDATES = 8
MAX_SIGNUPS_SCANNED = 5000
ADDABLE_TYPES = ("email", "phone", "domain", "business", "person")

ALWAYS_UNKNOWN = (
    "The message does not show how the sender obtained your phone number, or whether "
    "this service shared it with anyone."
)


@dataclass
class SourceSignal:
    type: str
    category: str
    explanation: str
    excerpt: str | None = None
    weak: bool = False


@dataclass
class SourceCandidate:
    key: str
    name: str
    domain: str | None
    signup_id: int | None
    status: str = "unknown"
    signals: list[SourceSignal] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    email_count: int | None = None
    last_email_at: datetime | None = None
    sms_count: int | None = None


@dataclass
class IdentifierFinding:
    entity_key: str
    relation: str
    signup_id: int | None = None


@dataclass
class Analysis:
    extraction: Extraction
    entities: list[Entity]
    excluded: set[str]
    sender: dict | None
    sender_notes: list[str]
    received_at: datetime | None
    label: str | None
    status: str
    candidates: list[SourceCandidate]
    identifiers: list[IdentifierFinding]
    missing: list[str]
    warnings: list[str]
    dedup_key: str
    risk: dict | None = None


def _compress(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _phrase_span(text: str, phrase: str) -> tuple[int, int] | None:
    m = re.search(rf"(?<![\w]){re.escape(phrase)}(?![\w])", text, re.IGNORECASE)
    return (m.start(), m.end()) if m else None


def _usable_name(name: str | None) -> bool:
    if not name or len(name.strip()) < 3:
        return False
    return not all(w.lower() in sms_extract.GENERIC_WORDS for w in name.split())


def added_entity(index: int, type_: str, raw: str) -> Entity:
    """An entity the user added by hand. Raises ValueError if invalid."""
    value = " ".join(sms_extract.normalize_text(raw).split())
    if type_ == "email":
        value = normalize_email(value)
        domain = sms_extract.registrable_domain(value.split("@", 1)[1])
        return Entity(f"added:{index}", "email", sms_extract.mask_email(value), "user_added", value,
                      meta={"domain": domain, "freemail": domain in sms_extract.FREEMAIL_DOMAINS})
    if type_ == "phone":
        phone = sms_extract.normalize_phone(value)
        if not phone:
            raise ValueError("enter a phone number with 9 to 15 digits")
        return Entity(f"added:{index}", "phone", sms_extract.mask_digits(phone[0]), "user_added", phone[0],
                      meta={"format": phone[1]})
    if type_ == "domain":
        domain = normalize_domain(value.removeprefix("https://").removeprefix("http://").split("/")[0])
        return Entity(f"added:{index}", "domain", domain, "user_added", domain,
                      meta={"domain": sms_extract.registrable_domain(domain)})
    if type_ in ("business", "person"):
        if not 2 <= len(value) <= 100 or not re.search(r"[A-Za-z]", value):
            raise ValueError("enter 2 to 100 characters including a letter")
        return Entity(f"added:{index}", type_, value, "user_added", value)
    raise ValueError(f"type must be one of {', '.join(ADDABLE_TYPES)}")


def dedup_key(user_id: int, text: str, sender: dict | None, received_at: datetime | None) -> str:
    basis = "\n".join([str(user_id), " ".join(text.split()), sms_extract.sender_key(sender) or "",
                       received_at.isoformat() if received_at else ""])
    return hashlib.sha256(basis.encode()).hexdigest()


def _confirmed_by_sender(session: Session, user_id: int, key: str | None) -> dict[int, int]:
    """signup_id -> number of earlier saved SMS investigations from this sender
    that the user confirmed as relating to that website."""
    if not key:
        return {}
    rows = session.scalars(
        select(Incident.evidence).where(
            owned_by(Incident.user_id, user_id), Incident.channel == "sms",
            Incident.evidence["sender_key"].astext == key,
        ).limit(200)
    ).all()
    counts: dict[int, int] = defaultdict(int)
    for evidence in rows:
        confirmed = (evidence or {}).get("confirmed") or {}
        if isinstance(confirmed.get("signup_id"), int):
            counts[confirmed["signup_id"]] += 1
    return dict(counts)


def _quote(extraction: Extraction, e: Entity) -> str | None:
    """A redacted quotation around an entity; None for entities the user added."""
    return None if e.certainty == "user_added" else sms_extract.excerpt(extraction, e.start, e.end)


def _status(signals: list[SourceSignal]) -> str:
    if not signals:
        return "unknown"
    categories = {s.category for s in signals if not s.weak}
    return "strong" if len(categories) >= 2 else "possible"


def investigate(
    session: Session, user_id: int, account_email: str | None, text: str, *, sender_raw: str | None = None,
    received_at: datetime | None = None, label: str | None = None, exclude: set[str] | None = None,
    additions: list[tuple[str, str]] | None = None, alias_domain: str | None = None,
) -> Analysis:
    extraction = sms_extract.extract(text)
    sender = sms_extract.parse_sender(sender_raw)
    entities = list(extraction.entities) + [added_entity(i, t, v) for i, (t, v) in enumerate(additions or [])]
    excluded = {k for k in (exclude or set()) if any(e.key == k for e in entities)}
    active = [e for e in entities if e.key not in excluded]
    body = extraction.text
    warnings: list[str] = []

    signups = session.scalars(
        select(Signup).where(owned_by(Signup.user_id, user_id)).order_by(Signup.id).limit(MAX_SIGNUPS_SCANNED)
    ).all()
    by_id = {s.id: s for s in signups}
    emails = [e for e in active if e.type == "email"]
    hosts = [(e, e.meta.get("host") or e.value) for e in active if e.type in ("url", "domain") and (e.meta.get("host") or e.value)]
    domain_entities = [(e, h) for e, h in hosts if not e.meta.get("shortener") and not e.meta.get("ip")]
    for e in active:
        if e.type == "url" and e.meta.get("shortener"):
            warnings.append("A shortened link hides its destination; it was not opened and is not used as evidence.")
            break
    service_emails = [e for e in emails if not e.meta.get("freemail")
                      and not (alias_domain and e.value.endswith(f"@{alias_domain}"))]
    businesses = [e for e in active if e.type == "business"]
    people = [e for e in active if e.type == "person"]
    consumed: set[str] = set()

    # ---------- candidates from the user's own websites ----------
    candidates: dict[str, SourceCandidate] = {}
    name_hits: dict[int, tuple[int, int]] = {}
    for s in signups:
        if _usable_name(s.site_name):
            span = _phrase_span(body, s.site_name)
            if span:
                name_hits[s.id] = span
    # A longer name that matches wins over a shorter one it contains ("Example Shop Plus" over "Example Shop").
    for a in list(name_hits):
        for b_id in list(name_hits):
            if a != b_id and a in name_hits and b_id in name_hits:
                na, nb = by_id[a].site_name.lower(), by_id[b_id].site_name.lower()
                if na != nb and na in nb:
                    del name_hits[a]
    duplicate_names = defaultdict(list)
    for sid in name_hits:
        duplicate_names[by_id[sid].site_name.lower()].append(sid)

    prior = _confirmed_by_sender(session, user_id, sms_extract.sender_key(sender))
    for s in signups:
        signals: list[SourceSignal] = []
        alias = (s.alias or "").lower()
        for e in emails:
            if alias and e.value == alias:
                signals.append(SourceSignal("alias_in_message", "leaktrace_marker",
                    "The message contains the alias LeakTrace generated for this website.", _quote(extraction, e)))
                consumed.add(e.key)
        if s.nickname and _usable_name(s.nickname):
            span = _phrase_span(body, s.nickname)
            if span or any(p.value.lower().split()[0] == s.nickname.lower() for p in people if p.value):
                signals.append(SourceSignal("nickname_in_message", "leaktrace_marker",
                    "The nickname you gave only to this website appears in the message.",
                    sms_extract.excerpt(extraction, *span) if span else None))
        if s.surname_variant and len(s.surname_variant) >= 3:
            span = _phrase_span(body, s.surname_variant)
            if span:
                signals.append(SourceSignal("surname_in_message", "leaktrace_marker_weak",
                    "The surname variant you gave this website appears. Surname variants are not unique, so this is weak evidence.",
                    sms_extract.excerpt(extraction, *span), weak=True))
        if s.site_domain:
            for e, host in domain_entities + [(e, e.value.split("@", 1)[1]) for e in service_emails]:
                if s.site_domain in parent_domains(host) or sms_extract.registrable_domain(host) == sms_extract.registrable_domain(s.site_domain):
                    signals.append(SourceSignal("domain_in_message", "domain",
                        f"The message mentions {sms_extract.registrable_domain(host)}, the domain of this website. Anyone can mention a domain, so this alone does not prove the message came from it.",
                        _quote(extraction, e)))
                    consumed.add(e.key)
                    break
        if s.id in name_hits:
            ambiguous = len(duplicate_names[s.site_name.lower()]) > 1
            signals.append(SourceSignal("name_in_message", "name",
                f"The message mentions “{s.site_name}”, the name of this website."
                + (" Another of your websites has the same name, so this is ambiguous." if ambiguous else ""),
                sms_extract.excerpt(extraction, *name_hits[s.id]), weak=ambiguous))
            for biz in businesses:
                if biz.value and _compress(biz.value) == _compress(s.site_name):
                    consumed.add(biz.key)
        if prior.get(s.id):
            signals.append(SourceSignal("sender_previously_confirmed", "user_confirmation",
                f"You confirmed {prior[s.id]} earlier message{'s' if prior[s.id] > 1 else ''} from this sender as relating to this website."))
        if sender and sender["type"] == "alphanumeric" and _compress(sender["value"]) and _compress(sender["value"]) == _compress(s.site_name):
            signals.append(SourceSignal("sender_id_name", "sender",
                "The sender ID matches this website's name. Sender IDs are not verified and can be spoofed.", weak=True))
        if signals:
            candidates[f"signup:{s.id}"] = SourceCandidate(f"signup:{s.id}", s.site_name, s.site_domain, s.id, signals=signals)

    # ---------- services named in the message that are not the user's websites ----------
    groups: dict[str, SourceCandidate] = {}
    for e, host in [(e, h) for e, h in domain_entities if e.key not in consumed] + \
                   [(e, e.value.split("@", 1)[1]) for e in service_emails if e.key not in consumed]:
        domain = sms_extract.registrable_domain(host)
        if alias_domain and domain == sms_extract.registrable_domain(alias_domain):
            continue
        cand = groups.setdefault(f"domain:{domain}", SourceCandidate(f"domain:{domain}", domain, domain, None))
        if not any(s.type == "domain_in_message" for s in cand.signals):
            what = "an email address at" if e.type == "email" else "a link to" if e.type == "url" else "the domain"
            cand.signals.append(SourceSignal("domain_in_message", "domain",
                f"The message contains {what} {domain}.", _quote(extraction, e)))
    for biz in businesses:
        if biz.key in consumed or not biz.value:
            continue
        label_ = _compress(biz.value)
        target = None
        for cand in groups.values():
            first = _compress(cand.domain.split(".")[0])
            if len(label_) >= 4 and len(first) >= 4 and (label_ == first or label_ in first or first in label_):
                target = cand
                break
        if target is None:
            key = f"name:{label_}"
            target = groups.setdefault(key, SourceCandidate(key, biz.value, None, None))
        else:
            target.name = biz.value
        if not any(s.type == "name_in_message" for s in target.signals):
            target.signals.append(SourceSignal("name_in_message", "name",
                f"The message names “{biz.value}”. {biz.note or ''}".strip(),
                _quote(extraction, biz)))
    candidates.update(groups)

    # ---------- statuses, unknowns and related records ----------
    for cand in candidates.values():
        cand.status = _status(cand.signals)
        cand.unknowns.append(ALWAYS_UNKNOWN)
        types = {s.type for s in cand.signals}
        if cand.signup_id is None:
            cand.unknowns.append("This service is not one of your LeakTrace websites, so there is no record of you signing up to it.")
        elif not types & {"alias_in_message", "nickname_in_message"}:
            cand.unknowns.append("No LeakTrace alias or nickname for this website appears in the message.")
        if types <= {"domain_in_message", "name_in_message", "sender_id_name"}:
            cand.unknowns.append("Anyone can mention a company name or link, so the message may not come from this service.")
        if any(e.type == "url" for e in active):
            cand.unknowns.append("Links were not opened, so where they lead is unverified.")
    ranked = sorted(candidates.values(), key=lambda c: (-STATUS_ORDER.index(c.status), c.signup_id is None, c.name.lower()))
    if len(ranked) > MAX_CANDIDATES:
        warnings.append(f"Only the {MAX_CANDIDATES} best-supported services are shown.")
        ranked = ranked[:MAX_CANDIDATES]
    _related_activity(session, user_id, [c for c in ranked if c.signup_id])

    strong = [c for c in ranked if c.status == "strong"]
    if len(strong) > 1:
        status = "possible"
        warnings.append("The evidence points to more than one service, so no single source is suggested.")
    elif strong:
        status = "strong"
    elif ranked:
        status = "possible"
        if len(ranked) > 1:
            warnings.append("Several services are mentioned; none has enough evidence on its own.")
    else:
        status = "unknown"

    identifiers = _identifier_findings(active, signups, account_email, alias_domain)
    missing = [] if ranked else _missing_evidence(active, sender, prior)
    sender_notes = _sender_notes(sender)
    logger.info("SMS analysis: entities=%d candidates=%d status=%s", len(active), len(ranked), status)
    from backend.services.sms_risk import assess
    risk = assess(extraction, entities, excluded, ranked, signups)
    return Analysis(extraction, entities, excluded, sender, sender_notes, received_at, label, status, ranked,
                    identifiers, missing, warnings, dedup_key(user_id, extraction.text, sender, received_at), risk)


def _related_activity(session: Session, user_id: int, candidates: list[SourceCandidate]) -> None:
    ids = [c.signup_id for c in candidates]
    if not ids:
        return
    mail = dict((sid, (n, last)) for sid, n, last in session.execute(
        select(MailLog.signup_id, func.count(), func.max(MailLog.received_at)).join(Signup, alias_link(user_id))
        .where(owned_by(MailLog.user_id, user_id), MailLog.signup_id.in_(ids)).group_by(MailLog.signup_id)
    ).all())
    for cand in candidates:
        n, last = mail.get(cand.signup_id, (0, None))
        cand.email_count, cand.last_email_at = n, last
        cand.sms_count = session.scalar(
            select(func.count()).select_from(Incident).where(
                owned_by(Incident.user_id, user_id), Incident.channel == "sms",
                Incident.evidence.contains({"candidates": [{"signup_id": cand.signup_id}]}),
            )
        ) or 0


def _identifier_findings(active: list[Entity], signups, account_email: str | None,
                         alias_domain: str | None) -> list[IdentifierFinding]:
    aliases = {(s.alias or "").lower(): s for s in signups if s.alias}
    nicknames = {(s.nickname or "").lower(): s for s in signups if s.nickname}
    findings = []
    for e in active:
        if e.type == "email":
            if account_email and e.value == account_email.lower():
                findings.append(IdentifierFinding(e.key, "Your LeakTrace account email address."))
            elif e.value in aliases:
                s = aliases[e.value]
                findings.append(IdentifierFinding(e.key, f"Your LeakTrace alias for {s.site_name}.", s.id))
            elif alias_domain and e.value.endswith(f"@{alias_domain}"):
                findings.append(IdentifierFinding(e.key, "An address at your alias domain that is not one of your aliases."))
            elif e.meta.get("freemail"):
                findings.append(IdentifierFinding(e.key, "A personal webmail address; it does not indicate a service."))
        elif e.type == "phone":
            findings.append(IdentifierFinding(e.key, "LeakTrace does not store phone numbers, so it cannot tell where this number was shared."))
        elif e.type == "person" and e.value:
            first = e.value.split()[0].lower()
            if first in nicknames:
                s = nicknames[first]
                findings.append(IdentifierFinding(e.key, f"The nickname you use only for {s.site_name}.", s.id))
    return findings


def _missing_evidence(active: list[Entity], sender: dict | None, prior: dict[int, int]) -> list[str]:
    types = {e.type for e in active}
    missing = []
    if "business" not in types:
        missing.append("No business or service name was found in the message.")
    if not types & {"url", "domain"} and not any(e.type == "email" and not e.meta.get("freemail") for e in active):
        missing.append("No website, domain or company email address was found.")
    missing.append("None of your LeakTrace aliases, nicknames or website names appear in the message.")
    if not sender:
        missing.append("No sender was given.")
    elif not prior:
        missing.append("You have not linked this sender to a website before.")
    return missing


def _sender_notes(sender: dict | None) -> list[str]:
    if not sender:
        return []
    notes = ["The sender delivered this message. That does not mean it is the service that collected your number."]
    if sender["type"] == "alphanumeric":
        notes.append("Alphanumeric sender IDs are not verified and can be spoofed.")
    elif sender["type"] == "short_code":
        notes.append("Short codes are usually shared by messaging providers and can serve many companies.")
    elif sender["type"] == "phone":
        notes.append("Phone-number senders can be spoofed.")
    return notes
