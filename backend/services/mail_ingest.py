"""Email ingestion: turn one inbound message into a MailLog row and a matcher result.

Trust boundaries:
- recipient and envelope_from come from the email Worker, i.e. from Cloudflare's
  SMTP session. The envelope sender is still whatever the sending server
  claimed and can be forged.
- from_header and subject are message content, fully untrusted. They are parsed
  leniently: anything unparseable is ignored rather than trusted.
- auth_results is a header too. Only verdicts from an instance naming
  Cloudflare's server are kept, and LeakTrace cannot confirm Cloudflare
  removes forged copies, so they are shown as reported, never as proof.

Attribution uses the envelope recipient only, and only an exact,
case-insensitive alias match: the To/Cc headers, plus-addressing and
lookalike aliases are never used to guess. For attributed mail ("matched"),
the sender name and address, subject and verdicts are stored so the owner's
inbox can show them. For mail no account can be found for ("unmatched"),
only the alias, the sender domain and the reason are kept. Bodies and
attachments are never received or stored.
"""

import hashlib
import logging
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.models import MailLog, Signup
from backend.services import email_attribution, matcher
from backend.services.domains import normalize_email

logger = logging.getLogger("leaktrace.ingest")

DEDUP_CONSTRAINT = "uq_mail_log_message_id_hash"
MAX_SUBJECT_LENGTH = 998
MAX_SENDER_NAME_LENGTH = 200
AUTHSERV_ID = "mx.cloudflare.net"
AUTH_METHODS = ("spf", "dkim", "dmarc")
_AUTH_VERDICT = re.compile(r"(?<![\w.-])(spf|dkim|dmarc)=([a-z]+)\b")
# Workers join repeated headers with ", "; each instance starts with "i=<n>;".
_NEXT_INSTANCE = re.compile(r",\s*(?=i=\d+\s*;)")
_INSTANCE_START = re.compile(r"\s*i=\d+\s*;\s*([^;\s]+)")


@dataclass(frozen=True)
class InboundMail:
    recipient: str
    envelope_from: str | None
    claimed_sender: str | None
    subject: str | None
    message_id: str | None
    received_at: datetime
    sender_name: str | None = None
    auth_results: str | None = None

    @property
    def sender_for_matching(self) -> str | None:
        """The From header address when present (what the recipient sees),
        otherwise the envelope sender."""
        return self.claimed_sender or self.envelope_from


@dataclass(frozen=True)
class IngestOutcome:
    mail_log_id: int
    duplicate: bool
    recipient_known: bool
    match_status: str | None
    match_confidence: str | None
    ingest_status: str
    status_reason: str | None
    reprocessed: bool = False


def parse_from_header(value: str | None) -> str | None:
    """First valid address in an untrusted From header, or None."""
    if not value:
        return None
    for _, address in getaddresses([value]):
        try:
            return normalize_email(address)
        except ValueError:
            continue
    return None


def _clean_text(value: str, max_length: int) -> str | None:
    """Decode MIME encoded-words, drop control characters, collapse whitespace."""
    try:
        value = str(make_header(decode_header(value)))
    except Exception:  # malformed encoding: fall back to the raw text
        pass
    value = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in value)
    value = " ".join(value.split())[:max_length]
    return value or None


def decode_subject(value: str | None) -> str | None:
    return _clean_text(value, MAX_SUBJECT_LENGTH) if value else None


def parse_sender_name(value: str | None) -> str | None:
    """Display name of the first valid address in an untrusted From header."""
    if not value:
        return None
    for name, address in getaddresses([value]):
        try:
            normalize_email(address)
        except ValueError:
            continue
        name = _clean_text(name, MAX_SENDER_NAME_LENGTH) if name else None
        # A display name that is just an address adds nothing and can mislead.
        return None if name is None or "@" in name else name
    return None


def parse_auth_results(value: str | None) -> str | None:
    """SPF/DKIM/DMARC verdicts from the topmost ARC-Authentication-Results
    instance, only when it names Cloudflare's server, e.g. "spf=pass dkim=fail".

    The first verdict of each method is kept. Anything else returns None.
    """
    if not value:
        return None
    first = _NEXT_INSTANCE.split(value, maxsplit=1)[0].lower()
    start = _INSTANCE_START.match(first)
    if not start or start.group(1) != AUTHSERV_ID:
        return None
    verdicts: dict[str, str] = {}
    for method, result in _AUTH_VERDICT.findall(first[start.end():]):
        verdicts.setdefault(method, result[:16])
    return " ".join(f"{m}={verdicts[m]}" for m in AUTH_METHODS if m in verdicts) or None


def dedup_hash(mail: InboundMail) -> str:
    """Stable key for one message delivered to one alias.

    A message sent to several aliases is delivered once per envelope recipient
    with the same Message-ID, so the recipient is part of the key: each alias
    keeps its own copy, while retries of the same delivery collapse into one.
    Without a Message-ID it falls back to the message's key fields, so two
    genuinely different messages with identical fields would be treated as one.
    """
    if mail.message_id:
        basis = "message-id\n" + mail.recipient + "\n" + mail.message_id
    else:
        parts = (mail.recipient, mail.envelope_from, mail.claimed_sender, mail.subject)
        basis = "fields\n" + "\n".join(p or "" for p in parts)
    return hashlib.sha256(basis.encode()).hexdigest()


def _outcome(session: Session, log: MailLog, duplicate: bool, reprocessed: bool = False) -> IngestOutcome:
    signup = session.get(Signup, log.signup_id) if log.signup_id else None
    linked = bool(signup and log.user_id and signup.user_id == log.user_id
                  and email_attribution.valid_stored_alias(log.alias) and signup.alias
                  and signup.alias.lower() == log.alias.lower() and signup.site_name.strip())
    status = email_attribution.effective_status(log.ingest_status, linked)
    reason = email_attribution.status_reason(log.ingest_status, linked, log.status_reason)
    return IngestOutcome(
        log.id, duplicate, log.signup_id is not None, log.match_status, log.match_confidence,
        status, reason, reprocessed,
    )


def _existing(session: Session, key: str) -> MailLog | None:
    return session.scalar(select(MailLog).where(MailLog.message_id_hash == key))


def resolve_recipient(session: Session, recipient: str) -> tuple[Signup | None, str | None]:
    """The signup whose alias is exactly this recipient, and why it cannot be
    attributed to an account (None when it can)."""
    found = session.scalars(select(Signup).where(func.lower(Signup.alias) == recipient).limit(2)).all()
    if not found:
        return None, "unknown_alias"
    if len(found) > 1:  # prevented by uq_signups_alias_lower; never pick one
        return None, "ambiguous_alias"
    if not found[0].site_name or not found[0].site_name.strip():
        return None, "unknown_alias"
    if found[0].user_id is None:
        return found[0], "unowned_alias"
    return found[0], None


def _analyse(session: Session, mail: InboundMail, signup: Signup) -> tuple[str, str] | None:
    """Matcher status and confidence, or None if the matcher failed.

    Database errors propagate (the delivery is then refused and retried);
    any other error is recorded as a failed analysis.
    """
    try:
        result = matcher.check(session, matcher.Clues(
            recipient=mail.recipient, sender=mail.sender_for_matching, subject=mail.subject,
            user_id=signup.user_id,
        ))
    except SQLAlchemyError:
        raise
    except Exception as exc:
        logger.error("Leak analysis failed: %s", type(exc).__name__)
        return None
    return result.status, result.confidence


def _reprocess(session: Session, mail: InboundMail, log: MailLog) -> IngestOutcome:
    """Redelivery of a message whose analysis failed: run the matcher again."""
    signup = session.get(Signup, log.signup_id) if log.signup_id else None
    if (signup is None or not log.user_id or signup.user_id != log.user_id or not signup.site_name.strip() or not signup.alias
            or signup.alias.lower() != mail.recipient or log.alias != mail.recipient):
        return _outcome(session, log, True)
    analysed = _analyse(session, mail, signup)
    if analysed is None:
        return _outcome(session, log, True)
    log.match_status, log.match_confidence = analysed
    log.ingest_status, log.status_reason = "matched", None
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise
    return _outcome(session, log, True, reprocessed=True)


def process(session: Session, mail: InboundMail) -> IngestOutcome:
    """Attribute, match and record one message. Safe to call again for a
    retried delivery: a duplicate changes nothing, except that a message whose
    analysis failed is analysed again.

    The recipient alias decides whose signups are searched: the matcher runs
    in that signup owner's scope only. If the alias is unknown, no search is
    made at all, rather than searching more broadly.
    """
    # Reject malformed envelope addresses even when invoked outside the HTTP route.
    from dataclasses import replace
    mail = replace(mail, recipient=normalize_email(mail.recipient))
    key = dedup_hash(mail)
    if existing := _existing(session, key):
        if existing.ingest_status == "failed":
            return _reprocess(session, mail, existing)
        return _outcome(session, existing, True)

    signup, reason = resolve_recipient(session, mail.recipient)
    sender = mail.sender_for_matching
    status, confidence = "no_match", "none"
    ingest_status = "matched" if reason is None else "unmatched"
    if signup is not None and reason is None:
        analysed = _analyse(session, mail, signup)
        if analysed is None:
            status, confidence = None, None
            if reason is None:
                ingest_status, reason = "failed", "analysis_failed"
        else:
            status, confidence = analysed

    attributed = ingest_status != "unmatched"
    log = MailLog(
        user_id=signup.user_id if signup else None,
        signup_id=signup.id if signup else None,
        alias=mail.recipient,
        received_at=mail.received_at,
        message_id_hash=key,
        sender_domain=sender.split("@", 1)[1] if sender else None,
        match_status=status,
        match_confidence=confidence,
        ingest_status=ingest_status,
        status_reason=reason,
        # Message details only for mail an account owns and can see.
        sender=sender if attributed else None,
        sender_name=mail.sender_name if attributed else None,
        subject=mail.subject if attributed else None,
        auth_results=mail.auth_results if attributed else None,
    )
    try:
        session.add(log)
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint != DEDUP_CONSTRAINT:
            raise
        # A concurrent delivery of the same message committed first.
        existing = _existing(session, key)
        if existing is None:
            raise
        return _outcome(session, existing, True)
    except Exception:
        session.rollback()
        raise
    return _outcome(session, log, False)


def now() -> datetime:
    return datetime.now(timezone.utc)
