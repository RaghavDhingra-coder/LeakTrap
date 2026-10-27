"""Recipient attribution and possible exposure clues from a user's own signups."""
from sqlalchemy import and_, func
from backend.models import MailLog, Signup
from backend.services.ownership import owned_by
from backend.services.domains import normalize_email, parent_domains
from backend.services.sender_classification import classify

# Stored addresses are canonical ASCII. Also validates historical rows before a join
# can expose a website. PostgreSQL and Python domain validation use the same label limits.
_ATOM = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
STORED_ALIAS_PATTERN = rf"^{_ATOM}(\.{_ATOM})*@{_LABEL}(\.{_LABEL})+$"


def valid_stored_alias(alias: str | None) -> bool:
    if not alias:
        return False
    try:
        return normalize_email(alias) == alias.lower()
    except ValueError:
        return False


def effective_status(ingest_status: str | None, linked: bool) -> str:
    if ingest_status == "failed":
        return "failed"
    if ingest_status is None:
        return "unprocessed"
    return "matched" if linked and ingest_status == "matched" else "unmatched"


def status_reason(ingest_status: str | None, linked: bool, stored_reason: str | None) -> str | None:
    status = effective_status(ingest_status, linked)
    if status == "matched":
        return None
    if status == "unprocessed":
        return "legacy_unprocessed"
    return stored_reason or ("analysis_failed" if status == "failed" else "invalid_alias_association")


def alias_link(user_id: int):
    return and_(MailLog.signup_id == Signup.id, owned_by(Signup.user_id, user_id),
                MailLog.user_id == Signup.user_id, MailLog.ingest_status.in_(("matched", "failed")),
                func.lower(MailLog.alias) == func.lower(Signup.alias), func.length(func.trim(Signup.site_name)) > 0,
                func.lower(MailLog.alias).op("~")(STORED_ALIAS_PATTERN),
                ~func.lower(MailLog.alias).op("~")(r"\.[0-9]+$"),
                func.length(func.split_part(MailLog.alias, "@", 1)) <= 64,
                func.length(func.split_part(MailLog.alias, "@", 2)) <= 253)



EXPOSURE_CAVEAT = (
    "This does not prove the website leaked or shared your details. Senders can be spoofed; "
    "an alias can be guessed or forwarded, and a nickname can be coincidental."
)


def email_exposure(log: MailLog, recipient_signup: Signup | None, owned_signups: list[Signup]) -> list[dict]:
    """Return a possible-source lead only with curated ownership plus DMARC evidence."""
    if effective_status(log.ingest_status, recipient_signup is not None) != "matched":
        return []
    assessment = log.sender_attribution or classify(
        site_name=recipient_signup.site_name if recipient_signup else None,
        site_domain=recipient_signup.site_domain if recipient_signup else None,
        alias=log.alias, sender_domain=log.sender_domain, auth_results=log.auth_results,
        alias_matched=recipient_signup is not None,
        evaluated_at=log.received_at,
    )
    if not assessment.get("possible_exposure") or not recipient_signup:
        return []
    return [{
        "signup_id": recipient_signup.id, "site_name": recipient_signup.site_name,
        "marker_type": "recipient_alias", "marker": log.alias or "",
        "observed_source": assessment.get("sender_domain"),
        "expected_domain": recipient_signup.site_domain, "confidence": "medium",
        "explanation": assessment["explanation"], "caveat": EXPOSURE_CAVEAT,
    }]
