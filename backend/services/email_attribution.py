"""Recipient attribution and possible exposure clues from a user's own signups."""
from sqlalchemy import and_, func
from backend.models import MailLog, Signup
from backend.services.ownership import owned_by
from backend.services.domains import normalize_email

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
    "This is a user-reviewed lead, not proof the website leaked or shared an address. "
    "Aliases can be guessed or forwarded, and sender authentication does not establish how the sender obtained it."
)


def email_exposure(log: MailLog, recipient_signup: Signup | None, assessment: dict) -> list[dict]:
    """Emit a possible disclosure lead only after review plus aligned sender evidence."""
    if not recipient_signup or assessment["disclosure_status"] != "potential" or not log.alias:
        return []
    return [{
        "signup_id": recipient_signup.id, "site_name": recipient_signup.site_name,
        "marker_type": "recipient_alias", "marker": log.alias,
        "observed_source": log.sender_domain, "expected_domain": recipient_signup.site_domain,
        "confidence": "medium",
        "explanation": (
            f"Mail reached the alias saved for {recipient_signup.site_name}. You marked the claimed sender "
            f"{log.sender_domain} unexpected, and Cloudflare reported DMARC pass for that From domain. "
            "This supports a possible third-party disclosure, not a confirmed leak."
        ), "caveat": EXPOSURE_CAVEAT,
    }]
