"""Recipient attribution rules, independent of sender/source-analysis results."""
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

