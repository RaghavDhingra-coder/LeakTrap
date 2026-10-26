"""Recipient attribution and possible exposure clues from a user's own signups."""
import re

from sqlalchemy import and_, func
from backend.models import MailLog, Signup
from backend.services.ownership import owned_by
from backend.services.domains import normalize_email, parent_domains

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
    """Suggest sources only from the owner's recorded markers and stored email metadata.

    Email bodies are unavailable. A nickname is considered only in the subject,
    never in the From display name (which describes the claimed sender).
    """
    if effective_status(log.ingest_status, recipient_signup is not None) != "matched":
        return []
    sender_domain = (log.sender_domain or "").lower()
    if not sender_domain:
        return []
    out: list[dict] = []

    def add(signup: Signup, marker_type: str, marker: str, confidence: str) -> None:
        if signup.site_domain and signup.site_domain in parent_domains(sender_domain):
            return
        out.append({
            "signup_id": signup.id, "site_name": signup.site_name,
            "marker_type": marker_type, "marker": marker,
            "observed_source": sender_domain, "expected_domain": signup.site_domain,
            "confidence": confidence if signup.site_domain else "low",
            "explanation": (
                f"This message uses your {('alias for' if marker_type == 'recipient_alias' else 'nickname recorded for')} "
                f"{signup.site_name}. Its claimed sender domain is {sender_domain}. "
                + (f"That is outside the recorded domain {signup.site_domain}. " if signup.site_domain else
                   "No website domain was recorded, so this sender cannot be compared with it. ")
                + f"{signup.site_name} is a possible source of the detail."
            ), "caveat": EXPOSURE_CAVEAT,
        })

    if recipient_signup:
        add(recipient_signup, "recipient_alias", log.alias, "medium")
    subject = log.subject or ""
    if subject:
        nickname_owners: dict[str, list[Signup]] = {}
        for signup in owned_signups:
            nickname = (signup.nickname or "").strip().lower()
            if len(nickname) >= 3:
                nickname_owners.setdefault(nickname, []).append(signup)
        for nickname, sites in nickname_owners.items():
            if (len(sites) == 1 and sites[0].id != getattr(recipient_signup, "id", None)
                    and re.search(rf"(?<!\w){re.escape(nickname)}(?!\w)", subject, re.I)):
                add(sites[0], "nickname_mention", sites[0].nickname, "low")
    return out
