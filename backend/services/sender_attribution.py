"""Separate alias attribution, claimed sender review, and disclosure evidence.

A user's expected-domain review describes their expectation, not cryptographic
sender authentication. The stored authentication summary is the inbound
provider's assertion. Only a reported DMARC pass supports alignment with the
visible From domain; SPF or DKIM pass alone is insufficient here because the
stored summary has no envelope or signing domain.
"""

from collections import defaultdict
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import MailLog, SenderDomainReview, Signup
from backend.services.domains import normalize_domain, parent_domains
from backend.services.ownership import owned_by


def reviews_for_user(session: Session, user_id: int) -> dict[int, list[SenderDomainReview]]:
    rows = session.scalars(select(SenderDomainReview).where(owned_by(SenderDomainReview.user_id, user_id))).all()
    result: dict[int, list[SenderDomainReview]] = defaultdict(list)
    for row in rows:
        result[row.signup_id].append(row)
    return dict(result)


def _review_for(domain: str, reviews: Sequence[SenderDomainReview]) -> SenderDomainReview | None:
    by_domain = {review.domain: review for review in reviews}
    return next((by_domain[parent] for parent in parent_domains(domain) if parent in by_domain), None)


def _provider_authentication(value: str | None) -> str:
    # parse_auth_results at ingestion keeps only Cloudflare's top ARC instance.
    verdicts = dict(part.split("=", 1) for part in (value or "").split() if "=" in part)
    if verdicts.get("dmarc") == "pass":
        return "provider_dmarc_pass"
    if verdicts.get("dmarc") == "fail":
        return "provider_dmarc_fail"
    return "not_established"


def assess(log: MailLog, signup: Signup | None, reviews: Sequence[SenderDomainReview] = ()) -> dict:
    linked = bool(signup and log.ingest_status in ("matched", "failed") and log.alias and signup.alias
                  and log.alias.lower() == signup.alias.lower() and log.user_id == signup.user_id)
    result = {
        "alias_attribution": "matched" if linked else "not_matched",
        "sender_domain_status": "missing",
        "sender_authentication": "not_established",
        "disclosure_status": "none",
        "confirmed_leak": False,
        "evidence": [],
        "limitations": [],
    }
    if not linked:
        return result
    result["evidence"].append("The envelope recipient exactly matches this website's saved alias.")
    result["limitations"].append("An alias match identifies the signup, not who obtained the address.")
    if log.ingest_status == "failed":
        result["limitations"].append("Message analysis failed, so no sender or disclosure conclusion is available.")
        return result
    sender = log.sender_domain
    try:
        sender = normalize_domain(sender) if sender else None
    except ValueError:
        sender = None
    if not sender:
        result["sender_domain_status"] = "missing"
        result["limitations"].append("No valid claimed sender domain was recorded.")
        return result
    result["sender_authentication"] = _provider_authentication(log.auth_results)
    domain = signup.site_domain
    if domain and (sender in parent_domains(domain) or domain in parent_domains(sender)):
        result["sender_domain_status"] = "website_domain"
    else:
        review = _review_for(sender, reviews)
        if review:
            result["sender_domain_status"] = "expected_by_user" if review.review_status == "expected" else "unexpected_by_user"
        else:
            result["sender_domain_status"] = "unreviewed"
    if result["sender_authentication"] == "provider_dmarc_pass":
        result["evidence"].append("Cloudflare reported DMARC pass for the claimed From domain.")
        result["limitations"].append("A DMARC pass supports From-domain alignment; it does not identify who shared the alias.")
    elif result["sender_authentication"] == "provider_dmarc_fail":
        result["limitations"].append("Cloudflare reported DMARC failure; the claimed From domain may be spoofed.")
    else:
        result["limitations"].append("No provider-reported DMARC pass is available. SPF or DKIM alone does not establish From-domain alignment here.")
    if result["sender_domain_status"] == "unexpected_by_user":
        result["evidence"].append(f"You marked {sender} as unexpected for this website's alias.")
        if result["sender_authentication"] == "provider_dmarc_pass":
            result["disclosure_status"] = "potential"
            result["limitations"].append("The alias could still have been guessed, forwarded, or shared legitimately; this is not a confirmed leak.")
        else:
            result["disclosure_status"] = "review"
    elif result["sender_domain_status"] == "unreviewed":
        result["disclosure_status"] = "review"
    return result
