"""A domain-only comparison for mail delivered to an owned website alias.

"Verified" here describes the relationship between domain strings. It never
authenticates the message or replaces the sender-attribution assessment.
"""
from __future__ import annotations

from backend.services.domains import normalize_domain, normalize_email
from backend.services.sms_extract import registrable_domain


def assess(*, site_domain: str | None, sender_address: str | None,
           stored_sender_domain: str | None, alias_matched: bool) -> dict:
    result = {
        "status": "Review", "relationship": "unavailable",
        "registered_domain": None, "sender_domain": None,
        "reason": "missing_website", "domain_only": True,
        "explanation": "No currently owned website is linked to this email.",
    }
    if not alias_matched:
        return result
    try:
        site = normalize_domain(site_domain or "")
    except ValueError:
        result.update(reason="invalid_website_domain",
                      explanation="The registered website domain is missing or invalid.")
        return result
    result["registered_domain"] = site
    if not sender_address:
        result.update(reason="missing_sender_address",
                      explanation="The received email has no stored sender address to compare.")
        return result
    try:
        sender = normalize_email(sender_address).split("@", 1)[1]
    except ValueError:
        result.update(reason="invalid_sender_address",
                      explanation="The stored sender address is malformed; its domain cannot be trusted for comparison.")
        return result
    result["sender_domain"] = sender
    if stored_sender_domain:
        try:
            if normalize_domain(stored_sender_domain) != sender:
                raise ValueError
        except ValueError:
            result.update(reason="sender_domain_conflict",
                          explanation="The stored sender domain disagrees with the received sender address.")
            return result
    if sender == site:
        relationship = "exact"
    elif sender.endswith("." + site):
        relationship = "sender_subdomain"
    elif site.endswith("." + sender):
        relationship = "sender_parent"
    else:
        relationship = "unrelated"
    result["relationship"] = relationship
    if relationship == "unrelated":
        result.update(status="Not Verified", reason="different_domain",
                      explanation="The sender domain does not match the registered website domain. This does not prove disclosure or that the email is malicious.")
    elif relationship != "exact" and registrable_domain(sender) != registrable_domain(site):
        result.update(reason="uncertain_domain_boundary",
                      explanation="The domains have a parent or subdomain pattern, but a shared registrable domain could not be established.")
    else:
        description = {
            "exact": "exactly matches", "sender_subdomain": "is a subdomain of",
            "sender_parent": "is a parent domain of",
        }[relationship]
        result.update(status="Verified", reason="domain_match",
                      explanation=f"The sender domain {description} the registered website domain. This domain match does not authenticate the email.")
    return result
