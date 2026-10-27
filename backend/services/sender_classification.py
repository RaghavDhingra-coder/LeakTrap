"""Evidence-backed final email classification; no LLM output is authoritative."""
from __future__ import annotations

from datetime import datetime, timezone

from backend.services.domains import normalize_domain

RULESET_VERSION = "2026-10-27.4"
BRAND_DOMAINS: dict[str, dict] = {}  # Empty by default; production evidence is discovered and cached.
SHARED_MAIL_PROVIDERS = {
    "gmail.com": "Google Gmail", "googlemail.com": "Google Gmail",
    "outlook.com": "Microsoft Outlook", "hotmail.com": "Microsoft Outlook",
    "yahoo.com": "Yahoo Mail", "amazonses.com": "Amazon Simple Email Service",
}


def domain_evidence(domain: str | None, registry: dict[str, dict] | None = None) -> dict | None:
    """Compatibility helper used by tests; runtime classifications use collected evidence."""
    if not domain:
        return None
    try:
        normalized = normalize_domain(domain)
    except ValueError:
        return None
    labels = normalized.split(".")
    for index in range(len(labels) - 1):
        apex = ".".join(labels[index:])
        entry = (BRAND_DOMAINS if registry is None else registry).get(apex)
        if entry:
            name = entry.get("organization")
            return {"domain": normalized, "apex_domain": apex, **entry,
                    "organization_verified": bool(name),
                    "checked_at": entry.get("checked_at"),
                    "dns": {"records": []},
                    "website": {"organization_claims": [name] if name else []}}
    return None


def _auth_results(value: str | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in (value or "").split():
        if "=" not in item:
            continue
        method, result = item.split("=", 1)
        if method in {"spf", "dkim", "dmarc"} and result in {
            "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
        }:
            parsed[method] = result
    return parsed


def _organization(evidence: dict | None) -> str | None:
    if not isinstance(evidence, dict):
        return None
    if evidence.get("organization_verified") is True:
        name = evidence.get("organization")
        return name if isinstance(name, str) and name.strip() else None
    website = evidence.get("website", {})
    claims = website.get("organization_claims", []) if isinstance(website, dict) else []
    if isinstance(claims, list):
        valid = [claim.strip() for claim in claims if isinstance(claim, str) and 1 < len(claim.strip()) <= 120]
        if valid and len({claim.casefold() for claim in valid}) == 1:
            return valid[0]
    return None


def _evidence_ok(evidence: dict | None) -> bool:
    if not isinstance(evidence, dict):
        return False
    if evidence.get("organization_verified") is True and evidence.get("source_urls"):
        return True  # Explicit curated evidence in the compatibility test seam.
    website = evidence.get("website", {})
    if not isinstance(website, dict) or website.get("error"):
        return False
    try:
        checked = datetime.fromisoformat(evidence["checked_at"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if checked.tzinfo is None or age > 86400 or age < -300:
            return False
        if evidence.get("expires_at") and datetime.fromisoformat(evidence["expires_at"]) <= datetime.now(timezone.utc):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return bool((evidence.get("dns") or {}).get("records") is not None
                and website.get("observed_url") and evidence.get("source_urls"))


def _lookup_status(evidence: dict | None) -> str:
    if not evidence:
        return "Evidence not evaluated"
    website = evidence.get("website", {}) if isinstance(evidence, dict) else {}
    records = evidence.get("dns", {}).get("records", []) if isinstance(evidence.get("dns"), dict) else []
    has_dns = any(isinstance(row, dict) and "data" in row for row in records)
    if has_dns and isinstance(website, dict) and website.get("error") == "website_access_denied":
        return "DNS collected; website blocked lookup"
    if has_dns and isinstance(website, dict) and website.get("error"):
        return "DNS collected; website unavailable"
    if evidence.get("errors") and not _organization(evidence):
        return "Evidence lookup failed"
    try:
        checked = datetime.fromisoformat(evidence["checked_at"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if checked.tzinfo is None or age > 86400 or age < -300 or (evidence.get("expires_at") and
                datetime.fromisoformat(evidence["expires_at"]) <= datetime.now(timezone.utc)):
            return "Evidence expired"
    except (KeyError, TypeError, ValueError):
        return "Insufficient evidence"
    return "Evidence collected" if _organization(evidence) and _evidence_ok(evidence) else "Insufficient evidence"


def _identity_link(site_domain: str | None, sender_domain: str | None, site_evidence: dict | None) -> bool:
    try:
        site, sender = normalize_domain(site_domain or ""), normalize_domain(sender_domain or "")
    except ValueError:
        return False
    if site == sender or sender.endswith("." + site) or site.endswith("." + sender):
        return True
    website = site_evidence.get("website", {}) if isinstance(site_evidence, dict) else {}
    links = website.get("linked_domains", []) if isinstance(website, dict) else []
    return isinstance(links, list) and any(sender == link or sender.endswith("." + link)
                                            for link in links if isinstance(link, str))


def _domain_relationship(site_domain: str | None, sender_domain: str | None) -> str | None:
    try:
        site, sender = normalize_domain(site_domain or ""), normalize_domain(sender_domain or "")
    except ValueError:
        return None
    if site == sender:
        return "same_domain"
    if site.endswith("." + sender):
        return "sender_parent_domain"
    if sender.endswith("." + site):
        return "sender_subdomain"
    return None


def classify(*, site_name: str | None, site_domain: str | None, alias: str | None,
             sender_domain: str | None, auth_results: str | None, sender_address: str | None = None,
             alias_matched: bool, evaluated_at: datetime | None = None,
             site_evidence: dict | None = None, sender_evidence: dict | None = None,
             domain_registry: dict[str, dict] | None = None) -> dict:
    evaluated = evaluated_at or datetime.now(timezone.utc)
    # Explicit registries are only a deterministic test seam; production passes cache evidence.
    if domain_registry is not None:
        site_evidence = site_evidence or domain_evidence(site_domain, domain_registry)
        sender_evidence = sender_evidence or domain_evidence(sender_domain, domain_registry)
    auth = _auth_results(auth_results)
    all_pass = all(auth.get(method) == "pass" for method in ("spf", "dkim", "dmarc"))
    any_failure = any(result in {"fail", "softfail", "permerror"} for result in auth.values())
    dmarc_pass = auth.get("dmarc") == "pass"
    sender_org, site_org = _organization(sender_evidence), _organization(site_evidence)
    service_provider = None
    if sender_domain:
        try:
            labels = normalize_domain(sender_domain).split(".")
            service_provider = next((SHARED_MAIL_PROVIDERS[".".join(labels[index:])]
                                     for index in range(len(labels) - 1)
                                     if ".".join(labels[index:]) in SHARED_MAIL_PROVIDERS), None)
        except ValueError:
            pass
    same_org = bool(sender_org and site_org and sender_org.casefold() == site_org.casefold())
    different_org = bool(sender_org and site_org and not same_org)
    relationship = _domain_relationship(site_domain, sender_domain)
    exposure = bool(alias_matched and different_org and dmarc_pass
                    and _evidence_ok(site_evidence) and _evidence_ok(sender_evidence))
    status = "Unknown"
    if any_failure:
        status = "Suspicious"
        explanation = "An available SPF, DKIM, or DMARC result failed; the claimed From domain may be spoofed."
    elif not alias_matched:
        explanation = "This message is not linked to a currently owned website alias."
    elif not sender_domain:
        explanation = "The sender domain is unavailable, so its organization cannot be established."
    elif site_evidence is None and sender_evidence is None:
        explanation = "Public domain evidence has not been evaluated for this email yet. Refresh sender evidence to check it."
    elif (same_org and all_pass and _evidence_ok(site_evidence) and _evidence_ok(sender_evidence)
          and _identity_link(site_domain, sender_domain, site_evidence)):
        status = "Verified Sender"
        explanation = (f"The registered website and sender domain both publish the organization name {site_org}, "
                      "the domains are directly related or linked from the registered website, "
                      "and SPF, DKIM, and DMARC were reported as passing for this message.")
    elif exposure:
        status = "Possible Third-Party Exposure"
        explanation = (f"This alias was registered for {site_org}, but a DMARC-aligned email from a domain "
                      f"publishing the name {sender_org} reached it. This is a possible exposure signal, not "
                      f"proof that {site_org} shared or sold the address.")
    elif relationship and not sender_org and not site_org:
        description = {"same_domain": "the same domain as", "sender_parent_domain": "a parent domain of",
                       "sender_subdomain": "a subdomain of"}[relationship]
        explanation = (f"The sender domain is {description} the registered website domain. This domain relationship "
                       "does not establish the sender's organization or authenticate the message. "
                       "The available authentication and website evidence do not meet verification requirements.")
    elif sender_org:
        explanation = (f"The sender domain's website publishes the name {sender_org}, but available evidence "
                      "does not establish an authenticated sender or a different organization for comparison. "
                      "Check the evidence sources and missing authentication results.")
    elif service_provider:
        explanation = (f"The sender uses shared mail infrastructure ({service_provider}); this identifies the "
                      "service provider, not the organization that sent the message.")
    elif sender_domain:
        explanation = "The sender's organization could not be established from available website and DNS evidence."
    else:
        explanation = "Sender-domain evidence is unavailable."

    return {
        "ruleset_version": RULESET_VERSION, "evaluated_at": evaluated.isoformat(),
        "status": status, "alias_attribution": "matched" if alias_matched else "unmatched",
        "registered_website": site_name, "registered_domain": site_domain,
        "recipient_alias": alias if alias_matched else None,
        "claimed_sender_address": sender_address if alias_matched else None,
        "sender_domain": sender_domain, "sender_organization": sender_org,
        "domain_relationship": relationship,
        "sender_service_provider": service_provider,
        "sender_domain_evidence": sender_evidence, "registered_organization": site_org,
        "registered_domain_evidence": site_evidence,
        "evidence_status": {"sender_domain": _lookup_status(sender_evidence),
                            "registered": _lookup_status(site_evidence)},
        "authentication": {"reported_by": "Cloudflare ARC Authentication-Results" if auth_results else None,
                           "results": auth, "status": "passed" if all_pass else "failed" if any_failure else "incomplete",
                           "all_required_passed": all_pass, "dmarc_pass": dmarc_pass},
        "possible_exposure": exposure, "possible_source": site_org if exposure else None,
        "explanation": explanation,
        "limitations": [
            "Organization names are self-published on the domain and do not prove legal ownership.",
            "Authentication verdicts are reported by the inbound provider and are not independently revalidated by LeakTrace.",
            "DMARC alignment and domain control do not prove who disclosed the alias or whether disclosure was authorized.",
            "Shared mail infrastructure does not establish sender-organization ownership.",
        ],
    }


def classify_for_email(session, *, site_name: str | None, site_domain: str | None, alias: str | None,
                       sender_domain: str | None, sender_address: str | None,
                       auth_results: str | None, alias_matched: bool,
                       evaluated_at: datetime | None = None,
                       correlation_id: str | None = None) -> dict:
    from backend.services.domain_evidence import cached_public_evidence
    from backend.services.domain_evidence import _log_failure

    def load(domain: str | None, stage: str) -> dict | None:
        if not domain:
            return None
        try:
            return cached_public_evidence(session, domain, correlation_id=correlation_id)
        except Exception as exc:
            code = getattr(exc, "code", "cache_or_collection_error")
            _log_failure(stage, domain, code, correlation_id)
            return {"domain": domain, "evidence_status": "lookup_failed",
                    "errors": [{"stage": stage, "category": code}]}

    site = load(site_domain, "registered_domain")
    sender = load(sender_domain, "sender_domain")
    return classify(site_name=site_name, site_domain=site_domain, alias=alias,
                    sender_domain=sender_domain, sender_address=sender_address,
                    auth_results=auth_results, alias_matched=alias_matched,
                    evaluated_at=evaluated_at, site_evidence=site, sender_evidence=sender)
