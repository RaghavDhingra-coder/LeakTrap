"""Deterministic sender attribution boundaries; no external provider calls."""
from datetime import datetime, timezone

from backend.services.sender_classification import classify, domain_evidence


NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
AMAZON = {"amazon.com": {"organization": "Amazon", "checked_at": "2026-10-27", "source_urls": ["https://amazon.example/help"]}}
OTHER = {**AMAZON, "other.example": {"organization": "Northstar Labs", "checked_at": "2026-10-27", "source_urls": ["https://other.example/about"]}}
PASS = "spf=pass dkim=pass dmarc=pass"


def evaluate(sender="mx.amazon.com", auth=PASS, registry=AMAZON, display_name_ignored=None):
    return classify(site_name="Amazon", site_domain="amazon.com", alias="alice@leaktrap.xyz",
                    sender_domain=sender, sender_address="notice@" + sender,
                    auth_results=auth, alias_matched=True, evaluated_at=NOW,
                    domain_registry=registry)


def test_amazon_sender_subdomain_and_all_authentication_checks_pass():
    row = evaluate()
    assert row["status"] == "Verified Sender"
    assert row["sender_organization"] == "Amazon"
    assert row["authentication"]["all_required_passed"] is True
    assert row["possible_source"] is None
    assert row["sender_domain_evidence"]["apex_domain"] == "amazon.com"
    assert row["evaluated_at"] == NOW.isoformat()


def test_matching_domain_with_spf_none_remains_unknown():
    row = evaluate(auth="spf=none dkim=pass dmarc=pass")
    assert row["status"] == "Unknown"
    assert row["authentication"]["results"] == {"spf": "none", "dkim": "pass", "dmarc": "pass"}
    assert row["authentication"]["all_required_passed"] is False


def test_parent_domain_with_dns_only_shows_relationship_without_verification():
    now = datetime.now(timezone.utc).isoformat()
    def partial(domain):
        return {"domain": domain, "checked_at": now,
                "dns": {"records": [{"type": "A", "data": "93.184.216.34"}]},
                "website": {"error": "website_access_denied", "organization_claims": []},
                "errors": [{"stage": "https", "category": "website_access_denied"}],
                "source_urls": [f"https://dns.google/resolve?name={domain}&type=TXT"]}
    result = classify(site_name="Adobe", site_domain="auth.services.adobe.com", alias="a@leaktrap.xyz",
                      sender_domain="adobe.com", auth_results="spf=none dkim=pass dmarc=pass",
                      alias_matched=True, site_evidence=partial("auth.services.adobe.com"),
                      sender_evidence=partial("adobe.com"))
    assert result["status"] == "Unknown"
    assert result["sender_organization"] is None
    assert result["domain_relationship"] == "sender_parent_domain"
    assert result["evidence_status"]["sender_domain"] == "DNS collected; website blocked lookup"
    assert "does not establish" in result["explanation"]


def test_different_curated_organization_is_separate_from_possible_source():
    row = evaluate("mail.other.example", registry=OTHER)
    assert row["status"] == "Possible Third-Party Exposure"
    assert row["sender_organization"] == "Northstar Labs"
    assert row["possible_source"] == "Amazon"
    assert row["sender_organization"] != row["possible_source"]
    assert "not proof" in row["explanation"]
    assert "sold" in row["explanation"]


def test_unrecognized_domain_and_shared_provider_do_not_claim_organization():
    unknown = evaluate("unknown.example")
    provider = evaluate("amazonses.com")
    assert unknown["status"] == "Unknown" and unknown["sender_organization"] is None
    assert provider["status"] == "Unknown" and provider["sender_organization"] is None
    assert "shared mail infrastructure" in provider["explanation"]
    assert not unknown["possible_exposure"] and not provider["possible_exposure"]


def test_auth_failure_and_conflicting_verdicts_keep_exposure_separate():
    failed = evaluate("mail.other.example", "spf=fail dkim=pass dmarc=pass", OTHER)
    assert failed["status"] == "Suspicious"
    assert failed["authentication"]["status"] == "failed"
    assert failed["possible_exposure"] is True
    assert failed["possible_source"] == "Amazon"


def test_display_name_cannot_establish_sender_brand_and_missing_auth_is_not_verified():
    row = classify(site_name="Amazon", site_domain="amazon.com", alias="alice@leaktrap.xyz",
                   sender_domain="amazonses.com", sender_address="Amazon Support <notice@amazonses.com>",
                   auth_results=None, alias_matched=True, evaluated_at=NOW)
    assert row["status"] == "Unknown"
    assert row["sender_organization"] is None
    assert row["authentication"]["status"] == "incomplete"
    assert domain_evidence("mail.amazon.com", AMAZON)["organization"] == "Amazon"
    assert domain_evidence("amazon.com.evil.example", AMAZON) is None


def test_classification_is_deterministic_and_has_no_ai_dependency():
    args = dict(site_name="Amazon", site_domain="amazon.com", alias="alice@leaktrap.xyz",
                sender_domain="mail.amazon.com", sender_address="n@mail.amazon.com",
                auth_results=PASS, alias_matched=True, evaluated_at=NOW)
    assert classify(**args) == classify(**args)
