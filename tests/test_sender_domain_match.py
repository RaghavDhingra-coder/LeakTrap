"""Domain comparison never authenticates a message or guesses from names."""
from backend.services.sender_domain_match import assess


def compare(site, sender, stored=None, matched=True):
    return assess(site_domain=site, sender_address=sender, stored_sender_domain=stored,
                  alias_matched=matched)


def test_exact_domain_and_internationalized_normalization():
    result = compare("Adobe.COM.", "notice@adobe.com", "ADOBE.COM")
    assert (result["status"], result["relationship"], result["sender_domain"]) == (
        "Verified", "exact", "adobe.com")
    international = compare("bücher.de", "notice@xn--bcher-kva.de")
    assert international["status"] == "Verified"
    assert international["registered_domain"] == "xn--bcher-kva.de"
    assert international["domain_only"] is True


def test_sender_parent_and_subdomain_use_label_boundaries():
    parent = compare("auth.services.adobe.com", "notice@adobe.com")
    subdomain = compare("adobe.com", "notice@mail.adobe.com")
    assert (parent["status"], parent["relationship"]) == ("Verified", "sender_parent")
    assert (subdomain["status"], subdomain["relationship"]) == ("Verified", "sender_subdomain")
    uncertain = compare("shop.co.uk", "notice@co.uk")
    assert uncertain["status"] == "Review" and uncertain["reason"] == "uncertain_domain_boundary"


def test_unrelated_lookalike_and_sibling_domains_require_review():
    for sender in ("notice@adobe.com.evil.example", "notice@notadobe.com",
                   "notice@mail.services.adobe.com"):
        result = compare("auth.services.adobe.com", sender)
        assert result["status"] == "Not Verified" and result["relationship"] == "unrelated"
    assert "does not prove disclosure" in compare("adobe.com", "notice@other.example")["explanation"]


def test_malformed_missing_and_conflicting_sender_records_require_review():
    assert compare("adobe.com", "Adobe <notice@adobe.com>")["reason"] == "invalid_sender_address"
    assert compare("adobe.com", "notice@adobe.com", stored="other.example")["reason"] == "sender_domain_conflict"
    assert compare("adobe.com", None)["reason"] == "missing_sender_address"
    assert compare(None, "notice@adobe.com")["reason"] == "invalid_website_domain"
    assert compare("adobe.com", "notice@adobe.com", matched=False)["reason"] == "missing_website"
    assert all(compare("adobe.com", value)["status"] == "Review"
               for value in ("notice@127.0.0.1", "notice@bad domain", "notice@@adobe.com"))
