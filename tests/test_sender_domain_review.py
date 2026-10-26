"""Sender review is separate from alias matching and public leak reports."""
import pytest

from backend.models import WebsiteReport
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver  # noqa: F401

pytestmark = pytest.mark.integration
PASS = "i=1; mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass"
FAIL = "i=1; mx.cloudflare.net; spf=fail; dkim=fail; dmarc=fail"
METHOD_PASS_ONLY = "i=1; mx.cloudflare.net; spf=pass; dkim=pass"


def detail(alice, mail_id):
    response = alice.get(f"/dashboard/api/inbox/{mail_id}")
    assert response.status_code == 200, response.text
    return response.json()


def review(alice, signup_id, domain, status):
    return alice.post(f"/dashboard/api/signups/{signup_id}/sender-domains",
                      json={"domain": domain, "review_status": status})


def test_cricbuzz_sender_is_unknown_not_a_leak(alice, worker, signups, session):
    site = signups["shop"]
    site.site_name = "Cricbuzz"
    site.site_domain = "cricbuzz.com"
    session.commit()
    mail_id = deliver(worker, site.alias, 51, from_header="Cricbuzz <no-reply@cricbuzz.email>",
                      subject="Cricbuzz OTP", auth_results=PASS)["mail_log_id"]
    item = detail(alice, mail_id)
    assessment = item["sender_assessment"]
    assert item["status"] == "matched" and item["site_name"] == "Cricbuzz"
    assert item["sender_domain"] == "cricbuzz.email"
    assert assessment["alias_attribution"] == "matched"
    assert assessment["sender_domain_status"] == "unreviewed"
    assert assessment["sender_authentication"] == "provider_dmarc_pass"
    assert assessment["disclosure_status"] == "review" and assessment["confirmed_leak"] is False
    assert item["exposure"] == []
    assert session.query(WebsiteReport).count() == 0


def test_multiple_expected_domains_do_not_claim_sender_authenticity(alice, worker, signups):
    site = signups["shop"]
    for domain in ("cricbuzz.email", "transactional.example"):
        response = review(alice, site.id, domain.upper(), "expected")
        assert response.status_code == 200, response.text
    rows = alice.get(f"/dashboard/api/signups/{site.id}/sender-domains").json()
    assert {r["domain"] for r in rows} == {"cricbuzz.email", "transactional.example"}
    mail_id = deliver(worker, site.alias, 52, from_header="News <send@cricbuzz.email>")["mail_log_id"]
    assessment = detail(alice, mail_id)["sender_assessment"]
    assert assessment["sender_domain_status"] == "expected_by_user"
    assert assessment["sender_authentication"] == "not_established"
    assert assessment["disclosure_status"] == "none" and assessment["confirmed_leak"] is False


def test_user_review_plus_provider_dmarc_pass_supports_only_potential_disclosure(alice, worker, signups, session):
    site = signups["shop"]
    mail_id = deliver(worker, site.alias, 53, from_header="Offers <hi@unrelated.example>",
                      auth_results=PASS)["mail_log_id"]
    assert detail(alice, mail_id)["sender_assessment"]["disclosure_status"] == "review"
    response = review(alice, site.id, "unrelated.example", "unexpected")
    assert response.status_code == 200, response.text
    item = detail(alice, mail_id)
    assessment = item["sender_assessment"]
    assert assessment["sender_domain_status"] == "unexpected_by_user"
    assert assessment["disclosure_status"] == "potential" and assessment["confirmed_leak"] is False
    assert any("You marked" in evidence for evidence in assessment["evidence"])
    assert any("guessed" in caveat for caveat in assessment["limitations"])
    assert item["exposure"][0]["marker_type"] == "recipient_alias"
    assert session.query(WebsiteReport).count() == 0  # review never publishes a community report
    assert review(alice, site.id, "unrelated.example", "expected").status_code == 200
    assert detail(alice, mail_id)["sender_assessment"]["disclosure_status"] == "none"


def test_spoof_or_spf_dkim_only_cannot_support_disclosure(alice, worker, signups):
    site = signups["shop"]
    ids = [deliver(worker, site.alias, n, from_header="Offers <hi@unrelated.example>",
                   auth_results=verdict)["mail_log_id"]
           for n, verdict in ((54, FAIL), (55, METHOD_PASS_ONLY))]
    assert review(alice, site.id, "unrelated.example", "unexpected").status_code == 200
    for mail_id in ids:
        item = detail(alice, mail_id)
        assert item["sender_assessment"]["disclosure_status"] == "review"
        assert item["exposure"] == []
    assert detail(alice, ids[0])["sender_assessment"]["sender_authentication"] == "provider_dmarc_fail"
    assert detail(alice, ids[1])["sender_assessment"]["sender_authentication"] == "not_established"


def test_review_is_owned_validated_and_removable(alice, bob, worker, signups):
    site = signups["shop"]
    assert review(bob, site.id, "cricbuzz.email", "expected").status_code == 404
    assert review(alice, site.id, "https://cricbuzz.email/path", "expected").status_code == 422
    assert review(alice, site.id, "not-observed.example", "unexpected").status_code == 422
    assert review(alice, site.id, "cricbuzz.email", "expected").status_code == 200
    path = f"/dashboard/api/signups/{site.id}/sender-domains/cricbuzz.email"
    assert bob.delete(path).status_code == 404
    assert alice.delete(path).status_code == 204
    assert alice.get(f"/dashboard/api/signups/{site.id}/sender-domains").json() == []
