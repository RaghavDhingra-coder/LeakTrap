"""End-to-end sender attribution through ingestion and the personal dashboard API."""
import pytest
from datetime import datetime, timezone

from backend.services import domain_evidence
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver, inbox  # noqa: F401

pytestmark = pytest.mark.integration


PASS = "i=1; mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass"


def mock_domains(monkeypatch, names):
    def collect(domain):
        name = names.get(domain)
        return ({"domain": domain, "checked_at": datetime.now(timezone.utc).isoformat(),
                 "dns": {"records": [{"type": "A", "data": "93.184.216.34"}]},
                 "website": {"title": name or "", "organization_claims": [name] if name else [],
                             "observed_url": f"https://{domain}/" if name else None},
                 "source_urls": [f"https://{domain}/"]}, 86400)
    monkeypatch.setattr(domain_evidence, "collect_public_evidence", collect)


def test_amazon_alias_verified_sender_duplicate_and_user_isolation(alice, bob, worker, signups, session, monkeypatch):
    # External DNS/site retrieval is mocked; these domains never leave the test.
    mock_domains(monkeypatch, {"amazon.com": "Amazon", "mail.amazon.com": "Amazon"})
    signup = signups["shop"]
    signup.site_name, signup.site_domain = "Amazon", "amazon.com"
    session.commit()
    fields = {"from_header": "Amazon <notice@mail.amazon.com>", "auth_results": PASS,
              "message_id": "<amazon-verified@example>"}
    first = deliver(worker, signup.alias, 1, **fields)
    retry = deliver(worker, signup.alias, 1, **fields)
    assert retry["mail_log_id"] == first["mail_log_id"]
    item = alice.get(f"/dashboard/api/inbox/{first['mail_log_id']}").json()
    activity = alice.get(f"/dashboard/api/emails/{first['mail_log_id']}").json()
    attribution = item["sender_attribution"]
    assert attribution["status"] == "Verified Sender"
    assert attribution["registered_website"] == "Amazon"
    assert attribution["recipient_alias"] == signup.alias
    assert attribution["claimed_sender_address"] == "notice@mail.amazon.com"
    assert attribution["sender_organization"] == "Amazon"
    assert attribution["authentication"]["status"] == "passed"
    assert attribution["possible_source"] is None and item["exposure"] == []
    assert activity["sender_attribution"] == attribution
    assert bob.get(f"/dashboard/api/inbox/{first['mail_log_id']}").status_code == 404


def test_other_curated_org_and_possible_source_are_separate(alice, worker, signups, session, monkeypatch):
    signup = signups["shop"]
    signup.site_name, signup.site_domain = "Amazon", "amazon.com"
    mock_domains(monkeypatch, {"amazon.com": "Amazon", "mail.other.example": "Northstar Labs"})
    session.commit()
    mail_id = deliver(worker, signup.alias, 2, from_header="Amazon support <contact@mail.other.example>",
                      auth_results=PASS)["mail_log_id"]
    item = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    attr = item["sender_attribution"]
    assert attr["status"] == "Possible Third-Party Exposure"
    assert attr["sender_organization"] == "Northstar Labs"
    assert attr["possible_source"] == "Amazon"
    assert item["exposure"][0]["site_name"] == "Amazon"
    assert "not proof" in attr["explanation"] and "sold" in attr["explanation"]
    assert "Northstar Labs" != attr["possible_source"]


def test_unknown_domains_spoofed_display_names_and_failed_auth(alice, worker, signups, session, monkeypatch):
    mock_domains(monkeypatch, {"amazon.com": "Amazon", "mail.amazon.com": "Amazon"})
    signup = signups["shop"]
    signup.site_name, signup.site_domain = "Amazon", "amazon.com"
    session.commit()
    unknown_id = deliver(worker, signup.alias, 3, from_header="Amazon Support <someone@unknown.example>",
                         auth_results=PASS)["mail_log_id"]
    provider_id = deliver(worker, signup.alias, 4, from_header="Amazon Support <notice@amazonses.com>",
                           auth_results=PASS)["mail_log_id"]
    failed_id = deliver(worker, signup.alias, 5, from_header="Amazon <notice@mail.amazon.com>",
                        auth_results="i=1; mx.cloudflare.net; spf=fail; dkim=pass; dmarc=fail")["mail_log_id"]
    unknown = alice.get(f"/dashboard/api/inbox/{unknown_id}").json()["sender_attribution"]
    provider = alice.get(f"/dashboard/api/inbox/{provider_id}").json()["sender_attribution"]
    failed = alice.get(f"/dashboard/api/inbox/{failed_id}").json()["sender_attribution"]
    assert unknown["status"] == provider["status"] == "Unknown"
    assert unknown["sender_organization"] is None and provider["sender_organization"] is None
    assert failed["status"] == "Suspicious"
    assert failed["authentication"]["results"] == {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
