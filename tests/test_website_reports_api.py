"""Community report API over the disposable PostgreSQL test fixture."""
import pytest
from types import SimpleNamespace

from backend.routes import website_reports
from backend.models import Report
from backend.services.auth import LIMITS
from tests.auth_support import extension_token
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver, local_client  # noqa: F401

pytestmark = pytest.mark.integration


def test_submission_deduplication_reputation_and_privacy(alice, bob, worker, signups, session, accounts):
    signup = signups["shop"]
    message = deliver(worker, signup.alias, 40, from_header="Unknown <x@unrelated.example>")
    mail_id = message["mail_log_id"]
    assert alice.get("/dashboard/api/inbox", params={"limit": 20, "offset": 0, "filter": "all"}).json()["items"][0]["sender_attribution"]["status"] in ("Unknown", "Suspicious")
    url = "/website-reports"
    payload = {"email_id": mail_id, "confirmed_domain": "SHOP.EXAMPLE.COM."}
    assert alice.post(url, json={**payload, "confirmed_domain": "evil.example"}).status_code == 422
    assert bob.post(url, json=payload).status_code == 404
    created = alice.post(url, json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["domain"] == "shop.example.com"
    assert created.json()["status"] == "community_reported"
    assert alice.post(url, json=payload).status_code == 409
    other = deliver(worker, signup.alias, 41, from_header="Unknown <y@unrelated.example>")
    assert alice.post(url, json={"email_id": other["mail_log_id"], "confirmed_domain": "shop.example.com"}).status_code == 409
    reputation = alice.get("/website-reports/reputation", params={"domain": "www.shop.example.com"})
    assert reputation.status_code == 200
    assert reputation.json()["unique_reporters"] == 1
    assert reputation.json()["reported_domain"] == "shop.example.com"
    assert reputation.json()["last_reported_at"]
    assert bob.get("/website-reports/my").json()["items"] == []
    session.add(Report(user_id=accounts["bob"].id, site_name="Shop", site_domain="shop.example.com",
                       category="possible_data_exposure", status="community_reported"))
    session.commit()
    assert alice.get("/website-reports/reputation?domain=shop.example.com").json()["unique_reporters"] == 2
    assert len(alice.get("/website-reports/my").json()["items"]) == 1
    token = extension_token(session, accounts["bob"])
    extension = local_client(session)
    extension.headers.update({"Authorization": f"Bearer {token}"})
    assert extension.get("/website-reports/reputation?domain=shop.example.com").json()["unique_reporters"] == 2
    assert extension.post(url, json=payload).status_code == 401
    for response in (created.json(), reputation.json()):
        content = str(response)
        assert signup.alias not in content and "unrelated.example" not in content
        assert "alice@example.com" not in content and "subject" not in content


def test_domain_boundaries_and_review_authorization(alice, bob, session, accounts, monkeypatch):
    session.add(Report(user_id=accounts["alice"].id, site_name="Shop", site_domain="shop.example.com",
                       category="possible_data_exposure", status="community_reported"))
    session.commit()
    for host in ("notshop.example.com", "example.com", "shop.example.com.evil.test"):
        assert alice.get("/website-reports/reputation", params={"domain": host}).json()["unique_reporters"] == 0
    session.add(Report(user_id=accounts["bob"].id, site_name="Suffix", site_domain="co.uk",
                       category="possible_data_exposure", status="community_reported"))
    session.commit()
    assert alice.get("/website-reports/reputation?domain=example.co.uk").json()["unique_reporters"] == 0
    assert alice.get("/website-reports/reputation?domain=https://shop.example.com").status_code == 422
    row = session.query(Report).filter_by(site_domain="shop.example.com").one()
    assert bob.get("/website-reports/review").status_code == 403
    assert bob.patch(f"/website-reports/{row.id}/review", json={"status": "dismissed"}).status_code == 403
    monkeypatch.setattr(website_reports, "settings", SimpleNamespace(domain_verification_admin_emails=("alice@example.com",)))
    assert alice.get("/website-reports/review").status_code == 200
    assert alice.patch(f"/website-reports/{row.id}/review", json={"status": "confirmed_breach"}).status_code == 422
    assert alice.patch(f"/website-reports/{row.id}/review", json={"status": "dismissed"}).status_code == 200
    assert alice.get("/website-reports/reputation?domain=shop.example.com").json()["unique_reporters"] == 0


def test_verified_email_is_ineligible_and_submission_is_rate_limited(alice, worker, signups, session, monkeypatch):
    from backend.models import MailLog

    signup = signups["shop"]
    mail_id = deliver(worker, signup.alias, 42, from_header="Unknown <z@unrelated.example>")["mail_log_id"]
    log = session.get(MailLog, mail_id)
    log.sender_attribution = {"status": "Verified Sender"}
    session.commit()
    body = {"email_id": mail_id, "confirmed_domain": "shop.example.com"}
    assert alice.post("/website-reports", json=body).status_code == 422
    log.sender_attribution = {"status": "Unknown"}
    session.commit()
    monkeypatch.setitem(LIMITS, "website_report_user", (0, LIMITS["website_report_user"][1]))
    assert alice.post("/website-reports", json=body).status_code == 429
    assert alice.get("/website-reports/reputation?domain=shop.example.com").json()["unique_reporters"] == 0
