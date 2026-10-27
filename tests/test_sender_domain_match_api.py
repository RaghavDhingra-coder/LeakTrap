"""Dashboard, inbox, and mobile use the same user-scoped domain comparison."""
import pytest

from tests.auth_support import mobile_token
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver, local_client  # noqa: F401

pytestmark = pytest.mark.integration


def test_domain_match_is_shared_without_overwriting_authentication(
    alice, bob, worker, signups, accounts, session,
):
    signup = signups["shop"]
    signup.site_domain = "auth.services.adobe.com"
    session.commit()
    mail_id = deliver(worker, signup.alias, 15,
                      from_header="Adobe <notice@adobe.com>",
                      auth_results="i=1; mx.cloudflare.net; spf=none; dkim=pass; dmarc=pass")["mail_log_id"]
    inbox = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    activity = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    token = mobile_token(session, accounts["alice"], scopes=("email:read",))
    mobile = local_client(session).get(f"/mobile/v1/emails/{mail_id}",
                                       headers={"Authorization": f"Bearer {token}"}).json()
    assert inbox["domain_match"] == activity["domain_match"] == mobile["domain_match"]
    assert inbox["domain_match"]["status"] == "Verified"
    assert inbox["domain_match"]["relationship"] == "sender_parent"
    assert inbox["sender_attribution"]["status"] == "Unknown"
    assert inbox["sender_attribution"]["authentication"]["results"] == {
        "spf": "none", "dkim": "pass", "dmarc": "pass"}
    assert bob.get(f"/dashboard/api/inbox/{mail_id}").status_code == 404


def test_unlinked_or_missing_website_never_gets_verified_domain_match(
    alice, worker, signups, session,
):
    signup = signups["news"]
    signup.site_domain = None
    session.commit()
    mail_id = deliver(worker, signup.alias, 16, from_header="News <notice@example.com>")["mail_log_id"]
    result = alice.get(f"/dashboard/api/inbox/{mail_id}").json()["domain_match"]
    assert result["status"] == "Review" and result["reason"] == "invalid_website_domain"


def test_unrelated_domain_is_not_verified_on_dashboard_or_mobile(
    alice, worker, signups, accounts, session,
):
    signup = signups["shop"]
    signup.site_domain = "adobe.com"
    session.commit()
    mail_id = deliver(worker, signup.alias, 17, from_header="Other <notice@unrelated.example>")["mail_log_id"]
    inbox = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    token = mobile_token(session, accounts["alice"], scopes=("email:read",))
    mobile = local_client(session).get(f"/mobile/v1/emails/{mail_id}",
                                       headers={"Authorization": f"Bearer {token}"}).json()
    assert inbox["domain_match"] == mobile["domain_match"]
    assert inbox["domain_match"]["status"] == "Not Verified"
    assert inbox["domain_match"]["relationship"] == "unrelated"
