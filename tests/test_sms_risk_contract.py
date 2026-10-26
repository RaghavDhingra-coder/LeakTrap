"""Conservative scam assessment reuses extracted URLs and user-scoped sources."""
import pytest
from tests.test_sms_api import accounts, sites, alice, bob, analyze, API  # noqa: F401
from tests.auth_support import mobile_token
from tests.test_mobile_auth_api import local_client

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("text,codes,assessment", [
    ("Urgent! Enter your password at https://exampleclinic.com@evil.example/login", {"urgency","sensitive_request","deceptive_url"}, "Likely scam"),
    ("Enter your password at https://examplecllnic.com", {"lookalike_domain","sensitive_request"}, "Likely scam"),
    ("Your account is suspended. Act now at http://192.0.2.1", {"account_threat","urgency","insecure_url","ip_url"}, "Suspicious"),
    ("Open https://bit.ly/offer", {"shortened_url"}, "Suspicious"),
    ("Your appointment at Example Clinic is confirmed. https://exampleclinic.com", set(), "Inconclusive"),
    ("Hello, see you tomorrow", set(), "Inconclusive"),
    ("Never share your password. Do not send your verification code.", set(), "Inconclusive"),
])
def test_assessment_signals(alice, sites, text, codes, assessment):
    result = analyze(alice, text)
    risk = result["risk"]
    assert risk["assessment"] == assessment
    assert codes <= {r["code"] for r in risk["reasons"]}
    assert risk["next_steps"] and "unverified" in risk["notice"]
    assert "leaked" not in risk["notice"]


def test_nickname_source_conflict_is_not_leak_proof(alice, sites):
    result = analyze(alice, "Hi Ocelot, urgent: enter your password at https://evil.example/login")
    risk = result["risk"]
    assert "source_conflict" in {r["code"] for r in risk["reasons"]}
    assert any(c["signup_id"] == sites["clinic"].id for c in result["candidates"])
    assert risk["assessment"] == "Likely scam"
    assert "not proof" in risk["notice"]


def test_other_accounts_domains_not_used(alice, sites):
    result = analyze(alice, "Hi Kestrel, enter your password at https://bobbank.example.evil.example")
    assert not ({"source_conflict","lookalike_domain"} & {r["code"] for r in result["risk"]["reasons"]})
    assert all(c["signup_id"] != sites["bob"].id for c in result["candidates"])


def test_mobile_dashboard_and_saved_risk_agree(alice, sites, session, accounts):
    text = "Urgent: enter your password at https://exampleclinic.com@evil.example/login?token=secret123"
    web = analyze(alice, text)
    phone = local_client(session)
    token = mobile_token(session, accounts["alice"], scopes=("sms:analyze",))
    response = phone.post("/mobile/v1/sms/analyze", headers={"Authorization": f"Bearer {token}"}, json={"text":text})
    assert response.status_code == 200, response.text
    assert response.json()["risk"] == web["risk"]
    assert "secret123" not in str(web["risk"])
    saved = alice.post(f"{API}/investigations", json={"text":text})
    assert saved.status_code in (200,201), saved.text
    assert saved.json()["investigation"]["risk"] == web["risk"]
