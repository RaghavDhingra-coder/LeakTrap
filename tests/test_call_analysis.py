"""Call transcripts use the owner's existing evidence without storing audio."""
import pytest

from tests.auth_support import mobile_token
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver  # noqa: F401

pytestmark = pytest.mark.integration


def test_call_alias_lead_is_shared_with_dashboard_and_scoped(worker, alice, bob, accounts, signups, session):
    deliver(worker, signups["shop"].alias, 39)
    token = mobile_token(session, accounts["alice"], scopes=("call:analyze", "call:write"))
    bob_token = mobile_token(session, accounts["bob"], scopes=("call:analyze", "call:write"))
    headers = {"Authorization": f"Bearer {token}"}
    response = worker.post("/mobile/v1/calls/analyze", headers=headers,
                           json={"transcript": f"Hello Ocelot, confirm {signups['shop'].alias}.",
                                 "save": True, "store_redacted_transcript": True})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["id"] and result["redacted_transcript"]
    assert signups["shop"].alias not in result["redacted_transcript"]
    assert any(e["type"] == "email" for e in result["entities"])
    [lead] = [e for e in result["exposure"] if e["site_name"] == "Example Shop"]
    assert lead["marker_type"] == "alias_mention"
    assert lead["observed_source"] is None
    assert "not proof" in lead["caveat"]
    assert next(c for c in result["candidates"] if c["signup_id"] == signups["shop"].id)["email_count"] == 1
    web = alice.get("/dashboard/api/calls").json()
    assert web["items"][0]["exposure"] == result["exposure"]
    assert worker.get("/mobile/v1/calls", headers={"Authorization": f"Bearer {bob_token}"}).json()["items"] == []
    assert worker.delete(f"/mobile/v1/calls/{result['id']}", headers={"Authorization": f"Bearer {bob_token}"}).status_code == 404
    assert worker.delete(f"/mobile/v1/calls/{result['id']}", headers=headers).status_code == 204
    assert alice.get("/dashboard/api/calls").json()["items"] == []


def test_call_nickname_without_url_is_a_weak_owner_only_lead(worker, accounts, signups, session):
    signups["shop"].nickname = "Ember"
    session.commit()
    token = mobile_token(session, accounts["alice"], scopes=("call:analyze",))
    response = worker.post("/mobile/v1/calls/analyze", headers={"Authorization": f"Bearer {token}"},
                           json={"transcript": "Hi Ember, win today 1 crore"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert any(e["site_name"] == "Example Shop" and e["marker_type"] == "nickname_mention"
               and e["confidence"] == "low" for e in result["exposure"])
    assert all(e["signup_id"] != signups["bob"].id for e in result["exposure"])
    assert all(e["observed_source"] is None for e in result["exposure"])
    assert result["id"] is None


def test_call_analysis_defaults_to_no_storage_and_requires_scopes(worker, accounts, signups, session):
    read = mobile_token(session, accounts["alice"], scopes=("call:analyze",))
    headers = {"Authorization": f"Bearer {read}"}
    transcript = "Hi Ocelot, see example.org"
    analysis = worker.post("/mobile/v1/calls/analyze", headers=headers, json={"transcript": transcript})
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["id"] is None
    assert worker.get("/mobile/v1/calls", headers=headers).json()["total"] == 0
    assert worker.post("/mobile/v1/calls/analyze", headers=headers,
                       json={"transcript": transcript, "save": True}).status_code == 403
    assert worker.post("/mobile/v1/calls/analyze", json={"transcript": transcript}).status_code == 401
    assert worker.post("/mobile/v1/calls/analyze", headers=headers,
                       json={"transcript": " " * 8001}).status_code in (413, 422)
