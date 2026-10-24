"""SMS analyzer API against a live PostgreSQL test database (TEST_DATABASE_URL).

Alice and Bob each own websites. Fictional messages and synthetic data only.
Every test runs in a transaction that is rolled back afterwards.
"""

import json
import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import Incident, MailLog, Signup
from backend.routes import sms as sms_routes
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.routes.ingest import IngestConfig, get_ingest_config
from tests.auth_support import ORIGIN, make_account, sign_in

pytestmark = pytest.mark.integration

API = "/dashboard/api/sms"
CLINIC = ("Your appointment at Example Clinic is confirmed for 12 Oct at 3:30pm. "
          "Contact us at appointments@exampleclinic.com or call +44 20 7946 0958.")
OTP = ("123456 is your Example Shop verification code. Reset your password: "
       "https://shop.example.com/reset?token=abcdEFGH1234ijklMNOP")
SECRET = "k" * 48


@pytest.fixture(autouse=True)
def alias_domain(monkeypatch):
    monkeypatch.setattr(sms_routes, "settings", replace(sms_routes.settings, alias_domain="leaktrap.xyz"))


def local_client(session: Session) -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    app.dependency_overrides[get_ingest_config] = lambda: IngestConfig(SECRET, 16384, "leaktrap.xyz")
    return TestClient(app, client=("127.0.0.1", 50000))


@pytest.fixture
def accounts(session: Session) -> dict:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


@pytest.fixture
def sites(session: Session, accounts) -> dict[str, Signup]:
    a, b = accounts["alice"].id, accounts["bob"].id
    rows = {
        "clinic": Signup(user_id=a, site_name="Example Clinic", site_domain="exampleclinic.com",
                         alias="ab12cd34@leaktrap.xyz", nickname="Ocelot", surname_variant="Smyth"),
        "shop": Signup(user_id=a, site_name="Example Shop", site_domain="shop.example.com", alias="ef56gh78@leaktrap.xyz"),
        "acme1": Signup(user_id=a, site_name="Acme", site_domain="acme-one.example"),
        "acme2": Signup(user_id=a, site_name="Acme", site_domain="acme-two.example"),
        "bob": Signup(user_id=b, site_name="Bob Bank", site_domain="bobbank.example", alias="bob1bob1@leaktrap.xyz",
                      nickname="Kestrel"),
    }
    session.add_all(rows.values())
    session.commit()
    return rows


@pytest.fixture
def alice(session, accounts):
    client = local_client(session)
    sign_in(client, session, accounts["alice"])
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def bob(session, accounts):
    client = local_client(session)
    sign_in(client, session, accounts["bob"])
    return client


def analyze(client, text, **fields):
    r = client.post(f"{API}/analyze", json={"text": text, **fields})
    assert r.status_code == 200, r.text
    return r.json()


def candidate(result, key):
    return next(c for c in result["candidates"] if c["key"] == key)


def incidents(session):
    session.expire_all()
    return session.scalar(select(func.count()).select_from(Incident).where(Incident.channel == "sms"))


# ---------- source matching ----------

def test_named_website_with_its_domain_is_a_strong_match_and_nothing_is_stored(alice, session, sites) -> None:
    result = analyze(alice, CLINIC, sender="+44 7700 900123")
    assert result["status"] == "strong"
    c = candidate(result, f"signup:{sites['clinic'].id}")
    assert (c["status"], c["name"], c["signup_id"]) == ("strong", "Example Clinic", sites["clinic"].id)
    assert {s["type"] for s in c["signals"]} == {"name_in_message", "domain_in_message"}
    assert any("Example Clinic" in (s["excerpt"] or "") for s in c["signals"])
    assert any("does not show how the sender obtained your phone number" in u for u in c["unknowns"])
    assert any("No LeakTrace alias or nickname" in u for u in c["unknowns"])
    assert (c["email_count"], c["sms_count"]) == (0, 0)
    phone = next(e for e in result["entities"] if e["type"] == "phone")
    assert phone["relation"].startswith("LeakTrace does not store phone numbers")
    assert result["sender"] == {"type": "phone", "display": "+44•••••••123"}
    assert any("does not mean it is the service that collected your number" in n for n in result["sender_notes"])
    assert "does not show who collected your phone number" in result["notice"]
    assert incidents(session) == 0  # analysis stores nothing


def test_leaktrace_markers_identify_the_website(alice, sites) -> None:
    result = analyze(alice, "Hi Ocelot, your booking is ready. Questions? Reply to ab12cd34@leaktrap.xyz")
    c = candidate(result, f"signup:{sites['clinic'].id}")
    assert {s["type"] for s in c["signals"]} == {"alias_in_message", "nickname_in_message"}
    assert c["status"] == "possible"  # two markers, but both are the same kind of evidence
    relations = {e["type"]: e["relation"] for e in result["entities"]}
    assert relations["email"] == "Your LeakTrace alias for Example Clinic."
    assert relations["person"] == "The nickname you use only for Example Clinic."


def test_message_with_no_identifiable_source(alice, sites) -> None:
    result = analyze(alice, "Hey, are we still on for tonight?")
    assert (result["status"], result["candidates"]) == ("unknown", [])
    assert "No business or service name was found in the message." in result["missing"]
    assert "No sender was given." in result["missing"]


def test_service_that_is_not_one_of_your_websites(alice, sites) -> None:
    result = analyze(alice, "Your order at Parcel Express has shipped. Help: support@parcelexpress.com")
    c = candidate(result, "domain:parcelexpress.com")
    assert (c["name"], c["signup_id"], c["status"]) == ("Parcel Express", None, "strong")
    assert any("not one of your LeakTrace websites" in u for u in c["unknowns"])


def test_ambiguous_company_name_is_never_strong(alice, sites) -> None:
    result = analyze(alice, "Thanks for shopping with Acme today!")
    acmes = [c for c in result["candidates"] if c["name"] == "Acme"]
    assert len(acmes) == 2 and {c["status"] for c in acmes} == {"possible"}
    assert all(c["signals"][0]["weak"] and "ambiguous" in c["signals"][0]["explanation"] for c in acmes)
    assert result["status"] == "possible"


def test_conflicting_evidence_suggests_no_single_source(alice, sites) -> None:
    text = ("Example Clinic: see exampleclinic.com. Also your Example Shop order is at https://shop.example.com/o/1")
    result = analyze(alice, text)
    strong = [c["name"] for c in result["candidates"] if c["status"] == "strong"]
    assert sorted(strong) == ["Example Clinic", "Example Shop"]
    assert result["status"] == "possible"
    assert any("more than one service" in w for w in result["warnings"])


def test_sender_is_never_treated_as_the_source(alice, sites) -> None:
    result = analyze(alice, "Your appointment is tomorrow.", sender="ExampleShop")
    c = candidate(result, f"signup:{sites['shop'].id}")
    assert [s["type"] for s in c["signals"]] == ["sender_id_name"]
    assert c["signals"][0]["weak"] and "spoofed" in c["signals"][0]["explanation"]
    assert c["status"] == "possible" and result["status"] != "strong"
    assert any("spoofed" in n for n in result["sender_notes"])


def test_unknown_and_invalid_sender_identifiers(alice, sites) -> None:
    assert analyze(alice, "Hello", sender="62820")["sender"] == {"type": "short_code", "display": "62820"}
    r = alice.post(f"{API}/analyze", json={"text": "Hello", "sender": "<script>"})
    assert r.status_code == 422 and r.json()["detail"][0]["loc"] == ["sender"]


def test_shortened_links_are_not_used_as_evidence(alice, sites) -> None:
    result = analyze(alice, "Your parcel is waiting: bit.ly/3xYzQ1")
    assert result["candidates"] == []
    assert any("shortened link" in w.lower() for w in result["warnings"])


# ---------- corrections ----------

def test_user_corrections_exclude_and_add_details(alice, sites) -> None:
    first = analyze(alice, CLINIC)
    business = next(e for e in first["entities"] if e["type"] == "business")
    email = next(e for e in first["entities"] if e["type"] == "email")
    # Excluding the address leaves only the name: the website drops to "possible".
    corrected = analyze(alice, CLINIC, exclude=[email["key"]])
    assert candidate(corrected, f"signup:{sites['clinic'].id}")["status"] == "possible"
    assert next(e for e in corrected["entities"] if e["key"] == email["key"])["excluded"] is True
    # Adding a domain the analyzer missed links an unrelated website.
    added = analyze(alice, "Your order has shipped.", additions=[{"type": "domain", "value": "shop.example.com"}])
    c = candidate(added, f"signup:{sites['shop'].id}")
    assert [s["type"] for s in c["signals"]] == ["domain_in_message"] and c["signals"][0]["excerpt"] is None
    assert next(e for e in added["entities"] if e["key"] == "added:0")["certainty"] == "user_added"
    assert business["certainty"] == "uncertain"


# ---------- privacy ----------

def test_sensitive_values_never_appear_in_any_response(alice, session, sites) -> None:
    result = analyze(alice, OTP)
    raw = json.dumps(result)
    for secret in ("123456", "abcdEFGH1234ijklMNOP", "token="):
        assert secret not in raw, secret
    assert "[code hidden]" in result["redacted_text"] and "[link hidden]" in result["redacted_text"]
    saved = alice.post(f"{API}/investigations", json={"text": OTP, "store_text": True}).json()
    session.expire_all()
    row = session.get(Incident, saved["investigation"]["id"])
    stored = json.dumps(row.evidence) + (row.message_text or "")
    for secret in ("123456", "abcdEFGH1234ijklMNOP"):
        assert secret not in stored and secret not in json.dumps(saved)


def test_saved_evidence_has_no_personal_identifiers(alice, session, sites) -> None:
    saved = alice.post(f"{API}/investigations", json={"text": CLINIC, "sender": "+44 7700 900123", "label": "work phone"}).json()
    session.expire_all()
    row = session.get(Incident, saved["investigation"]["id"])
    assert row.message_text is None  # text kept only when asked
    stored = json.dumps(row.evidence)
    for value in ("appointments@exampleclinic.com", "+442079460958", "7946"):
        assert value not in stored
    assert row.evidence["entity_counts"]["email"] == 1 and row.evidence["domains"] == ["exampleclinic.com"]
    assert saved["investigation"]["sender"] == {"type": "phone", "display": "+44•••••••123"}
    assert saved["investigation"]["label"] == "work phone"


def test_logs_never_contain_message_text_or_identifiers(alice, sites, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    analyze(alice, CLINIC, sender="+44 7700 900123")
    alice.post(f"{API}/investigations", json={"text": OTP})
    text = caplog.text.lower()
    for value in ("example clinic", "appointments@", "7946", "7700", "123456", "abcdefgh", "reset"):
        assert value not in text, value
    assert "sms analysis: entities=" in text


# ---------- malformed and adversarial input ----------

@pytest.mark.parametrize(("body", "loc"), [
    ({}, ["text"]), ({"text": "   "}, ["text"]), ({"text": "x" * 2001}, ["text"]),
    ({"text": "hi", "evil": 1}, ["evil"]), ({"text": "hi", "exclude": ["drop table"]}, ["exclude"]),
    ({"text": "hi", "additions": [{"type": "email", "value": "not-an-email"}]}, ["additions", 0, "value"]),
    ({"text": "hi", "additions": [{"type": "password", "value": "x"}]}, ["additions", 0, "type"]),
    ({"text": "hi", "received_at": "2026-10-24T10:00:00"}, ["received_at"]),
    ({"text": "hi", "received_at": "2999-01-01T00:00:00Z"}, ["received_at"]),
    ({"text": "hi", "label": "a\u0000b"}, ["label"]),
])
def test_invalid_requests_are_422_and_never_echo_the_text(alice, sites, body, loc) -> None:
    r = alice.post(f"{API}/analyze", json=body)
    assert r.status_code == 422, r.text
    assert r.json()["detail"][0]["loc"] == loc
    assert "x" * 50 not in r.text and '"input"' not in r.text


def test_size_and_content_type_limits(alice, sites) -> None:
    assert alice.post(f"{API}/analyze", content=b"text=hi", headers={"content-type": "text/plain"}).status_code == 415
    assert alice.post(f"{API}/analyze", json={"text": "a" * 20000}).status_code == 413
    assert alice.post(f"{API}/analyze", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422


def test_markup_in_messages_is_returned_as_plain_text(alice, sites) -> None:
    result = analyze(alice, '<img src=x onerror=alert(1)> Your Example Shop order shipped')
    assert result["redacted_text"].startswith("<img src=x onerror=alert(1)>")  # rendered with textContent only


# ---------- saving, duplicates, actions ----------

def test_saving_twice_returns_the_existing_record(alice, session, sites) -> None:
    body = {"text": CLINIC, "sender": "ExampleClnc", "received_at": "2026-10-20T09:00:00Z"}
    first = alice.post(f"{API}/investigations", json=body)
    again = alice.post(f"{API}/investigations", json={**body, "text": CLINIC.replace(" ", "  ")})  # whitespace only
    other = alice.post(f"{API}/investigations", json={**body, "received_at": "2026-10-21T09:00:00Z"})
    assert (first.status_code, again.status_code, other.status_code) == (201, 200, 201)
    assert again.json()["duplicate"] is True and again.json()["investigation"]["id"] == first.json()["investigation"]["id"]
    assert incidents(session) == 2


def test_confirm_reject_review_and_manual_association(alice, bob, sites) -> None:
    saved = alice.post(f"{API}/investigations", json={"text": CLINIC}).json()["investigation"]
    url = f"{API}/investigations/{saved['id']}/actions"
    clinic_key = f"signup:{sites['clinic'].id}"
    assert saved["status"] == "strong" and saved["matched_site"] == "Example Clinic"

    confirmed = alice.post(url, json={"action": "confirm", "candidate_key": clinic_key}).json()
    assert confirmed["status"] == "confirmed" and confirmed["confirmed"]["signup_id"] == sites["clinic"].id
    rejected = alice.post(url, json={"action": "reject", "candidate_key": clinic_key}).json()
    assert rejected["confirmed"] is None and rejected["rejected"] == [clinic_key] and rejected["status"] == "unknown"
    manual = alice.post(url, json={"action": "confirm", "signup_id": sites["shop"].id}).json()
    assert manual["confirmed"] == {"key": f"signup:{sites['shop'].id}", "signup_id": sites["shop"].id,
                                   "name": "Example Shop", "manual": True}
    reviewed = alice.post(url, json={"action": "reviewed"}).json()
    assert reviewed["reviewed"] is True and reviewed["reviewed_at"]
    # Bob's website cannot be linked; unknown suggestions are refused.
    assert alice.post(url, json={"action": "confirm", "signup_id": sites["bob"].id}).status_code == 422
    assert alice.post(url, json={"action": "reject", "candidate_key": "domain:nope.example"}).status_code == 422
    assert alice.post(url, json={"action": "explode"}).status_code == 422


def test_earlier_confirmation_of_a_sender_is_used_as_evidence(alice, sites) -> None:
    saved = alice.post(f"{API}/investigations", json={"text": CLINIC, "sender": "Example Clnc"}).json()["investigation"]
    alice.post(f"{API}/investigations/{saved['id']}/actions", json={"action": "confirm", "candidate_key": f"signup:{sites['clinic'].id}"})
    later = analyze(alice, "Reminder: you have a visit tomorrow.", sender="EXAMPLE-CLNC")
    c = candidate(later, f"signup:{sites['clinic'].id}")
    assert [s["type"] for s in c["signals"]] == ["sender_previously_confirmed"]
    assert "You confirmed 1 earlier message from this sender" in c["signals"][0]["explanation"]
    assert c["sms_count"] == 1


# ---------- other users ----------

def test_users_never_see_each_others_records(alice, bob, sites) -> None:
    # Bob's alias and nickname in Alice's message reveal nothing about Bob.
    result = analyze(alice, "Hi Kestrel, write to bob1bob1@leaktrap.xyz about Bob Bank")
    assert all(c["signup_id"] in (None,) for c in result["candidates"])
    assert "Kestrel" not in json.dumps(result["candidates"])
    email = next(e for e in result["entities"] if e["type"] == "email")
    assert email["relation"] == "An address at your alias domain that is not one of your aliases."

    saved = alice.post(f"{API}/investigations", json={"text": CLINIC}).json()["investigation"]
    for method, path, body in [("GET", f"{API}/investigations/{saved['id']}", None),
                               ("POST", f"{API}/investigations/{saved['id']}/actions", {"action": "reviewed"}),
                               ("DELETE", f"{API}/investigations/{saved['id']}", None)]:
        assert bob.request(method, path, json=body).status_code == 404, path
    assert bob.get(f"{API}/investigations").json()["total"] == 0
    assert all(i["channel"] != "sms" for i in bob.get("/dashboard/api/timeline").json()["items"])
    assert alice.get(f"{API}/investigations/{saved['id']}").status_code == 200


def test_csrf_and_extension_tokens_are_refused(alice, session, sites) -> None:
    csrf = alice.headers.pop("X-CSRF-Token")
    try:
        assert alice.post(f"{API}/analyze", json={"text": "hi"}).status_code == 403
    finally:
        alice.headers["X-CSRF-Token"] = csrf
    anonymous = local_client(session)
    assert anonymous.post(f"{API}/analyze", json={"text": "hi"}, headers={"Origin": ORIGIN}).status_code == 401


# ---------- cross-channel ----------

def test_timeline_and_website_detail_link_email_and_sms(alice, session, sites) -> None:
    ingest = local_client(session).post("/ingest/email", headers={"Authorization": f"Bearer {SECRET}"}, json={
        "recipient": "ab12cd34@leaktrap.xyz", "from_header": "Clinic <news@exampleclinic.com>", "subject": "Hello",
        "message_id": "<sms-test-1@x>", "received_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()})
    assert ingest.status_code == 201  # email ingestion is unchanged by the SMS feature
    saved = alice.post(f"{API}/investigations", json={
        "text": CLINIC, "received_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}).json()["investigation"]
    alice.post(f"{API}/investigations/{saved['id']}/actions", json={"action": "confirm", "candidate_key": f"signup:{sites['clinic'].id}"})
    items = alice.get("/dashboard/api/timeline").json()["items"]
    assert [i["channel"] for i in items] == ["sms", "email"]
    assert {(i["channel"], i["signup_id"], i["linked"]) for i in items} == {
        ("sms", sites["clinic"].id, True), ("email", sites["clinic"].id, True)}
    detail = alice.get(f"/dashboard/api/signups/{sites['clinic'].id}").json()
    assert detail["sms_investigations"][0]["confirmed"] is True and len(detail["emails"]) == 1
    # A later analysis shows the email already received by this website.
    c = candidate(analyze(alice, CLINIC), f"signup:{sites['clinic'].id}")
    assert c["email_count"] == 1 and c["last_email_at"]
    # Leak activity lists the SMS investigation next to email ones.
    investigations = alice.get("/dashboard/api/investigations").json()["items"]
    assert [(i["channel"], i["result"]) for i in investigations] == [("sms", "confirmed")]
    session.expire_all()
    assert session.scalar(select(func.count()).select_from(MailLog)) == 1  # SMS never creates email records


def test_a_shared_company_name_never_links_records(alice, session, sites) -> None:
    alice.post(f"{API}/investigations", json={"text": "Thanks for shopping with Acme today!"})
    sms_items = [i for i in alice.get("/dashboard/api/timeline").json()["items"] if i["channel"] == "sms"]
    assert [(i["linked"], i["signup_id"]) for i in sms_items] == [(False, None)]


def test_delete_saved_investigation(alice, session, sites) -> None:
    saved = alice.post(f"{API}/investigations", json={"text": CLINIC}).json()["investigation"]
    assert alice.delete(f"{API}/investigations/{saved['id']}").status_code == 204
    assert alice.get(f"{API}/investigations/{saved['id']}").status_code == 404
    assert incidents(session) == 0
