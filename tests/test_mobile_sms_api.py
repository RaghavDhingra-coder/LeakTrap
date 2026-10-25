"""Mobile SMS investigation routes against the isolated PostgreSQL test database.

They run the dashboard's SMS analyzer and investigation services through the
same shared request handling (backend.routes.sms_shared), so for the same user
and input they must return what the dashboard returns, store the same records
and refuse the same input, while accepting only a mobile Bearer token with
sms:analyze (analysis, reads) or sms:write (save, actions, delete).
Fictional messages and synthetic data only.
"""

import json
import logging
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import Incident, UserSession
from backend.routes import mobile as mobile_routes
from backend.routes import sms as sms_routes
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.security import MOBILE_SCOPES
from backend.services import auth as auth_service
from backend.services.auth import now, token_hash
from tests.auth_support import extension_token, mobile_token, sign_in
from tests.test_sms_api import CLINIC, OTP, accounts, sites  # noqa: F401 (fixtures)

pytestmark = pytest.mark.integration

DASH = "/dashboard/api/sms"
MOB = "/mobile/v1/sms"
SMS_SCOPES = ("sms:analyze", "sms:write")


@pytest.fixture(autouse=True)
def alias_domain(monkeypatch):
    for module in (sms_routes, mobile_routes):
        monkeypatch.setattr(module, "settings", replace(module.settings, alias_domain="leaktrap.xyz"))


def make_client(session: Session, host: str = "127.0.0.1") -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    return TestClient(app, client=(host, 50000))


@pytest.fixture
def web(session: Session, accounts, sites):  # noqa: F811
    """Alice's dashboard session, for comparing responses."""
    client = make_client(session)
    sign_in(client, session, accounts["alice"])
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def phone(session: Session, web):
    return make_client(session)


@pytest.fixture
def alice_token(session: Session, accounts) -> str:  # noqa: F811
    return mobile_token(session, accounts["alice"], scopes=SMS_SCOPES)


@pytest.fixture
def bob_token(session: Session, accounts) -> str:  # noqa: F811
    return mobile_token(session, accounts["bob"], scopes=SMS_SCOPES)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def call(phone, token, method, path, body=None, expect=200):
    r = phone.request(method, path, json=body, headers=bearer(token))
    assert r.status_code == expect, (method, path, r.status_code, r.text)
    return r.json() if r.content else None


def sms_rows(session) -> int:
    session.expire_all()
    return session.scalar(select(func.count()).select_from(Incident).where(Incident.channel == "sms"))


def save(phone, token, body, expect=201) -> dict:
    return call(phone, token, "POST", f"{MOB}/investigations", body, expect)["investigation"]


# ---------- analysis ----------

@pytest.mark.parametrize("body", [
    {"text": CLINIC},
    {"text": OTP},
    {"text": CLINIC, "sender": "+44 7700 900123", "label": "work phone", "received_at": "2026-10-20T09:00:00Z"},
    {"text": CLINIC, "exclude": ["email:0"], "additions": [{"type": "domain", "value": "exampleclinic.com"}]},
    {"text": "Hi Kestrel, write to bob1bob1@leaktrap.xyz about Bob Bank"},
    {"text": "Thanks for shopping with Acme today!"},
])
def test_analysis_matches_the_dashboard_and_stores_nothing(phone, web, session, alice_token, body) -> None:
    expected = web.post(f"{DASH}/analyze", json=body)
    assert expected.status_code == 200
    assert call(phone, alice_token, "POST", f"{MOB}/analyze", body) == expected.json()
    assert sms_rows(session) == 0


def test_analysis_suggests_the_users_own_website(phone, alice_token, sites) -> None:  # noqa: F811
    result = call(phone, alice_token, "POST", f"{MOB}/analyze", {"text": CLINIC})
    assert result["status"] == "strong"
    [top] = [c for c in result["candidates"] if c["status"] == "strong"]
    assert (top["signup_id"], top["name"]) == (sites["clinic"].id, "Example Clinic")
    assert result["limitations"] and "does not show who collected" in result["notice"]


def test_sensitive_values_are_redacted(phone, session, alice_token) -> None:
    result = call(phone, alice_token, "POST", f"{MOB}/analyze", {"text": OTP})
    raw = json.dumps(result)
    for secret in ("123456", "abcdEFGH1234ijklMNOP", "token="):
        assert secret not in raw, secret
    assert "[code hidden]" in result["redacted_text"] and "[link hidden]" in result["redacted_text"]
    assert all(e["value"] is None for e in result["entities"] if e["sensitive"])


# ---------- saving, reading, actions, deletion ----------

def test_save_list_get_and_delete_match_the_dashboard(phone, web, session, alice_token) -> None:
    body = {"text": CLINIC, "sender": "ExampleClnc", "received_at": "2026-10-20T09:00:00Z"}
    r = phone.post(f"{MOB}/investigations", json=body, headers=bearer(alice_token))
    assert r.status_code == 201 and r.json()["duplicate"] is False
    saved = r.json()["investigation"]
    again = phone.post(f"{MOB}/investigations", json={**body, "text": CLINIC.replace(" ", "  ")}, headers=bearer(alice_token))
    assert again.status_code == 200 and again.json() == {"investigation": saved, "duplicate": True}
    # The same message saved from the dashboard is the same record.
    from_web = web.post(f"{DASH}/investigations", json=body)
    assert from_web.status_code == 200 and from_web.json()["investigation"]["id"] == saved["id"]
    assert sms_rows(session) == 1

    listing = call(phone, alice_token, "GET", f"{MOB}/investigations")
    assert listing == web.get(f"{DASH}/investigations").json()
    assert (listing["total"], listing["limit"], listing["offset"]) == (1, 20, 0)
    one = call(phone, alice_token, "GET", f"{MOB}/investigations/{saved['id']}")
    assert one == web.get(f"{DASH}/investigations/{saved['id']}").json() == saved

    assert phone.delete(f"{MOB}/investigations/{saved['id']}", headers=bearer(alice_token)).status_code == 204
    assert phone.get(f"{MOB}/investigations/{saved['id']}", headers=bearer(alice_token)).status_code == 404
    assert web.get(f"{DASH}/investigations/{saved['id']}").status_code == 404
    assert phone.delete(f"{MOB}/investigations/{saved['id']}", headers=bearer(alice_token)).status_code == 404
    assert sms_rows(session) == 0


def test_pagination(phone, alice_token) -> None:
    for day in range(1, 4):
        save(phone, alice_token, {"text": CLINIC, "received_at": f"2026-10-0{day}T09:00:00Z"})
    page = call(phone, alice_token, "GET", f"{MOB}/investigations?limit=2&offset=1")
    assert (len(page["items"]), page["total"], page["limit"], page["offset"]) == (2, 3, 2, 1)
    assert call(phone, alice_token, "GET", f"{MOB}/investigations?offset=10")["items"] == []


def test_store_text_stays_off_unless_asked_and_is_redacted(phone, session, alice_token) -> None:
    plain = save(phone, alice_token, {"text": CLINIC})
    assert plain["stored_text"] is None
    session.expire_all()
    assert session.get(Incident, plain["id"]).message_text is None

    kept = save(phone, alice_token, {"text": OTP, "store_text": True})
    assert kept["stored_text"] and "[code hidden]" in kept["stored_text"]
    session.expire_all()
    row = session.get(Incident, kept["id"])
    stored = json.dumps(row.evidence) + (row.message_text or "") + json.dumps(kept)
    for secret in ("123456", "abcdEFGH1234ijklMNOP"):
        assert secret not in stored, secret


def test_actions_match_the_dashboard(phone, web, alice_token, sites) -> None:  # noqa: F811
    saved = save(phone, alice_token, {"text": CLINIC})
    url = f"{MOB}/investigations/{saved['id']}/actions"
    clinic_key = f"signup:{sites['clinic'].id}"

    confirmed = call(phone, alice_token, "POST", url, {"action": "confirm", "candidate_key": clinic_key})
    assert confirmed["status"] == "confirmed" and confirmed["confirmed"]["signup_id"] == sites["clinic"].id
    rejected = call(phone, alice_token, "POST", url, {"action": "reject", "candidate_key": clinic_key})
    assert rejected["confirmed"] is None and rejected["rejected"] == [clinic_key] and rejected["status"] == "unknown"
    manual = call(phone, alice_token, "POST", url, {"action": "confirm", "signup_id": sites["shop"].id})
    assert manual["confirmed"] == {"key": f"signup:{sites['shop'].id}", "signup_id": sites["shop"].id,
                                   "name": "Example Shop", "manual": True}
    reviewed = call(phone, alice_token, "POST", url, {"action": "reviewed"})
    assert reviewed["reviewed"] is True and reviewed["reviewed_at"]
    unreviewed = call(phone, alice_token, "POST", url, {"action": "unreviewed"})
    assert unreviewed["reviewed"] is False and unreviewed["reviewed_at"] is None
    cleared = call(phone, alice_token, "POST", url, {"action": "clear"})
    assert cleared["confirmed"] is None and cleared["rejected"] == []
    assert cleared == web.get(f"{DASH}/investigations/{saved['id']}").json()

    # Refused exactly as on the dashboard: another user's website, unknown suggestions and actions.
    for body in ({"action": "confirm", "signup_id": sites["bob"].id}, {"action": "reject", "candidate_key": "domain:nope.example"},
                 {"action": "confirm"}, {"action": "explode"}, {"action": "reviewed", "extra": 1}, {}):
        m = phone.post(url, json=body, headers=bearer(alice_token))
        d = web.post(f"{DASH}/investigations/{saved['id']}/actions", json=body)
        assert m.status_code == d.status_code == 422, body
        assert m.json() == d.json()


def test_timeline_shows_mobile_saved_investigations(phone, alice_token, session, accounts, sites) -> None:  # noqa: F811
    saved = save(phone, alice_token, {"text": CLINIC})
    call(phone, alice_token, "POST", f"{MOB}/investigations/{saved['id']}/actions",
         {"action": "confirm", "candidate_key": f"signup:{sites['clinic'].id}"})
    reader = mobile_token(session, accounts["alice"], scopes=("timeline:read",))
    items = call(phone, reader, "GET", "/mobile/v1/timeline")["items"]
    assert [(i["channel"], i["id"], i["signup_id"], i["linked"]) for i in items] == [
        ("sms", saved["id"], sites["clinic"].id, True)]


# ---------- isolation ----------

def test_other_users_records_behave_like_missing_ones(phone, web, session, alice_token, bob_token, sites) -> None:  # noqa: F811
    saved = save(phone, alice_token, {"text": CLINIC})
    for method, suffix, body in [("GET", "", None), ("POST", "/actions", {"action": "reviewed"}), ("DELETE", "", None)]:
        missing = phone.request(method, f"{MOB}/investigations/987654321{suffix}", json=body, headers=bearer(bob_token))
        theirs = phone.request(method, f"{MOB}/investigations/{saved['id']}{suffix}", json=body, headers=bearer(bob_token))
        assert missing.status_code == theirs.status_code == 404, (method, suffix)
        assert missing.json() == theirs.json() == {"detail": "SMS investigation not found"}
    assert call(phone, bob_token, "GET", f"{MOB}/investigations")["total"] == 0
    # Nothing Bob tried changed Alice's record.
    assert call(phone, alice_token, "GET", f"{MOB}/investigations/{saved['id']}") == saved
    # Bob's records never help analyse Alice's messages.
    result = call(phone, alice_token, "POST", f"{MOB}/analyze", {"text": "Hi Kestrel, write to bob1bob1@leaktrap.xyz about Bob Bank"})
    assert all(c["signup_id"] is None for c in result["candidates"])
    assert "Kestrel" not in json.dumps(result["candidates"])


def test_saved_records_ignore_a_user_id_in_the_body_or_query(phone, alice_token, bob_token, accounts) -> None:  # noqa: F811
    assert phone.post(f"{MOB}/investigations", json={"text": CLINIC, "user_id": accounts["bob"].id},
                      headers=bearer(alice_token)).status_code == 422
    save(phone, alice_token, {"text": CLINIC})
    assert call(phone, bob_token, "GET", f"{MOB}/investigations?user_id={accounts['alice'].id}")["total"] == 0


# ---------- input validation ----------

@pytest.mark.parametrize(("body", "loc"), [
    ({}, ["text"]), ({"text": "   "}, ["text"]), ({"text": "x" * 2001}, ["text"]),
    ({"text": "hi", "evil": 1}, ["evil"]), ({"text": "hi", "exclude": ["drop table"]}, ["exclude"]),
    ({"text": "hi", "additions": [{"type": "email", "value": "not-an-email"}]}, ["additions", 0, "value"]),
    ({"text": "hi", "additions": [{"type": "password", "value": "x"}]}, ["additions", 0, "type"]),
    ({"text": "hi", "received_at": "2026-10-24T10:00:00"}, ["received_at"]),
    ({"text": "hi", "received_at": "2999-01-01T00:00:00Z"}, ["received_at"]),
    ({"text": "hi", "label": "a\u0000b"}, ["label"]),
])
@pytest.mark.parametrize("path", ["/analyze", "/investigations"])
def test_invalid_requests_match_the_dashboard_and_never_echo_the_text(phone, web, session, alice_token, body, loc, path) -> None:
    m = phone.post(f"{MOB}{path}", json=body, headers=bearer(alice_token))
    d = web.post(f"{DASH}{path}", json=body)
    assert m.status_code == d.status_code == 422, m.text
    assert m.json() == d.json() and m.json()["detail"][0]["loc"] == loc
    assert "x" * 50 not in m.text and '"input"' not in m.text
    assert sms_rows(session) == 0


def test_store_text_must_be_a_boolean(phone, alice_token) -> None:
    r = phone.post(f"{MOB}/investigations", json={"text": CLINIC, "store_text": "yes please"}, headers=bearer(alice_token))
    assert r.status_code == 422 and r.json()["detail"][0]["loc"] == ["store_text"]


@pytest.mark.parametrize("path", ["/analyze", "/investigations"])
def test_size_and_content_type_limits(phone, alice_token, path) -> None:
    url = f"{MOB}{path}"
    assert phone.post(url, content=b"text=hi", headers={**bearer(alice_token), "content-type": "text/plain"}).status_code == 415
    assert phone.post(url, json={"text": "a" * 20000}, headers=bearer(alice_token)).status_code == 413
    assert phone.post(url, content=b"{not json", headers={**bearer(alice_token), "content-type": "application/json"}).status_code == 422


@pytest.mark.parametrize("query", ["/investigations?limit=0", "/investigations?limit=101", "/investigations?offset=-1",
                                   "/investigations/0", "/investigations/abc", "/investigations/9223372036854775808"])
def test_invalid_parameters_are_422(phone, alice_token, query) -> None:
    assert phone.get(f"{MOB}{query}", headers=bearer(alice_token)).status_code == 422


# ---------- authentication and scopes ----------

ROUTES = [  # (method, path, body, scope)
    ("POST", f"{MOB}/analyze", {"text": CLINIC}, "sms:analyze"),
    ("GET", f"{MOB}/investigations", None, "sms:analyze"),
    ("GET", f"{MOB}/investigations/1", None, "sms:analyze"),
    ("POST", f"{MOB}/investigations", {"text": CLINIC}, "sms:write"),
    ("POST", f"{MOB}/investigations/1/actions", {"action": "reviewed"}, "sms:write"),
    ("DELETE", f"{MOB}/investigations/1", None, "sms:write"),
]


def test_missing_invalid_expired_idle_and_revoked_tokens(phone, session, accounts) -> None:  # noqa: F811
    expired, idle, revoked = (mobile_token(session, accounts["alice"], scopes=SMS_SCOPES) for _ in range(3))
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(expired))
                    .values(expires_at=now() - timedelta(seconds=1)))
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(idle))
                    .values(last_used_at=now() - timedelta(days=15)))
    session.commit()
    assert phone.post("/mobile/v1/logout", headers=bearer(revoked)).status_code == 204
    for method, path, body, _ in ROUTES:
        r = phone.request(method, path, json=body)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", path
        for token in ("not-a-real-token", expired, idle, revoked):
            r = phone.request(method, path, json=body, headers=bearer(token))
            assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer error="invalid_token"', path
    assert sms_rows(session) == 0


def test_web_sessions_and_extension_tokens_are_refused(phone, web, session, accounts) -> None:  # noqa: F811
    ext = extension_token(session, accounts["alice"])
    web_token = auth_service.create_session(session, accounts["alice"].id, "web").token
    session.commit()
    for method, path, body, _ in ROUTES:
        assert web.request(method, path, json=body).status_code == 401, path  # cookie + CSRF header
        for token in (ext, web_token):
            assert phone.request(method, path, json=body, headers=bearer(token)).status_code == 401, path
    assert sms_rows(session) == 0


@pytest.mark.parametrize(("method", "path", "body", "scope"), ROUTES)
def test_each_route_needs_its_scope(phone, session, accounts, method, path, body, scope) -> None:  # noqa: F811
    without = mobile_token(session, accounts["alice"], scopes=sorted(MOBILE_SCOPES - {scope}))
    for token in (without, mobile_token(session, accounts["alice"], scopes=())):
        r = phone.request(method, path, json=body, headers=bearer(token))
        assert r.status_code == 403 and r.json()["detail"] == "This device is not allowed to do that."
        # The scope is checked before the body or the record, so nothing else is revealed.
        r = phone.request(method, path, json={"bogus": True} if body else None, headers=bearer(token))
        assert r.status_code == 403
    assert sms_rows(session) == 0


def test_analyze_scope_alone_cannot_change_anything(phone, session, accounts, alice_token) -> None:  # noqa: F811
    saved = save(phone, alice_token, {"text": CLINIC})
    reader = mobile_token(session, accounts["alice"], scopes=("sms:analyze",))
    assert phone.get(f"{MOB}/investigations/{saved['id']}", headers=bearer(reader)).status_code == 200
    assert phone.post(f"{MOB}/investigations", json={"text": OTP}, headers=bearer(reader)).status_code == 403
    assert phone.post(f"{MOB}/investigations/{saved['id']}/actions", json={"action": "reviewed"},
                      headers=bearer(reader)).status_code == 403
    assert phone.delete(f"{MOB}/investigations/{saved['id']}", headers=bearer(reader)).status_code == 403
    assert call(phone, alice_token, "GET", f"{MOB}/investigations/{saved['id']}") == saved
    assert sms_rows(session) == 1


def test_mobile_tokens_cannot_use_the_dashboard_sms_api(phone, alice_token) -> None:
    for method, path, body in [("POST", f"{DASH}/analyze", {"text": CLINIC}), ("GET", f"{DASH}/investigations", None),
                               ("POST", f"{DASH}/investigations", {"text": CLINIC}),
                               ("DELETE", f"{DASH}/investigations/1", None)]:
        assert phone.request(method, path, json=body, headers=bearer(alice_token)).status_code == 401, path


def test_dashboard_sms_stays_local_only_while_mobile_routes_are_token_only(session, accounts, alice_token, web) -> None:  # noqa: F811
    remote = make_client(session, host="203.0.113.7")
    sign_in(remote, session, accounts["alice"])
    assert remote.post(f"{DASH}/analyze", json={"text": CLINIC}).status_code == 403
    assert remote.post(f"{MOB}/analyze", json={"text": CLINIC}, headers=bearer(alice_token)).status_code == 200


# ---------- logs ----------

def test_logs_never_contain_message_text_identifiers_or_tokens(phone, alice_token, sites, caplog) -> None:  # noqa: F811
    caplog.set_level(logging.DEBUG)
    call(phone, alice_token, "POST", f"{MOB}/analyze", {"text": CLINIC, "sender": "+44 7700 900123"})
    saved = save(phone, alice_token, {"text": OTP, "store_text": True})
    call(phone, alice_token, "POST", f"{MOB}/investigations/{saved['id']}/actions", {"action": "reviewed"})
    phone.post(f"{MOB}/analyze", json={"text": "x" * 2001}, headers=bearer(alice_token))
    text = caplog.text.lower()
    for value in ("example clinic", "appointments@", "7946", "7700", "123456", "abcdefgh", "reset", "x" * 50,
                  alice_token.lower()):
        assert value not in text, value
    assert "sms analysis: entities=" in text
