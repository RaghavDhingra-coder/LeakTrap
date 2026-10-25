"""Mobile read routes (websites, email activity, timeline) against the isolated
PostgreSQL test database.

They must return exactly what the dashboard API returns for the same user and
parameters, only to a mobile Bearer token carrying the route's scope. Alice's
and Bob's records and unowned historical records come from the dashboard
tests' fixture, plus saved SMS investigations for the timeline.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import Incident, MailLog, UserSession
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.security import MOBILE_SCOPES, SESSION_COOKIE
from backend.services.auth import now, token_hash
from tests.auth_support import extension_token, mobile_token, sign_in
from tests.test_dashboard_api import NEVER_SHOWN, OTHERS, T0, accounts, data  # noqa: F401 (fixtures)

pytestmark = pytest.mark.integration

READ_SCOPES = ("websites:read", "email:read", "timeline:read")
ROUTES = {  # mobile path -> (scope, dashboard path)
    "/mobile/v1/websites": ("websites:read", "/dashboard/api/signups"),
    "/mobile/v1/emails": ("email:read", "/dashboard/api/emails"),
    "/mobile/v1/timeline": ("timeline:read", "/dashboard/api/timeline"),
}


def make_client(session: Session, host: str = "127.0.0.1") -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    return TestClient(app, client=(host, 50000))


@pytest.fixture
def sms(session: Session, accounts, data) -> dict:  # noqa: F811
    alice, bob = accounts["alice"].id, accounts["bob"].id
    mine = Incident(user_id=alice, channel="sms", result="strong", matched_site="Example Shop",
                    evidence={"source": "sms_analyzer", "sender": {"type": "short_code", "value": "56161"},
                              "received_at": (T0 + timedelta(hours=5)).isoformat(),
                              "confirmed": {"signup_id": data["shop"], "name": "Example Shop"}})
    theirs = Incident(user_id=bob, channel="sms", result="strong", matched_site="Bob Forum",
                      evidence={"source": "sms_analyzer", "sender": {"type": "alphanumeric", "value": "BOBFRM"}})
    session.add_all([mine, theirs])
    session.commit()
    return {"mine": mine.id, "theirs": theirs.id}


@pytest.fixture
def web(session: Session, accounts, data, sms):  # noqa: F811
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
    return mobile_token(session, accounts["alice"], scopes=("account:read", *READ_SCOPES))


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def mobile_get(phone, token, path, **params):
    r = phone.get(path, params=params, headers=bearer(token))
    assert r.status_code == 200, (path, r.status_code, r.text)
    return r.json()


# ---------- same data, same shapes as the dashboard ----------

@pytest.mark.parametrize(("mobile", "dashboard", "params"), [
    ("/mobile/v1/websites", "/dashboard/api/signups", {}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"q": "shop"}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"q": "EF56"}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"filter": "with_emails"}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"filter": "real_name"}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"limit": 1, "offset": 1}),
    ("/mobile/v1/websites", "/dashboard/api/signups", {"offset": 50}),
    ("/mobile/v1/emails", "/dashboard/api/emails", {}),
    ("/mobile/v1/emails", "/dashboard/api/emails", {"status": "matched"}),
    ("/mobile/v1/emails", "/dashboard/api/emails", {"status": "unprocessed"}),
    ("/mobile/v1/emails", "/dashboard/api/emails", {"limit": 2, "offset": 1}),
    ("/mobile/v1/timeline", "/dashboard/api/timeline", {}),
    ("/mobile/v1/timeline", "/dashboard/api/timeline", {"limit": 2}),
])
def test_lists_match_the_dashboard(phone, web, alice_token, mobile, dashboard, params) -> None:
    expected = web.get(dashboard, params=params)
    assert expected.status_code == 200
    assert mobile_get(phone, alice_token, mobile, **params) == expected.json()


def test_details_match_the_dashboard(phone, web, alice_token, data) -> None:  # noqa: F811
    detail = mobile_get(phone, alice_token, f"/mobile/v1/websites/{data['shop']}")
    assert detail == web.get(f"/dashboard/api/signups/{data['shop']}").json()
    assert detail["alias"] == "ab12cd34@leaktrap.xyz" and "not proof" in detail["notice"]
    assert [s["confirmed"] for s in detail["sms_investigations"]] == [True]
    for email in mobile_get(phone, alice_token, "/mobile/v1/emails")["items"]:
        mine = mobile_get(phone, alice_token, f"/mobile/v1/emails/{email['id']}")
        assert mine == web.get(f"/dashboard/api/emails/{email['id']}").json()
        assert mine["limitations"] and "not proof" in mine["notice"]


def test_list_contents_pagination_and_filters(phone, alice_token, data, sms) -> None:  # noqa: F811
    websites = mobile_get(phone, alice_token, "/mobile/v1/websites")
    assert websites["total"] == 3 and (websites["limit"], websites["offset"]) == (20, 0)
    page = mobile_get(phone, alice_token, "/mobile/v1/websites", limit=1, offset=1)
    assert [s["id"] for s in page["items"]] == [data["news"]] and page["total"] == 3
    assert [s["id"] for s in mobile_get(phone, alice_token, "/mobile/v1/websites", filter="with_receipts")["items"]] == [data["shop"]]

    emails = mobile_get(phone, alice_token, "/mobile/v1/emails")
    assert emails["total"] == 4
    assert [m["match_status"] for m in emails["items"]] == ["no_match", "ambiguous", "matched", None]
    for status in ("matched", "ambiguous", "no_match"):
        assert [m["match_status"] for m in mobile_get(phone, alice_token, "/mobile/v1/emails", status=status)["items"]] == [status]

    timeline = mobile_get(phone, alice_token, "/mobile/v1/timeline")["items"]
    assert timeline[0] == {**timeline[0], "channel": "sms", "id": sms["mine"], "linked": True, "signup_id": data["shop"]}
    assert sorted(i["channel"] for i in timeline) == ["email"] * 4 + ["sms"]
    assert len(mobile_get(phone, alice_token, "/mobile/v1/timeline", limit=2)["items"]) == 2


@pytest.mark.parametrize("query", [
    "/mobile/v1/websites?filter=deleted", "/mobile/v1/websites?q=" + "x" * 101, "/mobile/v1/websites?limit=0",
    "/mobile/v1/websites?limit=101", "/mobile/v1/websites?offset=-1", "/mobile/v1/emails?status=deleted",
    "/mobile/v1/emails?limit=101", "/mobile/v1/timeline?limit=0", "/mobile/v1/timeline?limit=101",
    "/mobile/v1/websites/0", "/mobile/v1/websites/abc", "/mobile/v1/emails/0", "/mobile/v1/emails/9223372036854775808",
])
def test_invalid_parameters_are_422(phone, alice_token, query) -> None:
    assert phone.get(query, headers=bearer(alice_token)).status_code == 422


# ---------- isolation ----------

def test_other_users_and_missing_records_are_indistinguishable(phone, session, alice_token, accounts, data) -> None:  # noqa: F811
    missing = phone.get("/mobile/v1/websites/987654321", headers=bearer(alice_token))
    assert missing.status_code == 404
    for signup_id in (data["bob_site"], data["historical"]):
        r = phone.get(f"/mobile/v1/websites/{signup_id}", headers=bearer(alice_token))
        assert (r.status_code, r.json()) == (404, missing.json())

    missing_mail = phone.get("/mobile/v1/emails/987654321", headers=bearer(alice_token))
    assert missing_mail.status_code == 404
    for subject_or_none in ("Bob mail", None):
        mail_id = session.scalar(select(MailLog.id).where(
            MailLog.user_id.is_(None) if subject_or_none is None else MailLog.subject == subject_or_none))
        r = phone.get(f"/mobile/v1/emails/{mail_id}", headers=bearer(alice_token))
        assert (r.status_code, r.json()) == (404, missing_mail.json())

    # Bob's own token sees only his records, and not Alice's.
    bob_token = mobile_token(session, accounts["bob"], scopes=READ_SCOPES)
    assert [s["site_name"] for s in mobile_get(phone, bob_token, "/mobile/v1/websites")["items"]] == ["Bob Forum"]
    assert phone.get(f"/mobile/v1/websites/{data['shop']}", headers=bearer(bob_token)).status_code == 404
    assert [i["title"] for i in mobile_get(phone, bob_token, "/mobile/v1/timeline")["items"]
            if i["channel"] == "sms"] == ["SMS from BOBFRM"]


def test_lists_never_include_other_users_or_unowned_records(phone, alice_token, accounts) -> None:  # noqa: F811
    texts = []
    for path in ROUTES:
        texts.append(phone.get(path, headers=bearer(alice_token)).text)
        # A user_id parameter is ignored: the token decides whose data is shown.
        texts.append(phone.get(path, params={"user_id": accounts["bob"].id}, headers=bearer(alice_token)).text)
    texts += [phone.get("/mobile/v1/websites", params={"q": q}, headers=bearer(alice_token)).text for q in ("bob", "hist")]
    for text in texts:
        for value in [*OTHERS, "BOBFRM"]:
            assert value not in text, value


def test_full_senders_subjects_and_hashes_never_returned(phone, alice_token, data) -> None:  # noqa: F811
    texts = [phone.get(p, headers=bearer(alice_token)).text for p in ROUTES]
    texts.append(phone.get(f"/mobile/v1/websites/{data['shop']}", headers=bearer(alice_token)).text)
    texts += [phone.get(f"/mobile/v1/emails/{i['id']}", headers=bearer(alice_token)).text
              for i in mobile_get(phone, alice_token, "/mobile/v1/emails")["items"]]
    combined = "\n".join(texts)
    for value in NEVER_SHOWN:
        assert value not in combined, value
    for key in ('"sender"', '"subject"', '"message_id_hash"', '"user_id"'):
        assert key not in combined, key


# ---------- authentication and scopes ----------

def all_read_paths(data) -> list[str]:  # noqa: F811
    return [*ROUTES, f"/mobile/v1/websites/{data['shop']}", "/mobile/v1/emails/1"]


def test_missing_invalid_expired_and_revoked_tokens(phone, session, accounts, data) -> None:  # noqa: F811
    expired = mobile_token(session, accounts["alice"], scopes=READ_SCOPES)
    revoked = mobile_token(session, accounts["alice"], scopes=READ_SCOPES)
    idle = mobile_token(session, accounts["alice"], scopes=READ_SCOPES)
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(expired))
                    .values(expires_at=now() - timedelta(seconds=1)))
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(idle))
                    .values(last_used_at=now() - timedelta(days=15)))
    session.commit()
    assert phone.post("/mobile/v1/logout", headers=bearer(revoked)).status_code == 204
    for path in all_read_paths(data):
        r = phone.get(path)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", path
        for token in ("not-a-real-token", expired, revoked, idle):
            r = phone.get(path, headers=bearer(token))
            assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer error="invalid_token"', path


@pytest.mark.parametrize("path", list(ROUTES))
def test_each_route_needs_its_own_scope(phone, session, accounts, data, path) -> None:  # noqa: F811
    scope = ROUTES[path][0]
    without = mobile_token(session, accounts["alice"], scopes=sorted(MOBILE_SCOPES - {scope}))
    only = mobile_token(session, accounts["alice"], scopes=(scope,))
    none = mobile_token(session, accounts["alice"], scopes=())
    for token in (without, none):
        r = phone.get(path, headers=bearer(token))
        assert r.status_code == 403 and r.json()["detail"] == "This device is not allowed to do that."
    assert phone.get(path, headers=bearer(only)).status_code == 200


def test_detail_routes_need_their_scope(phone, session, accounts, data) -> None:  # noqa: F811
    emails_only = mobile_token(session, accounts["alice"], scopes=("email:read",))
    websites_only = mobile_token(session, accounts["alice"], scopes=("websites:read",))
    assert phone.get(f"/mobile/v1/websites/{data['shop']}", headers=bearer(emails_only)).status_code == 403
    assert phone.get("/mobile/v1/emails/1", headers=bearer(websites_only)).status_code == 403
    # Scope is checked before existence, so a missing scope reveals nothing about records.
    assert phone.get("/mobile/v1/websites/987654321", headers=bearer(emails_only)).status_code == 403


def test_stage_one_tokens_without_read_scopes_are_refused(phone, session, accounts) -> None:  # noqa: F811
    old = mobile_token(session, accounts["alice"], scopes=("account:read",))
    assert phone.get("/mobile/v1/me", headers=bearer(old)).status_code == 200
    for path in ROUTES:
        assert phone.get(path, headers=bearer(old)).status_code == 403


def test_web_sessions_and_extension_tokens_are_refused(phone, web, session, accounts, data) -> None:  # noqa: F811
    ext = extension_token(session, accounts["alice"])
    for path in all_read_paths(data):
        assert web.get(path).status_code == 401, path  # cookie + CSRF header
        assert phone.get(path, headers=bearer(ext)).status_code == 401, path
    cookie_only = make_client(session)
    cookie_only.cookies.set(SESSION_COOKIE, web.cookies.get(SESSION_COOKIE))
    assert cookie_only.get("/mobile/v1/websites").status_code == 401


def test_mobile_tokens_cannot_read_the_dashboard_api(phone, alice_token, data) -> None:  # noqa: F811
    for path in [ROUTES[p][1] for p in ROUTES] + [f"/dashboard/api/signups/{data['shop']}", "/dashboard/api/emails/1"]:
        assert phone.get(path, headers=bearer(alice_token)).status_code == 401, path


def test_dashboard_stays_local_only_while_mobile_routes_are_token_only(session, accounts, alice_token, web) -> None:  # noqa: F811
    remote = make_client(session, host="203.0.113.7")
    sign_in(remote, session, accounts["alice"])
    assert remote.get("/dashboard/api/signups").status_code == 403  # loopback restriction unchanged
    assert remote.get("/mobile/v1/websites", headers=bearer(alice_token)).status_code == 200


def test_paired_device_can_read(phone, web, session) -> None:
    import hashlib
    import secrets

    secret = secrets.token_urlsafe(32)
    started = phone.post("/mobile/v1/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
                                                      "device_label": "Pixel 9"}).json()
    assert web.post("/extension/pairings/approve", json={"code": started["code"], "kind": "mobile"}).status_code == 200
    issued = phone.post(f"/mobile/v1/pairings/{started['pairing_id']}/token", json={"secret": secret}).json()
    assert set(READ_SCOPES) <= set(issued["scopes"])
    for path in ROUTES:
        assert phone.get(path, headers=bearer(issued["token"])).status_code == 200
