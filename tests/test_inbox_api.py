"""Inbox: email ingested through /ingest/email, then read through the dashboard
API, against a live PostgreSQL test database (TEST_DATABASE_URL).

Alice and Bob each own signups. Unowned historical records exist too. Every
test runs in a transaction that is rolled back afterwards.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import MailLog, Signup
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.routes.ingest import IngestConfig, get_ingest_config
from backend.services import mail_ingest
from tests.auth_support import make_account, sign_in

pytestmark = pytest.mark.integration

SECRET = "k" * 48
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def local_client(session: Session) -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    app.dependency_overrides[get_ingest_config] = lambda: IngestConfig(SECRET, 16384, "leaktrap.xyz")
    return TestClient(app, client=("127.0.0.1", 50000))


@pytest.fixture
def accounts(session: Session) -> dict:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


@pytest.fixture
def signups(session: Session, accounts) -> dict[str, Signup]:
    alice, bob = accounts["alice"].id, accounts["bob"].id
    rows = {
        "shop": Signup(user_id=alice, site_name="Example Shop", site_domain="shop.example.com",
                       alias="ab12cd34@leaktrap.xyz", nickname="Ocelot", surname_variant="Smith"),
        "news": Signup(user_id=alice, site_name="Daily News", alias="ef56gh78@leaktrap.xyz", real_name_used=True),
        "bob": Signup(user_id=bob, site_name="Bob Forum", alias="bob1bob1@leaktrap.xyz", nickname="Kestrel"),
        "historical": Signup(site_name="Historical Shop", alias="hist0000@leaktrap.xyz"),
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


@pytest.fixture
def worker(session):
    return local_client(session)


def deliver(worker, recipient: str, n: int, **fields) -> dict:
    body = {"recipient": recipient, "envelope_from": "bounce@mailer.example",
            "from_header": "Shop Deals <deals@shop.example.com>", "subject": f"Offer {n}",
            "message_id": f"<m{n}@mailer.example>", "received_at": (NOW - timedelta(minutes=60 - n)).isoformat(),
            **fields}
    response = worker.post("/ingest/email", json=body, headers={"Authorization": f"Bearer {SECRET}"})
    assert response.status_code in (200, 201), response.text
    return response.json()


def inbox(client, **params) -> dict:
    response = client.get("/dashboard/api/inbox", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_new_email_is_linked_to_identity_and_website(alice, bob, worker, signups) -> None:
    deliver(worker, "AB12CD34@leaktrap.xyz", 1, auth_results="i=1; mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass")
    page = inbox(alice)
    assert (page["total"], page["unread"]) == (1, 1)
    [item] = page["items"]
    assert item["identity"] == "Ocelot Smith" and item["identity_kind"] == "nickname"
    assert (item["site_name"], item["site_domain"], item["signup_id"]) == (
        "Example Shop", "shop.example.com", signups["shop"].id)
    assert item["alias"] == "ab12cd34@leaktrap.xyz"
    assert (item["sender_name"], item["sender_email"], item["subject"]) == ("Shop Deals", "deals@shop.example.com", "Offer 1")
    assert (item["status"], item["status_reason"], item["unread"], item["tracked"]) == ("matched", None, True, True)
    assert item["auth_results"] == "spf=pass dkim=pass dmarc=pass"
    assert datetime.fromisoformat(item["received_at"]) == NOW - timedelta(minutes=59)
    assert "forged" in page["notice"]
    # Bob sees nothing of it.
    assert inbox(bob) == {**inbox(bob), "items": [], "total": 0, "unread": 0}
    assert bob.get(f"/dashboard/api/inbox/{item['id']}").status_code == 404


def test_real_name_signup_identity_is_not_invented(alice, worker, signups) -> None:
    deliver(worker, signups["news"].alias, 1)
    [item] = inbox(alice)["items"]
    assert (item["identity"], item["identity_kind"]) == (None, "real_name")


def test_polling_reports_only_messages_since_the_last_poll(alice, bob, worker, signups) -> None:
    first = alice.get("/dashboard/api/inbox/updates").json()
    assert first == {"unread": 0, "latest_id": 0, "new": []}
    one = deliver(worker, signups["shop"].alias, 1)
    deliver(worker, signups["bob"].alias, 2)  # Bob's: never in Alice's updates
    two = deliver(worker, signups["news"].alias, 3)
    polled = alice.get("/dashboard/api/inbox/updates", params={"after_id": first["latest_id"]}).json()
    assert polled["unread"] == 2 and polled["latest_id"] == two["mail_log_id"]
    assert [m["id"] for m in polled["new"]] == [two["mail_log_id"], one["mail_log_id"]]
    again = alice.get("/dashboard/api/inbox/updates", params={"after_id": polled["latest_id"]}).json()
    assert again["new"] == [] and again["unread"] == 2
    # Without after_id (first poll after loading the page) nothing is reported as new.
    assert alice.get("/dashboard/api/inbox/updates").json()["new"] == []
    assert alice.get("/dashboard/api/inbox/updates", params={"after_id": -1}).status_code == 422


def test_duplicate_delivery_is_one_message(alice, worker, signups) -> None:
    deliver(worker, signups["shop"].alias, 1)
    assert deliver(worker, signups["shop"].alias, 1)["status"] == "duplicate"
    assert inbox(alice)["total"] == 1


def test_read_state_is_persisted_and_scoped(alice, bob, worker, session, signups) -> None:
    ids = [deliver(worker, signups["shop"].alias, n)["mail_log_id"] for n in (1, 2, 3)]
    read = alice.post(f"/dashboard/api/inbox/{ids[0]}/read", json={"read": True})
    assert read.status_code == 200 and read.json()["unread"] is False
    first_read_at = read.json()["read_at"]
    session.expire_all()
    assert session.get(MailLog, ids[0]).read_at is not None
    # Marking read again keeps the first read time.
    assert alice.post(f"/dashboard/api/inbox/{ids[0]}/read", json={"read": True}).json()["read_at"] == first_read_at
    assert inbox(alice)["unread"] == 2
    assert [m["id"] for m in inbox(alice, filter="unread")["items"]] == [ids[2], ids[1]]
    # Bob cannot change Alice's read state.
    assert bob.post(f"/dashboard/api/inbox/{ids[1]}/read", json={"read": True}).status_code == 404
    assert bob.post("/dashboard/api/inbox/read-all").json() == {"marked": 0, "unread": 0}
    assert inbox(alice)["unread"] == 2
    # Unread again, then all read.
    assert alice.post(f"/dashboard/api/inbox/{ids[0]}/read", json={"read": False}).json()["unread"] is True
    assert alice.post("/dashboard/api/inbox/read-all").json() == {"marked": 3, "unread": 0}
    assert inbox(alice, filter="unread")["items"] == []
    assert alice.get("/dashboard/api/overview").json()["unread"] == 0


def test_read_endpoint_validation_and_csrf(alice, worker, signups) -> None:
    mail_id = deliver(worker, signups["shop"].alias, 1)["mail_log_id"]
    url = f"/dashboard/api/inbox/{mail_id}/read"
    for body in ({}, {"read": "yes"}, {"read": True, "user_id": 1}):
        assert alice.post(url, json=body).status_code == 422
    assert alice.post(url, content=b"read", headers={"content-type": "text/plain"}).status_code == 415
    assert alice.post("/dashboard/api/inbox/987654321/read", json={"read": True}).status_code == 404
    csrf = alice.headers.pop("X-CSRF-Token")
    try:
        assert alice.post(url, json={"read": True}).status_code == 403
        assert alice.post("/dashboard/api/inbox/read-all").status_code == 403
    finally:
        alice.headers["X-CSRF-Token"] = csrf
    assert inbox(alice)["unread"] == 1


def test_filters_and_unmatched_reasons(alice, worker, session, signups, monkeypatch) -> None:
    matched = deliver(worker, signups["shop"].alias, 1)["mail_log_id"]
    deleted_site = deliver(worker, signups["news"].alias, 2)["mail_log_id"]
    monkeypatch.setattr(mail_ingest.matcher, "check", lambda *a, **k: 1 / 0)
    failed = deliver(worker, signups["shop"].alias, 3)["mail_log_id"]
    monkeypatch.undo()
    deliver(worker, "nobody00@leaktrap.xyz", 4)       # unknown alias: no owner
    deliver(worker, signups["historical"].alias, 5)   # unowned historical alias: no owner
    assert alice.delete(f"/signups/{signups['news'].id}").status_code == 204

    def ids(filter_):
        return [m["id"] for m in inbox(alice, filter=filter_)["items"]]

    assert ids("all") == [failed, deleted_site, matched]
    assert ids("matched") == [matched]
    assert ids("failed") == [failed]
    assert ids("unmatched") == [deleted_site]
    [unlinked] = inbox(alice, filter="unmatched")["items"]
    assert (unlinked["status_reason"], unlinked["site_name"], unlinked["alias"]) == (
        "invalid_alias_association", None, "ef56gh78@leaktrap.xyz")
    [failure] = inbox(alice, filter="failed")["items"]
    assert (failure["status_reason"], failure["site_name"], failure["subject"]) == ("analysis_failed", "Example Shop", "Offer 3")
    # Unknown and unowned aliases have no owner: stored without details, shown to nobody.
    orphans = session.scalars(select(MailLog).where(MailLog.user_id.is_(None))).all()
    assert sorted(o.status_reason for o in orphans) == ["unknown_alias", "unowned_alias"]
    assert all(o.subject is None and o.sender is None and o.sender_name is None for o in orphans)
    assert alice.get("/dashboard/api/inbox", params={"filter": "spam"}).status_code == 422


def test_records_from_before_inbox_tracking_show_no_details(alice, session, accounts, signups) -> None:
    session.add(MailLog(user_id=accounts["alice"].id, signup_id=signups["shop"].id, alias=signups["shop"].alias,
                        sender="legacy@sender.example", subject="Legacy subject", match_status="matched",
                        received_at=NOW - timedelta(days=2)))
    session.commit()
    page = inbox(alice)
    [item] = page["items"]
    assert (item["tracked"], item["unread"], item["status"]) == (False, False, "unprocessed")
    assert (item["sender_email"], item["subject"], item["sender_name"]) == (None, None, None)
    assert page["unread"] == 0
    assert "Legacy subject" not in str(page) and "legacy@sender.example" not in str(page)
    # It cannot be marked read or unread either.
    assert alice.post(f"/dashboard/api/inbox/{item['id']}/read", json={"read": False}).status_code == 404


def test_inbox_is_not_available_to_extension_tokens_or_signed_out(session, worker, signups) -> None:
    from tests.auth_support import ORIGIN
    for method, path in [("GET", "/dashboard/api/inbox"), ("GET", "/dashboard/api/inbox/updates"),
                         ("GET", "/dashboard/api/inbox/1"), ("POST", "/dashboard/api/inbox/1/read"),
                         ("POST", "/dashboard/api/inbox/read-all")]:
        assert worker.request(method, path, json={"read": True}, headers={"Origin": ORIGIN}).status_code == 401, path
        assert worker.request(method, path, json={"read": True},
                              headers={"Authorization": f"Bearer {SECRET}"}).status_code == 401, path
    app.dependency_overrides.clear()


def test_pagination_and_page_limits(alice, worker, signups) -> None:
    ids = [deliver(worker, signups["shop"].alias, n)["mail_log_id"] for n in range(1, 6)]
    page = inbox(alice, limit=2, offset=2)
    assert (page["total"], page["limit"], page["offset"]) == (5, 2, 2)
    assert [m["id"] for m in page["items"]] == [ids[2], ids[1]]
    assert alice.get("/dashboard/api/inbox", params={"limit": 101}).status_code == 422
