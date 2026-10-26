"""Personal dashboard API against a live PostgreSQL test database (TEST_DATABASE_URL).

Alice is signed in. Bob has his own records, and there are unowned historical
records; neither may ever appear in Alice's dashboard. Every test runs in a
transaction that is rolled back afterwards.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import ConsentReceipt, Incident, MailLog, Signup
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.services import matcher
from tests.auth_support import ORIGIN, make_account, sign_in

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
API = ["/dashboard/api/overview", "/dashboard/api/signups", "/dashboard/api/emails", "/dashboard/api/investigations"]
NEVER_SHOWN = ["legacy@sender.example", "Secret subject", "f" * 64]  # full senders, subjects, message hashes
OTHERS = ["Bob Forum", "bob1@leaktrap.xyz", "Historical Shop", "hist@leaktrap.xyz", "Bob mail"]


@pytest.fixture
def accounts(session: Session) -> dict:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


def local_client(session: Session) -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    return TestClient(app, client=("127.0.0.1", 50000))


@pytest.fixture
def client(session: Session, accounts):
    client = local_client(session)
    sign_in(client, session, accounts["alice"])
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def data(session: Session, accounts) -> dict:
    alice, bob = accounts["alice"].id, accounts["bob"].id
    shop = Signup(user_id=alice, site_name="Example Shop", site_domain="shop.example.com", alias="ab12cd34@leaktrap.xyz",
                  nickname="Ocelot", surname_variant="Dhingraa")
    news = Signup(user_id=alice, site_name="Daily News", alias="ef56gh78@leaktrap.xyz", real_name_required=True)
    bank = Signup(user_id=alice, site_name="Alice Bank", site_domain="bank.example")
    bob_site = Signup(user_id=bob, site_name="Bob Forum", alias="bob1@leaktrap.xyz")
    historical = Signup(site_name="Historical Shop", site_domain="shop.example.com", alias="hist@leaktrap.xyz")
    session.add_all([shop, news, bank, bob_site, historical])
    session.flush()
    session.add_all([
        # Pre-ingestion row: has full sender and subject, no status. Never shown.
        MailLog(user_id=alice, signup_id=shop.id, alias=shop.alias, sender="legacy@sender.example",
                subject="Secret subject", received_at=T0),
        MailLog(user_id=alice, signup_id=shop.id, alias=shop.alias, sender_domain="broker.example",
                ingest_status="matched", match_status="matched", match_confidence="high", message_id_hash="f" * 64,
                received_at=T0 + timedelta(hours=1)),
        MailLog(user_id=alice, signup_id=news.id, alias=news.alias, sender_domain="shop.example.com",
                ingest_status="matched", match_status="ambiguous", match_confidence="medium", received_at=T0 + timedelta(hours=2)),
        MailLog(user_id=alice, alias="zz99@leaktrap.xyz", ingest_status="unmatched", match_status="no_match", match_confidence="none",
                received_at=T0 + timedelta(hours=3)),
        MailLog(user_id=bob, signup_id=bob_site.id, subject="Bob mail", match_status="matched", received_at=T0),
        MailLog(signup_id=historical.id, match_status="matched", received_at=T0),  # unowned
        ConsentReceipt(user_id=alice, signup_id=shop.id, privacy_notice_text="", action="accepted", capture_source="manual",
                       source_url="https://shop.example.com/privacy"),
        ConsentReceipt(user_id=bob, signup_id=bob_site.id, privacy_notice_text="", action="declined"),
        Incident(user_id=alice, channel="email", result="matched", confidence="high", matched_site="Example Shop",
                 evidence={"recipient_alias_matched": True, "sender_domain": "broker.example",
                           "candidates": [{"signup_id": shop.id, "confidence": "high", "signals": ["alias_exact", "nickname_exact"]}]}),
        Incident(user_id=bob, channel="email", result="matched", matched_site="Bob Forum"),
        Incident(channel="email", result="matched", matched_site="Historical Shop"),
    ])
    session.commit()
    return {"shop": shop.id, "news": news.id, "bank": bank.id, "bob_site": bob_site.id, "historical": historical.id}


def get(client, path, **params):
    response = client.get(path, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_signed_out_requests_are_refused(session) -> None:
    anon = local_client(session)
    try:
        for path in API + ["/dashboard/api/signups/1", "/dashboard/api/emails/1"]:
            assert anon.get(path).status_code == 401, path
        assert anon.get("/dashboard").status_code == 200  # the page itself (it shows a sign-in form)
    finally:
        app.dependency_overrides.clear()


def test_extension_tokens_cannot_read_the_dashboard(session, accounts, data) -> None:
    from tests.auth_support import extension_token

    ext = local_client(session)
    try:
        token = extension_token(session, accounts["alice"])
        for path in API:
            assert ext.get(path, headers={"Authorization": f"Bearer {token}"}).status_code == 401, path
    finally:
        app.dependency_overrides.clear()


def test_empty_dataset(client) -> None:
    overview = get(client, "/dashboard/api/overview")
    for key in ("websites", "aliases", "nicknames", "receipts", "emails_total", "matched", "ambiguous",
                "no_match", "unprocessed", "investigations"):
        assert overview[key] == 0, key
    for path in API[1:]:
        assert (get(client, path)["items"], get(client, path)["total"]) == ([], 0)


def test_overview_counts_only_own_records(client, data) -> None:
    o = get(client, "/dashboard/api/overview")
    assert (o["websites"], o["aliases"], o["nicknames"], o["receipts"], o["investigations"]) == (3, 2, 1, 1, 1)
    assert (o["emails_total"], o["matched"], o["ambiguous"], o["no_match"], o["unprocessed"]) == (4, 2, 1, 1, 1)
    assert "not proof" in o["notice"]


def test_my_websites_shows_own_aliases_with_counts(client, data) -> None:
    page = get(client, "/dashboard/api/signups")
    assert page["total"] == 3
    assert [s["id"] for s in page["items"]] == [data["bank"], data["news"], data["shop"]]  # newest first
    shop = next(s for s in page["items"] if s["id"] == data["shop"])
    assert (shop["alias"], shop["nickname"], shop["receipt_count"], shop["email_count"]) == ("ab12cd34@leaktrap.xyz", "Ocelot", 1, 1)
    assert not {"surname_variant", "user_id"} & set(shop)


@pytest.mark.parametrize(("params", "expected"), [
    ({"q": "shop"}, ["shop"]), ({"q": "EF56"}, ["news"]), ({"q": "ocelot"}, ["shop"]), ({"q": "bank.example"}, ["bank"]),
    ({"q": "%"}, []), ({"q": "_"}, []), ({"q": "Bob"}, []), ({"q": "hist"}, []),
    ({"filter": "with_receipts"}, ["shop"]), ({"filter": "with_emails"}, ["news", "shop"]), ({"filter": "real_name"}, ["news"]),
    ({"q": "news", "filter": "with_receipts"}, []),
])
def test_search_and_filters(client, data, params, expected) -> None:
    page = get(client, "/dashboard/api/signups", **params)
    assert [s["id"] for s in page["items"]] == [data[k] for k in expected]
    assert page["total"] == len(expected)


@pytest.mark.parametrize("query", ["filter=deleted", "q=" + "x" * 101, "limit=0", "limit=101", "offset=-1"])
def test_invalid_list_parameters(client, query) -> None:
    assert client.get(f"/dashboard/api/signups?{query}").status_code == 422


def test_signups_pagination(client, data) -> None:
    second = get(client, "/dashboard/api/signups", limit=1, offset=1)
    assert [s["id"] for s in second["items"]] == [data["news"]]
    assert (second["limit"], second["offset"], second["total"]) == (1, 1, 3)
    assert get(client, "/dashboard/api/signups", offset=50)["items"] == []


def test_website_detail(client, data) -> None:
    d = get(client, f"/dashboard/api/signups/{data['shop']}")
    assert (d["alias"], d["nickname"], d["surname_variant"], d["site_domain"]) == ("ab12cd34@leaktrap.xyz", "Ocelot", "Dhingraa", "shop.example.com")
    assert [(r["action"], r["evidence_basis"]) for r in d["receipts"]] == [("accepted", "user_reported")]
    assert [e["match_status"] for e in d["emails"]] == ["matched"]
    assert "not proof" in d["notice"]


def test_email_activity_newest_first_with_site(client, data) -> None:
    page = get(client, "/dashboard/api/emails")
    assert page["total"] == 4
    assert [m["match_status"] for m in page["items"]] == ["no_match", "ambiguous", "matched", None]
    unknown, ambiguous, matched, legacy = page["items"]
    assert (unknown["recipient_known"], unknown["site_name"]) == (False, None)
    assert (matched["site_name"], matched["sender_domain"]) == ("Example Shop", "broker.example")
    assert legacy["match_status"] is None and legacy["sender_domain"] is None


@pytest.mark.parametrize("status", ["matched", "ambiguous", "no_match", "unprocessed"])
def test_email_status_filter(client, data, status) -> None:
    page = get(client, "/dashboard/api/emails", status=status)
    assert page["total"] == (2 if status == "matched" else 1)
    if status in ("matched", "unprocessed"):
        assert all(item["status"] == status for item in page["items"])
    else:
        assert page["items"][0]["match_status"] == status


def test_email_detail_uses_only_stored_data(client, data) -> None:
    matched_id = next(m["id"] for m in get(client, "/dashboard/api/emails", status="matched")["items"] if m["match_status"] == "matched")
    detail = get(client, f"/dashboard/api/emails/{matched_id}")
    assert (detail["match_status"], detail["match_confidence"]) == ("matched", "high")
    assert detail["limitations"] == list(matcher.LIMITATIONS)
    assert "signals" not in detail and "confirmed" not in str(detail).lower()


def test_leak_investigations(client, data) -> None:
    page = get(client, "/dashboard/api/investigations")
    assert page["total"] == 1
    [i] = page["items"]
    assert (i["result"], i["matched_site"], i["recipient_alias_matched"], i["sender_domain"]) == ("matched", "Example Shop", True, "broker.example")
    assert (i["candidate_count"], i["signal_types"]) == (1, ["alias_exact", "nickname_exact"])


def test_other_users_and_unowned_records_are_unreachable(client, session, data, accounts) -> None:
    texts = [client.get(p).text for p in API] + [client.get("/dashboard/api/signups", params={"q": q}).text for q in ("bob", "hist")]
    # A user_id parameter is ignored: the session decides whose data is shown.
    texts += [client.get(p, params={"user_id": accounts["bob"].id}).text for p in API]
    for text in texts:
        for value in OTHERS:
            assert value not in text, value
    for signup_id in (data["bob_site"], data["historical"], 987654321):
        assert client.get(f"/dashboard/api/signups/{signup_id}").status_code == 404
    bob_mail = session.scalar(__import__("sqlalchemy").select(MailLog.id).where(MailLog.subject == "Bob mail"))
    assert client.get(f"/dashboard/api/emails/{bob_mail}").status_code == 404
    # Bob, signed in, sees only his own.
    bob = local_client(session)
    sign_in(bob, session, accounts["bob"])
    assert [s["site_name"] for s in get(bob, "/dashboard/api/signups")["items"]] == ["Bob Forum"]
    assert client.get(f"/dashboard/api/signups/{data['shop']}").status_code == 200
    assert bob.get(f"/dashboard/api/signups/{data['shop']}").status_code == 404


def test_full_senders_subjects_and_hashes_never_returned(client, data) -> None:
    texts = [client.get(p).text for p in API] + [client.get(f"/dashboard/api/signups/{data['shop']}").text]
    texts += [client.get(f"/dashboard/api/emails/{i['id']}").text for i in get(client, "/dashboard/api/emails")["items"]]
    combined = "\n".join(texts)
    for value in NEVER_SHOWN:
        assert value not in combined, value
    for key in ('"sender"', '"subject"', '"message_id_hash"'):
        assert key not in combined, key


@pytest.mark.parametrize("path", ["/dashboard/api/signups", "/dashboard/api/emails", "/dashboard/api/investigations"])
def test_list_query_count_does_not_grow_with_rows(client, session, data, path) -> None:
    statements = []
    engine = session.get_bind()
    listener = lambda *args: statements.append(args[2])  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        get(client, path, limit=100)
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    # session lookup + user lookup (authentication) + one count + one page query
    assert 1 <= len(statements) <= 5, statements
