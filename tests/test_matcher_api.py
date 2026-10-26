"""Matcher API against a live PostgreSQL test database (TEST_DATABASE_URL).

Every test runs in a transaction that is rolled back afterwards.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import Incident, Signup, User
from tests.auth_support import ORIGIN, make_account, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
def accounts(session: Session) -> dict[str, User]:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


@pytest.fixture
def client(session: Session, accounts):
    """Signed in as Alice."""
    app.dependency_overrides[get_db] = lambda: session
    client = TestClient(app)
    sign_in(client, session, accounts["alice"])
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def signups(session: Session, accounts) -> dict[str, Signup]:
    alice, bob = accounts["alice"].id, accounts["bob"].id
    rows = {
        "shop": Signup(user_id=alice, site_name="Example Shop", site_domain="shop.example.com",
                       alias="ab12@leaktrap.xyz", nickname="Ocelot", surname_variant="Dhingraa"),
        "news": Signup(user_id=alice, site_name="Daily News", site_domain="news.example.org",
                       alias="cd34@leaktrap.xyz", nickname="Zephyr"),
        "owned": Signup(user_id=bob, site_name="Private Bank", site_domain="bank.example.net",
                        alias="ef56@leaktrap.xyz", nickname="Kestrel"),
        "historical": Signup(site_name="Old Forum", site_domain="forum.example.net",
                             alias="gh78@leaktrap.xyz", nickname="Heron"),
    }
    session.add_all(rows.values())
    session.commit()
    return rows


def check(client, **body):
    response = client.post("/matcher/check", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def incident_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(Incident))


def test_exact_alias_match_against_stored_signup(client, signups) -> None:
    result = check(client, recipient="AB12@LeakTrap.xyz")
    assert result["status"] == "matched"
    assert result["confidence"] == "high"
    [match] = result["matches"]
    assert match["signup_id"] == signups["shop"].id
    assert (match["site_name"], match["site_domain"]) == ("Example Shop", "shop.example.com")
    assert [s["type"] for s in match["signals"]] == ["alias_exact"]
    assert result["incident_id"] is None
    assert any("not proof" in text for text in result["limitations"])


def test_unknown_alias_returns_no_match(client, signups) -> None:
    result = check(client, recipient="zz99@leaktrap.xyz")
    assert (result["status"], result["confidence"], result["matches"]) == ("no_match", "none", [])


def test_sender_domain_without_alias(client, signups) -> None:
    result = check(client, sender="promo@mail.shop.example.com")
    assert (result["status"], result["confidence"]) == ("matched", "low")
    assert result["matches"][0]["signals"][0]["type"] == "sender_domain"


def test_nickname_and_surname_clues(client, signups) -> None:
    assert check(client, nickname="  ocelot ")["confidence"] == "medium"
    surname = check(client, surname_variant="DHINGRAA")
    assert surname["confidence"] == "low"
    assert surname["matches"][0]["signup_id"] == signups["shop"].id


def test_alias_plus_subject_nickname_and_third_party_sender(client, signups) -> None:
    result = check(client, recipient="ab12@leaktrap.xyz", sender="deals@broker.example",
                   subject="Ocelot, your exclusive offer")
    [match] = result["matches"]
    assert {s["type"] for s in match["signals"]} == {"alias_exact", "nickname_exact"}
    assert any("not associated with the site" in w for w in result["warnings"])


def test_conflicting_clues_are_ambiguous(client, signups) -> None:
    result = check(client, recipient="ab12@leaktrap.xyz", nickname="Zephyr")
    assert result["status"] == "ambiguous"
    assert result["confidence"] == "medium"
    assert [m["signup_id"] for m in result["matches"]] == [signups["shop"].id, signups["news"].id]


def test_missing_optional_fields_are_fine(client, signups) -> None:
    result = check(client, recipient="cd34@leaktrap.xyz")
    assert result["matches"][0]["signup_id"] == signups["news"].id


def test_other_users_and_unowned_signups_are_never_disclosed(client, session, signups, accounts) -> None:
    # Bob's and the unowned historical signup never match for Alice.
    for clue in ({"recipient": "ef56@leaktrap.xyz"}, {"nickname": "Kestrel"}, {"sender": "a@bank.example.net"},
                 {"recipient": "gh78@leaktrap.xyz"}, {"nickname": "Heron"}, {"sender": "a@forum.example.net"}):
        result = check(client, **clue)
        assert result["matches"] == [], clue
        assert "Private Bank" not in str(result) and "Old Forum" not in str(result)
    # Bob sees his own, not Alice's.
    bob = TestClient(app)
    sign_in(bob, session, accounts["bob"])
    scoped = check(bob, recipient="ef56@leaktrap.xyz", nickname="Ocelot")
    assert [m["signup_id"] for m in scoped["matches"]] == [signups["owned"].id]


@pytest.mark.parametrize("user_id", [987654321, 1])
def test_client_supplied_user_id_is_rejected(client, signups, user_id) -> None:
    response = client.post("/matcher/check", json={"recipient": "ab12@leaktrap.xyz", "user_id": user_id})
    assert response.status_code == 422


def test_signed_out_check_is_refused(session, signups) -> None:
    app.dependency_overrides[get_db] = lambda: session
    try:
        anon = TestClient(app, headers={"Origin": ORIGIN})
        assert anon.post("/matcher/check", json={"recipient": "ab12@leaktrap.xyz"}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_check_does_not_create_incident_by_default(client, session, signups) -> None:
    before = incident_count(session)
    check(client, recipient="ab12@leaktrap.xyz")
    assert incident_count(session) == before


def test_opt_in_records_suspected_incident(client, session, signups) -> None:
    existing = Incident(channel="email", result="matched", confidence="low")
    session.add(existing)
    session.commit()

    result = check(client, recipient="ab12@leaktrap.xyz", sender="Deals@Broker.example",
                   subject="Hi Ocelot", record_incident=True)
    incident = session.get(Incident, result["incident_id"])
    assert incident.id != existing.id
    assert incident.user_id == signups["shop"].user_id  # owned by the signed-in user
    assert incident.channel == "email"
    assert incident.result == "matched"  # matcher status, not "confirmed"
    assert incident.confidence == "high"
    assert incident.matched_site == "Example Shop"
    assert incident.message_text is None
    assert incident.evidence["sender_domain"] == "broker.example"
    assert incident.evidence["candidates"] == [{
        "signup_id": signups["shop"].id, "confidence": "high",
        "signals": ["alias_exact", "nickname_exact"],
    }]
    stored = str(incident.evidence)
    assert "Ocelot" not in stored and "deals@" not in stored

    session.refresh(existing)
    assert (existing.result, existing.confidence) == ("matched", "low")


def test_ambiguous_incident_has_no_single_matched_site(client, session, signups) -> None:
    result = check(client, recipient="ab12@leaktrap.xyz", nickname="Zephyr", record_incident=True)
    incident = session.get(Incident, result["incident_id"])
    assert (incident.result, incident.matched_site) == ("ambiguous", None)
