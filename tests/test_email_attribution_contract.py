"""Recipient attribution, independent of claimed sender or source heuristics."""
import pytest
from backend.models import MailLog
from tests.auth_support import mobile_token
from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver, inbox, NOW  # noqa: F401

pytestmark = pytest.mark.integration


def views(alice, worker, session, user, mail_id):
    token = mobile_token(session, user, scopes=("email:read",))
    web = alice.get(f"/dashboard/api/emails/{mail_id}").json()
    response = worker.get(f"/mobile/v1/emails/{mail_id}", headers={"Authorization":f"Bearer {token}"})
    assert response.status_code == 200, response.text
    mobile = response.json()
    detail = alice.get(f"/dashboard/api/inbox/{mail_id}").json()
    assert web["status"] == mobile["status"] == detail["status"]
    assert web["site_name"] == mobile["site_name"] == detail["site_name"]
    return web


def test_envelope_alias_wins_over_sender_and_multiple_recipients(alice, bob, worker, signups, session, accounts):
    delivered = []
    for n, key in enumerate(("shop", "news", "bob")):
        d = deliver(worker, signups[key].alias, n, message_id="<same-multi@example.com>",
                    from_header="Facebook Support <facebook@facebook.com>", subject="Facebook: urgent Amazon account")
        assert d["ingest_status"] == "matched"
        delivered.append(d["mail_log_id"])
        row = session.get(MailLog, d["mail_log_id"])
        assert row.signup_id == signups[key].id and row.user_id == signups[key].user_id
    assert len(set(delivered)) == 3
    a = views(alice, worker, session, accounts["alice"], delivered[0])
    assert a["site_name"] == "Example Shop"
    assert {r["id"] for r in inbox(alice)["items"]} == set(delivered[:2])
    assert alice.get(f"/dashboard/api/inbox/{delivered[2]}").status_code == 404


def test_unknown_and_unowned_never_match(alice, worker, signups, session):
    for n, alias in enumerate(("unknown@leaktrap.xyz", signups["historical"].alias)):
        d = deliver(worker, alias, n, from_header="Example Shop <sales@shop.example.com>")
        assert d["ingest_status"] == "unmatched"
        row = session.get(MailLog, d["mail_log_id"])
        assert row.user_id is None and row.subject is None
    assert not inbox(alice)["items"]


@pytest.mark.parametrize("damage", ["wrong_site", "other_user", "unknown_alias", "unregistered", "legacy", "failed", "malformed_both"])
def test_inconsistent_and_historical_links_not_fabricated(alice, worker, signups, session, accounts, damage):
    d = deliver(worker, signups["shop"].alias, 1)
    row = session.get(MailLog, d["mail_log_id"])
    if damage == "wrong_site": row.signup_id = signups["news"].id
    if damage == "other_user": row.signup_id = signups["bob"].id; row.alias = signups["bob"].alias
    if damage == "malformed_both":
        row.alias = "malformed"
        signups["shop"].alias = "malformed"
    if damage == "unknown_alias": row.alias = "invalid"
    if damage == "unregistered": row.ingest_status = "unmatched"; row.status_reason = "unknown_alias"
    if damage == "legacy": row.ingest_status = None
    if damage == "failed": row.ingest_status = "failed"; row.status_reason = "analysis_failed"
    session.commit()
    stored_before = row.ingest_status
    result = views(alice, worker, session, accounts["alice"], row.id)
    expected = "unprocessed" if damage == "legacy" else "failed" if damage == "failed" else "unmatched"
    assert result["status"] == expected
    if damage not in ("failed", "malformed_both"):
        duplicate = deliver(worker, signups["shop"].alias, 1)
        assert duplicate["ingest_status"] == expected
    if damage != "failed": assert result["site_name"] is None
    session.expire(row)
    assert row.ingest_status == stored_before  # reads and dedup checks never rewrite history


@pytest.mark.parametrize("recipient", [None, "", "malformed", ["a@leaktrap.xyz", "b@leaktrap.xyz"]])
def test_bad_envelope_rejected(worker, recipient):
    from tests.test_inbox_api import SECRET
    r = worker.post("/ingest/email", headers={"Authorization":f"Bearer {SECRET}"}, json={"recipient":recipient,"received_at":NOW.isoformat()})
    assert r.status_code == 422
