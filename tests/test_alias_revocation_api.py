"""Alias state transitions and the authenticated Cloudflare Worker status check."""
from datetime import datetime

import pytest

from tests.test_inbox_api import accounts, signups, alice, bob, worker, deliver  # noqa: F401

pytestmark = pytest.mark.integration
WORKER = {"Authorization": "Bearer " + "k" * 48}


def check_status(worker, recipient):
    return worker.post("/ingest/alias-status", json={"recipient": recipient}, headers=WORKER)


def test_revoke_restore_worker_status_and_preserved_history(alice, bob, worker, signups, session):
    signup = signups["shop"]
    previous = deliver(worker, signup.alias, 50)["mail_log_id"]
    listed = alice.get("/signups").json()
    item = next(row for row in listed["items"] if row["id"] == signup.id)
    assert item["alias_status"] == "active"
    assert check_status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": False}

    revoked = alice.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "revoked"})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["alias_status"] == "revoked"
    assert datetime.fromisoformat(revoked.json()["alias_status_changed_at"])
    session.expire_all()  # Read the saved value again, not the signup object held by the fixture.
    assert check_status(worker, signup.alias).json() == {"status": "revoked"}
    assert check_status(worker, signups["news"].alias).json() == {"status": "active", "block_promotional_emails": False}
    assert bob.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "active"}).status_code == 404

    # The ingest endpoint independently refuses revoked mail and retains the existing message.
    blocked = worker.post("/ingest/email", json={"recipient": signup.alias,
        "envelope_from": "bounce@example.test", "from_header": "Notice <notice@example.test>",
        "message_id": "<revoked-mail@example.test>"}, headers=WORKER)
    assert blocked.status_code == 410
    assert alice.get(f"/dashboard/api/inbox/{previous}").status_code == 200

    restored = alice.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "active"})
    assert restored.status_code == 200 and restored.json()["alias_status"] == "active"
    session.expire_all()
    assert check_status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": False}


def test_worker_status_is_secret_authenticated_and_fail_closed(worker, signups):
    signup = signups["shop"]
    assert worker.post("/ingest/alias-status", json={"recipient": signup.alias}).status_code == 401
    assert check_status(worker, "nobody@leaktrap.xyz").json() == {"status": "unverifiable"}
    for payload in ({}, {"recipient": "not-an-address"}, {"recipient": signup.alias, "user_id": signup.user_id}):
        response = worker.post("/ingest/alias-status", json=payload, headers=WORKER)
        assert response.status_code == 422


def test_alias_status_validation_and_revoked_alias_not_autofilled(alice, worker, signups, session):
    signup = signups["shop"]
    signups["news"].site_domain = "news.example.com"
    session.commit()
    assert check_status(worker, signups["news"].alias).json() == {"status": "active", "block_promotional_emails": False}
    assert alice.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "paused"}).status_code == 422
    assert alice.patch("/signups/987654321/alias-status", json={"alias_status": "revoked"}).status_code == 404
    assert alice.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "revoked", "user_id": 1}).status_code == 422
    assert alice.patch(f"/signups/{signup.id}/alias-status", json={"alias_status": "revoked"}).status_code == 200
    result = alice.post("/autofill/lookup", json={"site_domain": "shop.example.com"}).json()
    assert signup.alias not in str(result)
    # Other active aliases remain usable.
    active = alice.post("/autofill/lookup", json={"site_domain": "news.example.com"})
    assert active.status_code == 200
