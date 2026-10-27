"""Per-alias preference and the machine-readable status contract, using a disposable database."""

import pytest

from backend.models import Signup
from tests.test_inbox_api import accounts, signups, alice, bob, worker  # noqa: F401

pytestmark = pytest.mark.integration
WORKER = {"Authorization": "Bearer " + "k" * 48}


def status(worker, recipient):
    return worker.post("/ingest/alias-status", json={"recipient": recipient}, headers=WORKER)


def test_preference_defaults_off_and_persists_through_dashboard_and_worker(alice, worker, signups, session):
    signup = signups["shop"]
    assert signup.block_promotional_emails is False
    assert status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": False}
    response = alice.patch(f"/signups/{signup.id}/promotional-filter",
                           json={"block_promotional_emails": True})
    assert response.status_code == 200, response.text
    assert response.json()["block_promotional_emails"] is True
    session.expire_all()
    assert status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": True}
    detail = alice.get(f"/dashboard/api/signups/{signup.id}")
    assert detail.status_code == 200 and detail.json()["block_promotional_emails"] is True
    listed = alice.get("/dashboard/api/signups").json()["items"]
    assert next(item for item in listed if item["id"] == signup.id)["block_promotional_emails"] is True
    assert status(worker, signups["news"].alias).json() == {"status": "active", "block_promotional_emails": False}

    disabled = alice.patch(f"/signups/{signup.id}/promotional-filter",
                           json={"block_promotional_emails": False})
    assert disabled.status_code == 200
    session.expire_all()
    assert status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": False}


def test_preference_requires_owner_and_strict_boolean(alice, bob, worker, signups, session):
    signup = signups["shop"]
    path = f"/signups/{signup.id}/promotional-filter"
    assert worker.patch(path, json={"block_promotional_emails": True}).status_code == 401
    assert bob.patch(path, json={"block_promotional_emails": True}).status_code == 404
    for payload in ({}, {"block_promotional_emails": "true"}, {"block_promotional_emails": 1},
                    {"block_promotional_emails": True, "user_id": signup.user_id}):
        assert alice.patch(path, json=payload).status_code == 422
    assert alice.patch("/signups/987654321/promotional-filter",
                       json={"block_promotional_emails": True}).status_code == 404
    assert status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": False}

    no_alias = Signup(user_id=signup.user_id, site_name="No alias")
    session.add(no_alias)
    session.commit()
    assert alice.patch(f"/signups/{no_alias.id}/promotional-filter",
                       json={"block_promotional_emails": True}).status_code == 409


def test_revocation_still_wins_over_preference(alice, worker, signups):
    signup = signups["shop"]
    assert alice.patch(f"/signups/{signup.id}/promotional-filter",
                       json={"block_promotional_emails": True}).status_code == 200
    assert alice.patch(f"/signups/{signup.id}/alias-status",
                       json={"alias_status": "revoked"}).status_code == 200
    assert status(worker, signup.alias).json() == {"status": "revoked"}
    assert alice.patch(f"/signups/{signup.id}/alias-status",
                       json={"alias_status": "active"}).status_code == 200
    assert status(worker, signup.alias).json() == {"status": "active", "block_promotional_emails": True}


def test_new_signup_defaults_to_disabled(worker, signups, session):
    signup = Signup(user_id=signups["shop"].user_id, site_name="New", alias="newalias@leaktrap.xyz")
    session.add(signup)
    session.commit()
    session.expire_all()
    assert status(worker, "newalias@leaktrap.xyz").json() == {
        "status": "active", "block_promotional_emails": False,
    }
