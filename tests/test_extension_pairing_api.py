"""Extension pairing, scoped tokens and the API-wide authorization matrix,
against the isolated PostgreSQL test database."""

import hashlib
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import ExtensionPairing, Signup, UserSession
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.services.auth import now, token_hash
from tests.auth_support import ORIGIN, make_account, sign_in

pytestmark = pytest.mark.integration


def local_client(session: Session) -> TestClient:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_dashboard_config] = lambda: DashboardConfig(enabled=True)
    return TestClient(app, client=("127.0.0.1", 50000))


@pytest.fixture
def accounts(session: Session) -> dict:
    return {"alice": make_account(session, "alice@example.com"), "bob": make_account(session, "bob@example.com")}


@pytest.fixture
def alice(session: Session, accounts):
    client = local_client(session)
    sign_in(client, session, accounts["alice"])
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def ext(session: Session):
    """The extension: no cookies, no CSRF token."""
    return local_client(session)


def start(ext):
    secret = secrets.token_urlsafe(32)
    r = ext.post("/extension/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest()})
    assert r.status_code == 201, r.text
    return r.json(), secret


def exchange(ext, pairing_id, secret):
    return ext.post(f"/extension/pairings/{pairing_id}/token", json={"secret": secret})


def connect(ext, alice) -> str:
    started, secret = start(ext)
    assert alice.post("/extension/pairings/approve", json={"code": started["code"]}).status_code == 200
    return exchange(ext, started["pairing_id"], secret).json()["token"]


def test_full_pairing_flow(ext, alice, session, accounts) -> None:
    started, secret = start(ext)
    assert __import__("re").fullmatch(r"[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}", started["code"])
    assert started["approve_path"] == f"/dashboard#pair={started['code']}"
    row = session.get(ExtensionPairing, started["pairing_id"])
    assert row.code_hash == token_hash(started["code"].replace("-", "")) and started["code"] not in row.code_hash

    assert exchange(ext, started["pairing_id"], secret).status_code == 202  # not approved yet
    assert alice.post("/extension/pairings/approve", json={"code": started["code"].lower()}).status_code == 200
    r = exchange(ext, started["pairing_id"], secret)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    issued = r.json()
    assert issued["email"] == "alice@example.com"
    assert issued["scopes"] == ["receipts:create", "reports:create", "signups:create", "signups:lookup"]
    stored = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(issued["token"])))
    assert stored.kind == "extension" and stored.user_id == accounts["alice"].id
    assert timedelta(hours=7, minutes=59) < stored.expires_at - now() <= timedelta(hours=8)
    # Single use.
    assert exchange(ext, started["pairing_id"], secret).status_code == 410


def test_token_can_do_only_its_scoped_actions(ext, alice, session, accounts) -> None:
    token = connect(ext, alice)
    bearer = {"Authorization": f"Bearer {token}"}
    created = ext.post("/signups", json={"site_name": "Shop", "site_domain": "shop.example.com"}, headers=bearer)
    assert created.status_code == 201 and created.json()["user_id"] == accounts["alice"].id
    assert ext.post("/autofill/lookup", json={"site_domain": "shop.example.com"}, headers=bearer).status_code == 200
    receipt = ext.post("/consent-receipts", json={"signup_id": created.json()["id"], "action": "accepted",
                                                  "source_url": "https://shop.example.com/p"}, headers=bearer)
    assert receipt.status_code == 201
    assert ext.get("/extension/whoami", headers=bearer).json() == {
        "email": "alice@example.com", "scopes": ["receipts:create", "reports:create", "signups:create", "signups:lookup"]}
    # Everything else is refused: reading or deleting data, account actions, dashboard, approving pairings.
    for method, path in [("GET", "/signups"), ("GET", f"/signups/{created.json()['id']}"),
                         ("DELETE", f"/signups/{created.json()['id']}"), ("GET", "/consent-receipts"),
                         ("GET", "/dashboard/api/overview"), ("GET", "/auth/me"), ("POST", "/matcher/check"),
                         ("GET", "/extension/sessions"), ("POST", "/extension/pairings/approve")]:
        assert ext.request(method, path, headers=bearer, json={}).status_code == 401, path
    # A Bearer token is not a cookie: it cannot be used as a web session.
    assert session.get(Signup, created.json()["id"]) is not None


def test_wrong_secret_or_unknown_pairing(ext, alice) -> None:
    started, _ = start(ext)
    alice.post("/extension/pairings/approve", json={"code": started["code"]})
    assert exchange(ext, started["pairing_id"], "w" * 40).status_code == 404
    assert exchange(ext, 987654321, "w" * 40).status_code == 404


def test_code_cannot_be_approved_twice_or_guessed(ext, alice, session, accounts) -> None:
    started, secret = start(ext)
    assert alice.post("/extension/pairings/approve", json={"code": started["code"]}).status_code == 200
    bob = local_client(session)
    sign_in(bob, session, accounts["bob"])
    assert bob.post("/extension/pairings/approve", json={"code": started["code"]}).status_code == 404
    assert exchange(ext, started["pairing_id"], secret).json()["email"] == "alice@example.com"
    # Bob has 1 failure already; 9 more reach the limit of 10 failed approvals per 15 minutes.
    for _ in range(9):
        assert bob.post("/extension/pairings/approve", json={"code": "ZZZZ-ZZZZ"}).status_code == 404
    assert bob.post("/extension/pairings/approve", json={"code": "ZZZZ-ZZZZ"}).status_code == 429


def test_expired_pairing(ext, alice, session) -> None:
    started, secret = start(ext)
    session.execute(update(ExtensionPairing).values(expires_at=now() - timedelta(seconds=1)))
    session.commit()
    assert alice.post("/extension/pairings/approve", json={"code": started["code"]}).status_code == 404
    assert exchange(ext, started["pairing_id"], secret).status_code == 410


def test_approval_needs_a_signed_in_session_and_csrf(ext, session) -> None:
    started, _ = start(ext)
    assert ext.post("/extension/pairings/approve", json={"code": started["code"]}, headers={"Origin": ORIGIN}).status_code == 401


def test_pairing_start_is_rate_limited(ext) -> None:
    for _ in range(10):
        start(ext)
    assert ext.post("/extension/pairings", json={"secret_hash": "a" * 64}).status_code == 429


def test_invalid_pairing_input(ext) -> None:
    for body in ({}, {"secret_hash": "not-hex"}, {"secret_hash": "g" * 64}, {"secret_hash": "a" * 63},
                 {"secret_hash": "a" * 64, "user_id": 1}):
        assert ext.post("/extension/pairings", json=body).status_code == 422


def test_revocation_from_dashboard_and_from_extension(ext, alice, session, accounts) -> None:
    first, second = connect(ext, alice), connect(ext, alice)
    listing = alice.get("/extension/sessions").json()
    assert len(listing) == 2 and all(s["label"] == "Browser extension" for s in listing)
    assert "token" not in str(listing)
    bob = local_client(session)
    sign_in(bob, session, accounts["bob"])
    assert bob.delete(f"/extension/sessions/{listing[0]['id']}").status_code == 404  # not Bob's
    assert alice.delete(f"/extension/sessions/{listing[0]['id']}").status_code == 204
    alive = [t for t in (first, second) if ext.get("/extension/whoami", headers={"Authorization": f"Bearer {t}"}).status_code == 200]
    assert len(alive) == 1  # exactly the revoked connection stopped working
    # The extension disconnecting itself.
    assert ext.post("/extension/disconnect", headers={"Authorization": f"Bearer {alive[0]}"}).status_code == 204
    assert ext.get("/extension/whoami", headers={"Authorization": f"Bearer {alive[0]}"}).status_code == 401
    assert alice.get("/extension/sessions").json() == []


def test_expired_extension_token(ext, alice, session) -> None:
    token = connect(ext, alice)
    session.execute(update(UserSession).where(UserSession.kind == "extension").values(expires_at=now() - timedelta(seconds=1)))
    session.commit()
    assert ext.get("/extension/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_web_cookie_cannot_act_as_extension_token(alice) -> None:
    assert alice.get("/extension/whoami").status_code == 401


# ---------- API-wide authorization matrix ----------

PUBLIC = {
    ("POST", "/mobile/v1/login"),
    ("GET", "/"), ("GET", "/health"), ("GET", "/health/ready"), ("POST", "/auth/register"), ("POST", "/auth/login"),
    ("POST", "/auth/verify-email"), ("POST", "/ingest/email"), ("POST", "/extension/pairings"),
    ("POST", "/extension/pairings/{pairing_id}/token"), ("POST", "/mobile/v1/pairings"),
    ("POST", "/mobile/v1/pairings/{pairing_id}/token"),
}


def test_every_private_route_refuses_signed_out_requests(session) -> None:
    client = local_client(session)
    try:
        spec = client.get("/openapi.json").json()
        checked = 0
        for path, ops in spec["paths"].items():
            for method in ops:
                if (method.upper(), path) in PUBLIC:
                    continue
                concrete = path.replace("{signup_id}", "1").replace("{receipt_id}", "1").replace("{mail_log_id}", "1") \
                    .replace("{session_id}", "1").replace("{pairing_id}", "1").replace("{investigation_id}", "1") \
                    .replace("{device_id}", "1").replace("{website_id}", "1").replace("{email_id}", "1")
                r = client.request(method.upper(), concrete, json={}, headers={"Origin": ORIGIN})
                assert r.status_code == 401, (method, path, r.status_code)
                checked += 1
        assert checked >= 20
        assert ("POST", "/ingest/email") in PUBLIC  # protected by its own Worker secret instead
        assert client.post("/ingest/email", json={}).status_code in (401, 503)
    finally:
        app.dependency_overrides.clear()
