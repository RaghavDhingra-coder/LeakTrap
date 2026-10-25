"""Mobile device pairing, mobile Bearer tokens and device management, against
the isolated PostgreSQL test database."""

import hashlib
import logging
import re
import secrets
import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from backend.database import get_db
from backend.main import app
from backend.models import AuthEvent, ExtensionPairing, User, UserSession
from backend.routes.dashboard import DashboardConfig, get_dashboard_config
from backend.security import SESSION_COOKIE
from backend.services import auth as auth_service, pairing
from backend.services.auth import now, token_hash
from tests.auth_support import PASSWORD, extension_token, make_account, mobile_token, sign_in

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
def bob(session: Session, accounts, alice):
    client = local_client(session)
    sign_in(client, session, accounts["bob"])
    return client


@pytest.fixture
def phone(session: Session):
    """The app: no cookies, no CSRF token."""
    return local_client(session)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def start(phone, label: str | None = "Pixel 9"):
    secret = secrets.token_urlsafe(32)
    body = {"secret_hash": hashlib.sha256(secret.encode()).hexdigest()}
    if label is not None:
        body["device_label"] = label
    r = phone.post("/mobile/v1/pairings", json=body)
    assert r.status_code == 201, r.text
    return r.json(), secret


def exchange(phone, pairing_id, secret):
    return phone.post(f"/mobile/v1/pairings/{pairing_id}/token", json={"secret": secret})


def approve(web, code, kind="mobile"):
    return web.post("/extension/pairings/approve", json={"code": code, "kind": kind})


def connect(phone, web, label="Pixel 9") -> str:
    started, secret = start(phone, label)
    assert approve(web, started["code"]).status_code == 200
    return exchange(phone, started["pairing_id"], secret).json()["token"]


def start_extension(client):
    secret = secrets.token_urlsafe(32)
    r = client.post("/extension/pairings", json={"secret_hash": hashlib.sha256(secret.encode()).hexdigest()})
    assert r.status_code == 201, r.text
    return r.json(), secret


# ---------- pairing ----------

def test_full_mobile_pairing_flow(phone, alice, session, accounts) -> None:
    started, secret = start(phone)
    assert re.fullmatch(r"[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}", started["code"])
    assert set(started) == {"pairing_id", "code", "expires_at"}
    row = session.get(ExtensionPairing, started["pairing_id"])
    assert row.client_kind == "mobile" and row.device_label == "Pixel 9"
    assert row.code_hash == token_hash(started["code"].replace("-", ""))
    assert row.secret_hash == hashlib.sha256(secret.encode()).hexdigest() and secret not in row.secret_hash

    pending = exchange(phone, started["pairing_id"], secret)
    assert pending.status_code == 202 and pending.headers["cache-control"] == "no-store"

    preview = alice.post("/mobile/pairings/preview", json={"code": started["code"]})
    assert preview.status_code == 200 and preview.json()["device_label"] == "Pixel 9"
    assert exchange(phone, started["pairing_id"], secret).status_code == 202  # previewing approves nothing

    approved = approve(alice, started["code"].lower())
    assert approved.status_code == 200 and "device" in approved.json()["detail"]
    r = exchange(phone, started["pairing_id"], secret)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    issued = r.json()
    granted = ["account:read", "email:read", "sms:analyze", "sms:write", "timeline:read", "websites:read"]
    assert issued["email"] == "alice@example.com" and issued["scopes"] == granted

    stored = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(issued["token"])))
    assert stored.kind == "mobile" and stored.user_id == accounts["alice"].id
    assert stored.scopes == " ".join(granted) and stored.label == "Pixel 9"
    assert timedelta(days=29, hours=23) < stored.expires_at - now() <= timedelta(days=30)

    me = phone.get("/mobile/v1/me", headers=bearer(issued["token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == "alice@example.com" and body["email_verified"] is True
    assert body["scopes"] == granted
    assert body["device"]["id"] == stored.id and body["device"]["label"] == "Pixel 9"
    assert "token" not in str(body)

    assert exchange(phone, started["pairing_id"], secret).status_code == 410  # single use


def test_concurrent_pairing_exchange_issues_only_one_token(engine, monkeypatch) -> None:
    """Two requests that both read an approved pairing can only claim it once."""
    make_session = sessionmaker(bind=engine, expire_on_commit=False)
    secret = secrets.token_urlsafe(32)
    ip = f"pairing-race-{secrets.token_hex(8)}"
    rate_kind = "mobile_pairing_exchange_ip"
    rate_key = auth_service._key(rate_kind, ip)
    created_at = now()

    with make_session() as db:
        user = User(email=f"pairing-race-{secrets.token_hex(8)}@example.com", password_hash="test-hash",
                    email_verified_at=created_at)
        db.add(user)
        db.flush()
        row = ExtensionPairing(
            code_hash=token_hash(secrets.token_urlsafe(16)),
            secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
            client_kind="mobile",
            device_label="Race test device",
            user_id=user.id,
            approved_at=created_at,
            expires_at=created_at + timedelta(minutes=10),
        )
        db.add(row)
        db.commit()
        user_id, pairing_id = user.id, row.id

    both_ready_to_claim = threading.Barrier(2)
    claim = pairing._claim_exchange

    def synchronize_claim(db, row, kind, claimed_at):
        # Force both requests past the initial read/validation before either
        # performs the database's atomic compare-and-set.
        both_ready_to_claim.wait(timeout=15)
        return claim(db, row, kind, claimed_at)

    monkeypatch.setattr(pairing, "_claim_exchange", synchronize_claim)

    def exchange_once():
        with make_session() as db:
            try:
                return pairing.exchange(db, pairing_id, secret, ip, "mobile")
            except pairing.PairingExpired:
                return None

    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: exchange_once(), range(2)))

        issued = [outcome for outcome in outcomes if outcome is not None]
        assert len(issued) == 1
        assert issued[0].scopes == tuple(sorted(pairing.MOBILE_GRANTED_SCOPES))

        with make_session() as db:
            sessions = list(db.scalars(select(UserSession).where(
                UserSession.user_id == user_id, UserSession.kind == "mobile"
            )))
            assert len(sessions) == 1
            assert sessions[0].scopes == " ".join(issued[0].scopes)
            assert db.scalar(select(func.count()).select_from(ExtensionPairing).where(
                ExtensionPairing.id == pairing_id, ExtensionPairing.consumed_at.is_not(None)
            )) == 1
    finally:
        with make_session() as db:
            db.execute(delete(UserSession).where(UserSession.user_id == user_id))
            db.execute(delete(ExtensionPairing).where(ExtensionPairing.id == pairing_id))
            db.execute(delete(User).where(User.id == user_id))
            db.execute(delete(AuthEvent).where(AuthEvent.kind == rate_kind, AuthEvent.key_hash == rate_key))
            db.commit()


def test_missing_or_blank_label_gets_a_default(phone, alice) -> None:
    for label in (None, "   "):
        started, secret = start(phone, label)
        assert alice.post("/mobile/pairings/preview", json={"code": started["code"]}).json()["device_label"] == "Mobile device"
        approve(alice, started["code"])
        token = exchange(phone, started["pairing_id"], secret).json()["token"]
        assert phone.get("/mobile/v1/me", headers=bearer(token)).json()["device"]["label"] == "Mobile device"


def test_extension_and_mobile_pairings_cannot_be_crossed(phone, alice, session) -> None:
    mobile, mobile_secret = start(phone)
    extension, extension_secret = start_extension(phone)

    # Approving as the wrong kind is refused like an unknown code; the default kind is "extension".
    assert alice.post("/extension/pairings/approve", json={"code": mobile["code"]}).status_code == 404
    assert approve(alice, mobile["code"], kind="extension").status_code == 404
    assert approve(alice, extension["code"], kind="mobile").status_code == 404
    assert alice.post("/mobile/pairings/preview", json={"code": extension["code"]}).status_code == 404

    # Exchanging on the other kind's route fails, even once approved.
    assert approve(alice, mobile["code"]).status_code == 200
    assert approve(alice, extension["code"], kind="extension").status_code == 200
    assert phone.post(f"/extension/pairings/{mobile['pairing_id']}/token", json={"secret": mobile_secret}).status_code == 404
    assert exchange(phone, extension["pairing_id"], extension_secret).status_code == 404

    # Each still works on its own route and yields its own kind of token.
    ext_token = phone.post(f"/extension/pairings/{extension['pairing_id']}/token",
                           json={"secret": extension_secret}).json()["token"]
    mob_token = exchange(phone, mobile["pairing_id"], mobile_secret).json()["token"]
    kinds = {s.kind for s in session.scalars(select(UserSession).where(
        UserSession.token_hash.in_([token_hash(ext_token), token_hash(mob_token)])))}
    assert kinds == {"extension", "mobile"}

    # The extension's start route does not accept a device label.
    assert phone.post("/extension/pairings", json={"secret_hash": "a" * 64, "device_label": "x"}).status_code == 422


def test_expired_reused_and_other_users_codes(phone, alice, bob, session) -> None:
    started, secret = start(phone)
    assert approve(alice, started["code"]).status_code == 200
    assert approve(alice, started["code"]).status_code == 404  # already approved
    assert approve(bob, started["code"]).status_code == 404
    assert alice.post("/mobile/pairings/preview", json={"code": started["code"]}).status_code == 404
    assert exchange(phone, started["pairing_id"], secret).json()["email"] == "alice@example.com"

    expired, expired_secret = start(phone)
    session.execute(update(ExtensionPairing).where(ExtensionPairing.id == expired["pairing_id"])
                    .values(expires_at=now() - timedelta(seconds=1)))
    session.commit()
    assert alice.post("/mobile/pairings/preview", json={"code": expired["code"]}).status_code == 404
    assert approve(alice, expired["code"]).status_code == 404
    assert exchange(phone, expired["pairing_id"], expired_secret).status_code == 410


def test_wrong_secret_or_unknown_pairing(phone, alice) -> None:
    started, _ = start(phone)
    approve(alice, started["code"])
    assert exchange(phone, started["pairing_id"], "w" * 40).status_code == 404
    assert exchange(phone, 987654321, "w" * 40).status_code == 404


def test_preview_and_approval_need_a_signed_in_session_and_csrf(phone, alice) -> None:
    started, _ = start(phone)
    assert phone.post("/mobile/pairings/preview", json={"code": started["code"]}).status_code == 401
    assert approve(phone, started["code"]).status_code == 401
    del alice.headers["X-CSRF-Token"]
    assert alice.post("/mobile/pairings/preview", json={"code": started["code"]}).status_code == 403
    assert approve(alice, started["code"]).status_code == 403


def test_failed_previews_count_towards_the_approval_limit(phone, alice) -> None:
    for _ in range(10):
        assert alice.post("/mobile/pairings/preview", json={"code": "ZZZZ-ZZZZ"}).status_code == 404
    started, _ = start(phone)
    assert alice.post("/mobile/pairings/preview", json={"code": started["code"]}).status_code == 429
    assert approve(alice, started["code"]).status_code == 429


def test_invalid_pairing_input(phone) -> None:
    for body in ({}, {"secret_hash": "not-hex"}, {"secret_hash": "a" * 63}, {"secret_hash": "a" * 64, "user_id": 1},
                 {"secret_hash": "a" * 64, "device_label": "x" * 65},
                 {"secret_hash": "a" * 64, "device_label": "Phone\x00"},
                 {"secret_hash": "a" * 64, "device_label": "Pho​ne"}):
        r = phone.post("/mobile/v1/pairings", json=body)
        assert r.status_code == 422, body
        assert "Phone" not in r.text  # validation errors never echo values
    assert phone.post("/mobile/v1/pairings/1/token", json={"secret": "short"}).status_code == 422


def test_mobile_pairing_start_has_its_own_rate_limit(phone) -> None:
    for _ in range(10):
        start(phone)
    assert phone.post("/mobile/v1/pairings", json={"secret_hash": "a" * 64}).status_code == 429
    start_extension(phone)  # the extension's limit is separate


# ---------- tokens ----------

def test_missing_malformed_and_unknown_tokens(phone) -> None:
    for headers in ({}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}, {"Authorization": "Bearer"}):
        r = phone.get("/mobile/v1/me", headers=headers)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", headers
    for token in ("not-a-real-token", "x" * 201):
        r = phone.get("/mobile/v1/me", headers=bearer(token))
        assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert phone.post("/mobile/v1/logout", headers=bearer("not-a-real-token")).status_code == 401


def test_expired_and_idle_tokens(phone, session, accounts) -> None:
    expired = mobile_token(session, accounts["alice"])
    idle = mobile_token(session, accounts["alice"])
    fresh = mobile_token(session, accounts["alice"])
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(expired))
                    .values(expires_at=now() - timedelta(seconds=1)))
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(idle))
                    .values(last_used_at=now() - timedelta(days=14, minutes=1)))
    session.commit()
    assert phone.get("/mobile/v1/me", headers=bearer(expired)).status_code == 401
    assert phone.get("/mobile/v1/me", headers=bearer(idle)).status_code == 401
    assert phone.get("/mobile/v1/me", headers=bearer(fresh)).status_code == 200


def test_logout_revokes_only_this_device(phone, session, accounts) -> None:
    first, second = mobile_token(session, accounts["alice"]), mobile_token(session, accounts["alice"])
    assert phone.post("/mobile/v1/logout", headers=bearer(first)).status_code == 204
    assert phone.get("/mobile/v1/me", headers=bearer(first)).status_code == 401
    assert phone.post("/mobile/v1/logout", headers=bearer(first)).status_code == 401
    assert phone.get("/mobile/v1/me", headers=bearer(second)).status_code == 200


def test_disabled_account_tokens_stop_working(phone, session, accounts) -> None:
    token = mobile_token(session, accounts["alice"])
    session.execute(update(User).where(User.id == accounts["alice"].id).values(disabled_at=now()))
    session.commit()
    assert phone.get("/mobile/v1/me", headers=bearer(token)).status_code == 401


def test_password_change_revokes_mobile_devices(phone, alice, session, accounts) -> None:
    token = connect(phone, alice)
    r = alice.post("/auth/password", json={"current_password": PASSWORD, "new_password": "another long passphrase"})
    assert r.status_code == 204
    assert phone.get("/mobile/v1/me", headers=bearer(token)).status_code == 401
    assert alice.get("/mobile/devices").json() == []


def test_account_deletion_removes_mobile_devices(phone, alice, session, accounts) -> None:
    token = connect(phone, alice)
    assert alice.request("DELETE", "/account", json={"password": PASSWORD, "confirm": "DELETE"}).status_code == 204
    assert phone.get("/mobile/v1/me", headers=bearer(token)).status_code == 401
    assert session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token))) is None


def test_missing_and_insufficient_scopes(phone, session, accounts) -> None:
    for scopes in ((), ("websites:read",), ("sms:analyze", "sms:write")):
        token = mobile_token(session, accounts["alice"], scopes=scopes)
        r = phone.get("/mobile/v1/me", headers=bearer(token))
        assert r.status_code == 403 and r.json()["detail"] == "This device is not allowed to do that."
        assert phone.post("/mobile/v1/logout", headers=bearer(token)).status_code == 204  # any device may sign out


def test_unknown_scope_is_a_programming_error() -> None:
    from backend.security import require_mobile

    with pytest.raises(ValueError):
        require_mobile("signups:create")


def test_web_sessions_and_extension_tokens_are_refused_on_mobile_routes(phone, alice, session, accounts) -> None:
    assert alice.get("/mobile/v1/me").status_code == 401  # cookie + CSRF header
    assert alice.post("/mobile/v1/logout").status_code == 401
    ext = extension_token(session, accounts["alice"])
    assert phone.get("/mobile/v1/me", headers=bearer(ext)).status_code == 401
    assert phone.post("/mobile/v1/logout", headers=bearer(ext)).status_code == 401
    # The web session's own token, sent as a Bearer, is refused too.
    web = auth_service.create_session(session, accounts["alice"].id, "web")
    session.commit()
    assert phone.get("/mobile/v1/me", headers=bearer(web.token)).status_code == 401


def test_mobile_tokens_are_refused_everywhere_else(phone, session, accounts) -> None:
    token = mobile_token(session, accounts["alice"], scopes=("account:read", "websites:read", "email:read",
                                                            "timeline:read", "sms:analyze", "sms:write"))
    for method, path in [("GET", "/auth/me"), ("POST", "/auth/logout"), ("GET", "/extension/whoami"),
                         ("POST", "/extension/disconnect"), ("GET", "/extension/sessions"),
                         ("POST", "/extension/pairings/approve"), ("GET", "/signups"), ("POST", "/signups"),
                         ("POST", "/autofill/lookup"), ("GET", "/consent-receipts"), ("POST", "/matcher/check"),
                         ("GET", "/dashboard/api/overview"), ("GET", "/dashboard/api/timeline"),
                         ("GET", "/dashboard/api/sms/investigations"), ("GET", "/mobile/devices"),
                         ("POST", "/mobile/pairings/preview")]:
        r = phone.request(method, path, headers=bearer(token), json={})
        assert r.status_code == 401, (method, path, r.status_code)
    # Nor does it work as a session cookie.
    phone.cookies.set(SESSION_COOKIE, token)
    assert phone.get("/auth/me").status_code == 401
    assert phone.get("/dashboard/api/overview").status_code == 401


# ---------- devices ----------

def test_device_list_and_revocation(phone, alice, bob, session, accounts) -> None:
    first, second = connect(phone, alice, "Pixel 9"), connect(phone, alice, "Work phone")
    extension_token(session, accounts["alice"])
    devices = alice.get("/mobile/devices").json()
    assert sorted(d["label"] for d in devices) == ["Pixel 9", "Work phone"]  # extensions are not listed
    assert "token" not in str(devices)
    assert bob.get("/mobile/devices").json() == []

    target = next(d for d in devices if d["label"] == "Pixel 9")
    assert bob.delete(f"/mobile/devices/{target['id']}").status_code == 404  # not Bob's
    extension_id = alice.get("/extension/sessions").json()[0]["id"]
    assert alice.delete(f"/mobile/devices/{extension_id}").status_code == 404  # not a mobile device
    assert alice.get("/extension/sessions").json()[0]["id"] == extension_id

    csrf = alice.headers.pop("X-CSRF-Token")
    assert alice.delete(f"/mobile/devices/{target['id']}").status_code == 403
    alice.headers["X-CSRF-Token"] = csrf
    assert alice.delete(f"/mobile/devices/{target['id']}").status_code == 204
    assert phone.get("/mobile/v1/me", headers=bearer(first)).status_code == 401
    assert phone.get("/mobile/v1/me", headers=bearer(second)).status_code == 200
    assert [d["label"] for d in alice.get("/mobile/devices").json()] == ["Work phone"]
    assert alice.delete(f"/mobile/devices/{target['id']}").status_code == 404  # already revoked


def test_idle_and_expired_devices_are_not_listed(alice, session, accounts) -> None:
    idle, expired = mobile_token(session, accounts["alice"]), mobile_token(session, accounts["alice"])
    mobile_token(session, accounts["alice"])
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(idle))
                    .values(last_used_at=now() - timedelta(days=15)))
    session.execute(update(UserSession).where(UserSession.token_hash == token_hash(expired))
                    .values(expires_at=now() - timedelta(seconds=1)))
    session.commit()
    assert len(alice.get("/mobile/devices").json()) == 1


# ---------- secrets stay secret ----------

def test_logs_and_storage_never_contain_secrets(phone, alice, session, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    started, secret = start(phone, "Pixel 9")
    alice.post("/mobile/pairings/preview", json={"code": started["code"]})
    approve(alice, started["code"])
    token = exchange(phone, started["pairing_id"], secret).json()["token"]
    phone.get("/mobile/v1/me", headers=bearer(token))
    phone.post("/mobile/v1/logout", headers=bearer(token))

    logged = caplog.text
    for value in (secret, token, started["code"], started["code"].replace("-", "")):
        assert value not in logged
    pairing_row = session.get(ExtensionPairing, started["pairing_id"])
    session_row = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    stored = " ".join(str(v) for v in (*vars(pairing_row).values(), *vars(session_row).values()))
    for value in (secret, token, started["code"].replace("-", "")):
        assert value not in stored
