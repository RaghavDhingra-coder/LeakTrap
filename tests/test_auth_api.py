"""Accounts and sessions against the isolated PostgreSQL test database."""

import logging
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.main import app
from backend.models import AuthEvent, ConsentReceipt, MailLog, Signup, User, UserSession
from backend.security import SESSION_COOKIE
from backend.services import auth as auth_service
from tests.auth_support import ORIGIN, PASSWORD, make_account, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
def client(session: Session):
    app.dependency_overrides[get_db] = lambda: session
    yield TestClient(app, client=("127.0.0.1", 50000), headers={"Origin": ORIGIN})
    app.dependency_overrides.clear()


def register(client, email="alice@example.com", password=PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def login(client, email="alice@example.com", password=PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_register_then_login_sets_secure_session(client, session) -> None:
    r = register(client, "Alice@Example.com")
    assert r.status_code == 202
    assert r.json() == {"detail": "If this email address was not already registered, your account has been created. "
                        "Sign in to continue.", "verification_email_sent": False}
    user = session.scalar(select(User).where(User.email == "alice@example.com"))
    assert user.password_hash.startswith("$argon2id$") and PASSWORD not in user.password_hash
    assert SESSION_COOKIE not in client.cookies  # registration does not sign in

    r = login(client, "ALICE@example.com")
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "alice@example.com" and body["email_delivery_configured"] is False
    assert len(body["csrf_token"]) == 64
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    raw = client.cookies[SESSION_COOKIE]
    stored = session.scalar(select(UserSession).where(UserSession.user_id == user.id))
    assert stored.token_hash == auth_service.token_hash(raw) and raw not in stored.token_hash


def test_duplicate_registration_is_indistinguishable(client, session) -> None:
    first, second = register(client), register(client, "alice@example.com", "a different long password")
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    assert session.scalar(select(func.count()).select_from(User).where(User.email == "alice@example.com")) == 1
    assert login(client, password="a different long password").status_code == 401  # not overwritten


@pytest.mark.parametrize(("password", "message"), [
    ("short", "Use at least 12 characters."), (" " * 20, "The password cannot be only spaces."),
    ("alice@example.com", "The password cannot be your email address."), ("x" * 300, None)])
def test_password_policy(client, password, message) -> None:
    r = register(client, password=password)
    assert r.status_code == 422
    assert password not in r.text
    if message:
        assert r.json()["detail"][0]["msg"] == message


def test_invalid_registration_input(client) -> None:
    for body in ({"email": "not-an-email", "password": PASSWORD}, {"email": "a@example.com"},
                 {"email": "a@example.com", "password": PASSWORD, "admin": True}):
        r = client.post("/auth/register", json=body)
        assert r.status_code == 422 and PASSWORD not in r.text


def test_wrong_password_and_unknown_email_give_the_same_answer(client, session) -> None:
    make_account(session, "alice@example.com")
    wrong, unknown = login(client, password="not the right password"), login(client, "nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Incorrect email or password."}
    assert SESSION_COOKIE not in client.cookies


def test_failed_logins_are_rate_limited_per_account(client, session) -> None:
    make_account(session, "alice@example.com")
    for _ in range(5):
        assert login(client, password="wrong password here").status_code == 401
    r = login(client)  # even the right password is refused while limited
    assert r.status_code == 429
    assert session.scalar(select(func.count()).select_from(AuthEvent)) >= 5
    raw = session.scalars(select(AuthEvent.key_hash)).all()
    assert not any("alice" in k or "127.0.0.1" in k for k in raw)  # identifiers are hashed


def test_registration_is_rate_limited_per_ip(client) -> None:
    for i in range(5):
        assert register(client, f"user{i}@example.com").status_code == 202
    assert register(client, "user5@example.com").status_code == 429


def test_me_requires_a_session(client, session) -> None:
    assert client.get("/auth/me").status_code == 401
    user = make_account(session, "alice@example.com")
    csrf = sign_in(client, session, user)
    me = client.get("/auth/me").json()
    assert me == {"email": "alice@example.com", "email_verified": True, "csrf_token": csrf,
                  "email_delivery_configured": False, "is_domain_verification_admin": False}


def test_csrf_and_origin_are_required_for_state_changes(client, session) -> None:
    user = make_account(session, "alice@example.com")
    csrf = sign_in(client, session, user)
    client.headers.pop("X-CSRF-Token")
    assert client.post("/auth/logout").status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"}).status_code == 403
    no_origin = TestClient(app, client=("127.0.0.1", 50000))
    no_origin.cookies.set(SESSION_COOKIE, client.cookies[SESSION_COOKIE])
    assert no_origin.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204


def test_logout_revokes_the_session(client, session) -> None:
    user = make_account(session, "alice@example.com")
    sign_in(client, session, user)
    token = client.cookies[SESSION_COOKIE]
    assert client.post("/auth/logout").status_code == 204
    replay = TestClient(app, client=("127.0.0.1", 50000))
    replay.cookies.set(SESSION_COOKIE, token)
    assert replay.get("/auth/me").status_code == 401


def test_sessions_expire(client, session) -> None:
    user = make_account(session, "alice@example.com")
    sign_in(client, session, user)
    session.execute(update(UserSession).values(last_used_at=auth_service.now() - timedelta(hours=13)))
    session.commit()
    assert client.get("/auth/me").status_code == 401  # idle timeout
    sign_in(client, session, user)
    session.execute(update(UserSession).where(UserSession.revoked_at.is_(None))
                    .values(expires_at=auth_service.now() - timedelta(seconds=1)))
    session.commit()
    assert client.get("/auth/me").status_code == 401  # absolute expiry


def test_disabled_accounts_cannot_use_sessions(client, session) -> None:
    user = make_account(session, "alice@example.com")
    sign_in(client, session, user)
    user.disabled_at = auth_service.now()
    session.commit()
    assert client.get("/auth/me").status_code == 401
    assert login(client).status_code == 401


def test_password_change_signs_out_other_sessions(client, session) -> None:
    user = make_account(session, "alice@example.com")
    other = TestClient(app, client=("127.0.0.1", 50000), headers={"Origin": ORIGIN})
    sign_in(other, session, user)
    sign_in(client, session, user)
    assert client.post("/auth/password", json={"current_password": "wrong one entirely", "new_password": "x" * 20}).status_code == 401
    assert client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "short"}).status_code == 422
    assert client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "a brand new passphrase"}).status_code == 204
    assert client.get("/auth/me").status_code == 200
    assert other.get("/auth/me").status_code == 401
    assert login(client, password="a brand new passphrase").status_code == 200


def test_email_verification_flow_without_delivery(client, session, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    register(client)
    user = session.scalar(select(User).where(User.email == "alice@example.com"))
    assert user.email_verified_at is None
    token = auth_service.issue_verification_token(session, user.id)  # what a provider would email
    session.commit()
    assert token not in caplog.text
    login(client)
    client.headers["X-CSRF-Token"] = client.get("/auth/me").json()["csrf_token"]
    resend = client.post("/auth/verification/resend")
    assert resend.status_code == 202
    assert resend.json() == {"detail": "Email delivery is not configured, so no verification email was sent.",
                             "verification_email_sent": False}
    assert client.post("/auth/verify-email", json={"token": "x" * 40}).status_code == 400
    assert client.post("/auth/verify-email", json={"token": token}).json() == {"detail": "Your email address is verified."}
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400  # single use
    session.expire_all()
    assert session.get(User, user.id).email_verified_at is not None


def test_unverified_login_blocked_outside_development(client, session, monkeypatch) -> None:
    monkeypatch.setattr(auth_service, "settings", replace(auth_service.settings, allow_unverified_login=False))
    make_account(session, "alice@example.com", verified=False)
    assert login(client, password="wrong password here").json() == {"detail": "Incorrect email or password."}
    r = login(client)
    assert r.status_code == 403 and r.json() == {"detail": "Verify your email address before signing in."}


def test_account_deletion_removes_only_own_records(client, session) -> None:
    alice, bob = make_account(session, "alice@example.com"), make_account(session, "bob@example.com")
    for owner in (alice, bob, None):
        s = Signup(user_id=owner.id if owner else None, site_name="Shop", site_domain="shop.example.com")
        session.add(s)
        session.flush()
        session.add_all([ConsentReceipt(user_id=s.user_id, signup_id=s.id, privacy_notice_text=""),
                         MailLog(user_id=s.user_id, signup_id=s.id)])
    session.commit()
    sign_in(client, session, alice)
    assert client.request("DELETE", "/account", json={"password": "wrong password!!", "confirm": "DELETE"}).status_code == 401
    assert client.request("DELETE", "/account", json={"password": PASSWORD}).status_code == 422
    r = client.request("DELETE", "/account", json={"password": PASSWORD, "confirm": "DELETE"})
    assert r.status_code == 204
    session.expire_all()
    assert session.get(User, alice.id) is None and session.get(User, bob.id) is not None
    owners = sorted(str(o) for o in session.scalars(select(Signup.user_id)).all())
    assert owners == sorted([str(bob.id), "None"])  # Bob's and the unowned record remain
    assert session.scalar(select(func.count()).select_from(ConsentReceipt)) == 2
    assert session.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == alice.id)) == 0


def test_passwords_never_appear_in_responses_or_logs(client, session, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    texts = [register(client).text, login(client).text, login(client, password="wrong password here").text,
             client.post("/auth/register", json={"email": "bad", "password": PASSWORD}).text]
    assert all(PASSWORD not in t for t in texts)
    assert PASSWORD not in caplog.text
