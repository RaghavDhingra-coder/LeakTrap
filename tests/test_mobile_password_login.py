"""Password login uses the same verified-account and mobile session boundaries."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from backend.models import UserSession
from backend.security import MOBILE_GRANTED_SCOPES
from backend.services.auth import now, token_hash
from tests.auth_support import PASSWORD
from tests.test_mobile_auth_api import accounts, alice, phone, bearer  # noqa: F401

pytestmark = pytest.mark.integration


def login(phone, email="alice@example.com", password=PASSWORD):
    return phone.post("/mobile/v1/login", json={"email": email, "password": password, "device_label": "Android test"})


def test_login_scoped_session_and_logout(phone, alice, accounts, session):
    r = login(phone)
    assert r.status_code == 200, r.text
    data = r.json()
    assert r.headers["cache-control"] == "no-store"
    assert "set-cookie" not in r.headers
    assert set(data["scopes"]) == set(MOBILE_GRANTED_SCOPES)
    token = data["token"]
    row = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    assert row.kind == "mobile" and row.user_id == accounts["alice"].id
    me = phone.get("/mobile/v1/me", headers=bearer(token))
    assert me.status_code == 200 and me.json()["email"] == "alice@example.com"
    assert phone.get("/mobile/v1/me", headers=bearer(token), params={"user_id": accounts["bob"].id}).json()["email"] == "alice@example.com"
    assert phone.get("/dashboard/api/emails", headers=bearer(token)).status_code == 401
    assert phone.post("/mobile/v1/logout", headers=bearer(token)).status_code == 204
    assert phone.get("/mobile/v1/me", headers=bearer(token)).status_code == 401


@pytest.mark.parametrize("kind,code,reason", [("wrong",401,"invalid_credentials"), ("unknown",401,"invalid_credentials"),
    ("unverified",403,"email_unverified"), ("disabled",403,"account_disabled")])
def test_login_errors(phone, alice, accounts, session, kind, code, reason, caplog):
    user = accounts["alice"]
    if kind == "unverified": user.email_verified_at = None
    if kind == "disabled": user.disabled_at = now()
    session.commit()
    r = login(phone, "unknown@example.com" if kind == "unknown" else user.email,
              "incorrect-private-password" if kind == "wrong" else PASSWORD)
    assert r.status_code == code, r.text
    assert r.json()["detail"]["code"] == reason
    assert PASSWORD not in r.text and PASSWORD not in caplog.text
    assert "verification_token" not in r.text
    assert not session.scalar(select(UserSession).where(UserSession.kind == "mobile"))


def test_password_login_token_expiry(phone, alice, accounts, session):
    token = login(phone).json()["token"]
    row = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    row.expires_at = now() - timedelta(seconds=1)
    session.commit()
    assert phone.get("/mobile/v1/me", headers=bearer(token)).status_code == 401


def test_wrong_password_does_not_disclose_disabled_account(phone, alice, accounts, session):
    accounts["alice"].disabled_at = now()
    session.commit()
    assert login(phone, password="wrong").json()["detail"]["code"] == "invalid_credentials"


def test_login_rate_limit_and_validation_redaction(phone, alice, accounts):
    for _ in range(5): assert login(phone, password="wrong").status_code == 401
    assert login(phone).status_code == 429
    r = phone.post("/mobile/v1/login", json={"email":"alice@example.com", "password":"private" * 100})
    assert r.status_code == 422 and "private" not in r.text
