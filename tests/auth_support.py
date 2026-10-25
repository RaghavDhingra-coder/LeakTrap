"""Helpers for authenticated tests.

Integration tests create real accounts and sessions (Argon2 hashing, hashed
tokens) through the auth service. Unit tests that never touch a database
replace the authentication dependency with a fixed context instead.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.models import User
from backend.security import EXTENSION_SCOPES, SESSION_COOKIE, get_auth_context
from backend.services import auth as auth_service
from backend.services.auth import AuthContext

PASSWORD = "correct horse battery staple"
ORIGIN = "http://testserver"
FAKE_CSRF = "unit-test-csrf-token"
FAKE_HEADERS = {"X-CSRF-Token": FAKE_CSRF, "Origin": ORIGIN}


def make_account(session: Session, email: str, password: str = PASSWORD, verified: bool = True) -> User:
    user = User(email=email.lower(), password_hash=auth_service._hasher.hash(password))
    if verified:
        user.email_verified_at = auth_service.now()
    session.add(user)
    session.commit()
    return user


def sign_in(client: TestClient, session: Session, user: User) -> str:
    """Give `client` a real web session for `user`; returns the CSRF token."""
    created = auth_service.create_session(session, user.id, "web", label="Web")
    session.commit()
    client.cookies.set(SESSION_COOKIE, created.token)
    client.headers.update({"X-CSRF-Token": created.csrf_token, "Origin": ORIGIN})
    return created.csrf_token


def extension_token(session: Session, user: User, scopes=EXTENSION_SCOPES, hours: int = 8) -> str:
    from datetime import timedelta

    created = auth_service.create_session(session, user.id, "extension", " ".join(sorted(scopes)),
                                          label="Chrome extension", lifetime=timedelta(hours=hours))
    session.commit()
    return created.token


def mobile_token(session: Session, user: User, scopes=("account:read",), days: int = 30) -> str:
    from datetime import timedelta

    created = auth_service.create_session(session, user.id, "mobile", " ".join(sorted(scopes)),
                                          label="Test phone", lifetime=timedelta(days=days))
    session.commit()
    return created.token


def fake_auth(app: FastAPI, user_id: int = 1, kind: str = "web", scopes=EXTENSION_SCOPES) -> None:
    """Unit tests only: act as a signed-in user without a database."""
    context = AuthContext(user_id=user_id, session_id=1, kind=kind, scopes=frozenset(scopes),
                          csrf_token=FAKE_CSRF if kind == "web" else None, email="user@example.com")
    app.dependency_overrides[get_auth_context] = lambda: context
