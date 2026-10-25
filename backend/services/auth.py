"""Accounts, sessions, rate limiting and email verification.

- Passwords: Argon2id via argon2-cffi (never stored or logged in plain text).
- Session tokens, pairing codes and verification tokens: random values given
  to the client once; only their SHA-256 hashes are stored.
- CSRF token: derived from the session token, so only a holder of the HttpOnly
  session cookie (i.e. the server, on the user's behalf) can produce it.
- Rate limiting: database-backed counts of keyed hashes of IPs and emails.
"""

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import (
    AuthEvent,
    ComplaintDraft,
    ConsentReceipt,
    EmailVerificationToken,
    Incident,
    LeakEdge,
    MailLog,
    OwnershipClaim,
    Report,
    Signup,
    User,
    UserSession,
)
from backend.services.domains import normalize_email

logger = logging.getLogger("leaktrace.auth")

MIN_PASSWORD = 12
MAX_PASSWORD = 256
VERIFICATION_HOURS = 24
LAST_USED_RESOLUTION = timedelta(minutes=1)

_hasher = PasswordHasher()  # Argon2id with argon2-cffi's maintained defaults
_dummy_hash = _hasher.hash(secrets.token_urlsafe(16))
_rate_key = (settings.secret_key or secrets.token_urlsafe(48)).encode()
if not settings.secret_key:
    logger.warning("LEAKTRACE_SECRET_KEY is not set; using a random per-process key for rate limiting")

# (limit, window) per event kind; see rate_limited().
LIMITS = {
    "login_failed_account": (5, timedelta(minutes=15)),
    "login_failed_ip": (20, timedelta(minutes=15)),
    "register_ip": (5, timedelta(hours=1)),
    "pairing_start_ip": (10, timedelta(hours=1)),
    "pairing_exchange_ip": (120, timedelta(hours=1)),
    "pairing_approve_failed_user": (10, timedelta(minutes=15)),
    "mobile_pairing_start_ip": (10, timedelta(hours=1)),
    "mobile_pairing_exchange_ip": (120, timedelta(hours=1)),
    "sms_analyze_user": (60, timedelta(hours=1)),
    "sms_write_user": (120, timedelta(hours=1)),
    "verify_failed_ip": (20, timedelta(hours=1)),
}


class AuthError(Exception):
    """Generic failure; the message is safe to show and reveals nothing about accounts."""


class RateLimited(Exception):
    pass


class PasswordPolicyError(ValueError):
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token_for(session_token: str) -> str:
    return hashlib.sha256(f"csrf:{session_token}".encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


# ---------- rate limiting ----------

def _key(kind: str, value: str) -> str:
    return hmac.new(_rate_key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def rate_limited(session: Session, kind: str, value: str) -> bool:
    limit, window = LIMITS[kind]
    count = session.scalar(
        select(func.count()).select_from(AuthEvent)
        .where(AuthEvent.kind == kind, AuthEvent.key_hash == _key(kind, value), AuthEvent.created_at > now() - window)
    )
    return (count or 0) >= limit


def record_event(session: Session, kind: str, value: str) -> None:
    session.add(AuthEvent(kind=kind, key_hash=_key(kind, value)))
    # Keep the table small: events older than the longest window are useless.
    session.execute(delete(AuthEvent).where(AuthEvent.created_at < now() - timedelta(days=2)))


def check_rate(session: Session, kind: str, value: str) -> None:
    if rate_limited(session, kind, value):
        raise RateLimited


def limit_user(session: Session, kind: str, user_id: int) -> None:
    """Count one request against a per-user limit. Raises RateLimited once it is used up;
    refused requests are not counted."""
    check_rate(session, kind, str(user_id))
    record_event(session, kind, str(user_id))
    session.commit()


# ---------- passwords and registration ----------

def check_password_policy(password: str, email: str | None = None) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise PasswordPolicyError(f"Use at least {MIN_PASSWORD} characters.")
    if len(password) > MAX_PASSWORD:
        raise PasswordPolicyError(f"Use at most {MAX_PASSWORD} characters.")
    if not password.strip():
        raise PasswordPolicyError("The password cannot be only spaces.")
    if email and password.strip().lower() == email.lower():
        raise PasswordPolicyError("The password cannot be your email address.")


@dataclass(frozen=True)
class Registration:
    created: bool
    verification_token: str | None  # for delivery only; never returned by the API


def register(session: Session, email: str, password: str, ip: str) -> Registration:
    """Create an account. The caller responds identically whether or not the
    email was already registered, so registration cannot be used to find accounts."""
    email = normalize_email(email)
    check_password_policy(password, email)
    check_rate(session, "register_ip", ip)
    record_event(session, "register_ip", ip)
    password_hash = _hasher.hash(password)  # hashed even for existing emails: same timing
    exists = session.scalar(select(User.id).where(func.lower(User.email) == email))
    if exists:
        session.commit()
        return Registration(False, None)
    user = User(email=email, password_hash=password_hash)
    session.add(user)
    try:
        session.flush()
    except IntegrityError:  # concurrent registration of the same email
        session.rollback()
        return Registration(False, None)
    token = issue_verification_token(session, user.id)
    session.commit()
    deliver_verification_email(email, token)
    return Registration(True, token)


# ---------- email verification (delivery not configured) ----------

def email_delivery_configured() -> bool:
    return False  # no provider is integrated yet, whatever LEAKTRACE_EMAIL_DELIVERY says


def deliver_verification_email(email: str, token: str) -> bool:
    """Returns whether an email was actually sent. Nothing is sent until a
    delivery provider is integrated; the token is never logged."""
    if not email_delivery_configured():
        logger.info("Verification email not sent: no email delivery provider is configured")
        return False
    return False


def issue_verification_token(session: Session, user_id: int) -> str:
    token = new_token()
    session.add(EmailVerificationToken(
        user_id=user_id, token_hash=token_hash(token), expires_at=now() + timedelta(hours=VERIFICATION_HOURS)
    ))
    return token


def verify_email(session: Session, token: str, ip: str) -> bool:
    check_rate(session, "verify_failed_ip", ip)
    row = session.scalar(select(EmailVerificationToken).where(EmailVerificationToken.token_hash == token_hash(token)))
    if row is None or row.used_at is not None or row.expires_at <= now():
        record_event(session, "verify_failed_ip", ip)
        session.commit()
        return False
    row.used_at = now()
    session.execute(update(User).where(User.id == row.user_id, User.email_verified_at.is_(None)).values(email_verified_at=now()))
    session.commit()
    return True


# ---------- login and sessions ----------

@dataclass(frozen=True)
class NewSession:
    token: str
    csrf_token: str
    session_id: int
    expires_at: datetime


def create_session(session: Session, user_id: int, kind: str = "web", scopes: str = "",
                   label: str | None = None, lifetime: timedelta | None = None) -> NewSession:
    token = new_token()
    lifetime = lifetime or timedelta(days=settings.session_max_days)
    row = UserSession(user_id=user_id, token_hash=token_hash(token), kind=kind, scopes=scopes,
                      label=label, expires_at=now() + lifetime)
    session.add(row)
    session.flush()
    return NewSession(token, csrf_token_for(token), row.id, row.expires_at)


def login(session: Session, email: str, password: str, ip: str) -> NewSession:
    """Raises AuthError (generic), RateLimited, or PermissionError for an
    unverified account (only after the correct password)."""
    try:
        email = normalize_email(email)
    except ValueError:
        email = str(email).strip().lower()[:320]
    check_rate(session, "login_failed_ip", ip)
    check_rate(session, "login_failed_account", email)
    user = session.scalar(select(User).where(func.lower(User.email) == email))
    try:
        _hasher.verify(user.password_hash if user and user.password_hash else _dummy_hash, password)
        ok = user is not None and user.password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False
    if not ok or user.disabled_at is not None:
        record_event(session, "login_failed_ip", ip)
        record_event(session, "login_failed_account", email)
        session.commit()
        raise AuthError("Incorrect email or password.")
    if user.email_verified_at is None and not settings.allow_unverified_login:
        session.commit()
        raise PermissionError("Verify your email address before signing in.")
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
    created = create_session(session, user.id, "web", label="Web")
    session.commit()
    return created


@dataclass(frozen=True)
class AuthContext:
    user_id: int
    session_id: int
    kind: str
    scopes: frozenset[str]
    csrf_token: str | None  # web sessions only
    email: str | None


def authenticate(session: Session, token: str) -> AuthContext | None:
    """The active session for a raw token, or None. Applies idle and absolute expiry."""
    if not token or len(token) > 200:
        return None
    row = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    current = now()
    if row is None or row.revoked_at is not None or row.expires_at <= current:
        return None
    if row.kind == "web" and row.last_used_at < current - timedelta(hours=settings.session_idle_hours):
        return None
    if row.kind == "mobile" and row.last_used_at < current - timedelta(days=settings.mobile_idle_days):
        return None
    user = session.get(User, row.user_id)
    if user is None or user.disabled_at is not None or user.email is None:
        return None
    if current - row.last_used_at > LAST_USED_RESOLUTION:
        row.last_used_at = current
        session.commit()
    return AuthContext(
        user_id=user.id, session_id=row.id, kind=row.kind, scopes=frozenset(row.scopes.split()),
        csrf_token=csrf_token_for(token) if row.kind == "web" else None, email=user.email,
    )


def revoke_session(session: Session, session_id: int, user_id: int) -> bool:
    result = session.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now())
    )
    session.commit()
    return result.rowcount == 1


def change_password(session: Session, user_id: int, current: str, new: str, keep_session_id: int) -> None:
    user = session.get(User, user_id)
    try:
        _hasher.verify(user.password_hash, current)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise AuthError("The current password is incorrect.") from None
    check_password_policy(new, user.email)
    user.password_hash = _hasher.hash(new)
    # Sign out everywhere else, including connected extensions.
    session.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.id != keep_session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now())
    )
    session.commit()


def delete_account(session: Session, user_id: int, password: str) -> None:
    """Delete the account and every record it owns, in one transaction."""
    user = session.get(User, user_id)
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise AuthError("The password is incorrect.") from None
    try:
        for model in (ComplaintDraft, Report, LeakEdge, Incident, ConsentReceipt, MailLog, Signup, OwnershipClaim):
            session.execute(delete(model).where(model.user_id == user_id))
        session.delete(user)  # sessions, pairings and verification tokens cascade
        session.commit()
    except Exception:
        session.rollback()
        raise
