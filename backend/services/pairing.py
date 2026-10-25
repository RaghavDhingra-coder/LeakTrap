"""Connecting a browser extension or a mobile device to an account.

1. The client creates a random secret and starts a pairing with only the
   secret's SHA-256 hash. It receives a short code (shown to the user) and a
   pairing id.
2. The signed-in user approves that code in the dashboard, stating which kind
   of client they are approving; a code of the other kind is never approved.
3. The client exchanges the pairing id plus the secret for a scoped token.
   Knowing the code alone is not enough.

Each pairing has a kind ("extension" or "mobile") that decides the session kind,
scopes, label and lifetime issued, and the routes that can start and exchange it.
Codes and tokens are stored only as hashes; each pairing is single-use.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import ExtensionPairing, User, UserSession
from backend.security import EXTENSION_SCOPES, MOBILE_GRANTED_SCOPES
from backend.services import auth as auth_service
from backend.services.auth import RateLimited, check_rate, now, record_event, token_hash

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
CODE_LENGTH = 8
PAIRING_MINUTES = 10
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MOBILE_LABEL = "Mobile device"
# Pairings are useless once expired; they are deleted a day later, a bounded batch at a time.
CLEANUP_AFTER = timedelta(days=1)
CLEANUP_BATCH = 100


class PairingNotFound(Exception):
    pass


class PairingExpired(Exception):
    pass


class PairingPending(Exception):
    pass


def normalize_code(code: str) -> str:
    return re.sub(r"[\s-]", "", str(code)).upper()


def format_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


@dataclass(frozen=True)
class StartedPairing:
    pairing_id: int
    code: str
    expires_at: datetime


def cleanup_expired(session: Session) -> int:
    """Delete up to CLEANUP_BATCH pairings that expired more than CLEANUP_AFTER ago, oldest
    first. Pending, approved and consumed pairings all stop working at expiry, and nothing
    references a pairing, so only this table is touched. Returns how many were deleted."""
    stale = (select(ExtensionPairing.id).where(ExtensionPairing.expires_at < now() - CLEANUP_AFTER)
             .order_by(ExtensionPairing.expires_at).limit(CLEANUP_BATCH))
    return session.execute(delete(ExtensionPairing).where(ExtensionPairing.id.in_(stale.scalar_subquery()))).rowcount


def _rate_kind(kind: str, step: str) -> str:
    return f"pairing_{step}_ip" if kind == "extension" else f"mobile_pairing_{step}_ip"


def start(session: Session, secret_hash: str, ip: str, kind: str = "extension",
          device_label: str | None = None) -> StartedPairing:
    if not _HEX64.match(secret_hash or ""):
        raise ValueError("secret_hash must be 64 lowercase hex characters")
    if kind == "extension" and device_label is not None:
        raise ValueError("only mobile pairings carry a device label")
    check_rate(session, _rate_kind(kind, "start"), ip)
    record_event(session, _rate_kind(kind, "start"), ip)
    cleanup_expired(session)
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    row = ExtensionPairing(code_hash=token_hash(code), secret_hash=secret_hash, client_kind=kind,
                           device_label=device_label, expires_at=now() + timedelta(minutes=PAIRING_MINUTES))
    session.add(row)
    session.commit()
    return StartedPairing(row.id, format_code(code), row.expires_at)


def _pending(session: Session, user_id: int, code: str, kind: str) -> ExtensionPairing:
    """The approvable pairing for a code, or PairingNotFound (counted as a failed attempt).

    A code of the other kind is treated exactly like an unknown code, so approving
    the extension can never connect a mobile device, or the other way round.
    """
    check_rate(session, "pairing_approve_failed_user", str(user_id))
    row = session.scalar(select(ExtensionPairing).where(ExtensionPairing.code_hash == token_hash(normalize_code(code))))
    if (row is None or row.client_kind != kind or row.expires_at <= now() or row.approved_at is not None
            or row.consumed_at is not None):
        record_event(session, "pairing_approve_failed_user", str(user_id))
        session.commit()
        raise PairingNotFound
    return row


def preview(session: Session, user_id: int, code: str, kind: str) -> ExtensionPairing:
    """Look up a pending pairing so the user can check it before approving. Changes nothing."""
    return _pending(session, user_id, code, kind)


def approve(session: Session, user_id: int, code: str, kind: str = "extension") -> ExtensionPairing:
    row = _pending(session, user_id, code, kind)
    row.user_id = user_id
    row.approved_at = now()
    session.commit()
    return row


@dataclass(frozen=True)
class IssuedToken:
    token: str
    expires_at: datetime
    email: str
    scopes: tuple[str, ...]


def _claim_exchange(session: Session, row: ExtensionPairing, kind: str, claimed_at: datetime) -> bool:
    """Atomically consume an approved pairing if it is still exchangeable."""
    result = session.execute(
        update(ExtensionPairing)
        .where(
            ExtensionPairing.id == row.id,
            ExtensionPairing.client_kind == kind,
            ExtensionPairing.secret_hash == row.secret_hash,
            ExtensionPairing.user_id == row.user_id,
            ExtensionPairing.approved_at.is_not(None),
            ExtensionPairing.consumed_at.is_(None),
            ExtensionPairing.expires_at > claimed_at,
        )
        .values(consumed_at=claimed_at)
    )
    return result.rowcount == 1


def exchange(session: Session, pairing_id: int, secret: str, ip: str, kind: str = "extension") -> IssuedToken:
    check_rate(session, _rate_kind(kind, "exchange"), ip)
    record_event(session, _rate_kind(kind, "exchange"), ip)
    session.commit()
    row = session.get(ExtensionPairing, pairing_id)
    given = hashlib.sha256(str(secret).encode()).hexdigest()
    # A pairing can only be exchanged on its own kind's route.
    if row is None or row.client_kind != kind or not hmac.compare_digest(given, row.secret_hash):
        raise PairingNotFound
    if row.consumed_at is not None or row.expires_at <= now():
        raise PairingExpired
    if row.approved_at is None or row.user_id is None:
        raise PairingPending
    if kind == "mobile":
        scopes = tuple(sorted(MOBILE_GRANTED_SCOPES))
        label = row.device_label or DEFAULT_MOBILE_LABEL
        lifetime = timedelta(days=settings.mobile_token_days)
    else:
        scopes = tuple(sorted(EXTENSION_SCOPES))
        label = "Browser extension"
        lifetime = timedelta(hours=settings.extension_token_hours)

    claimed_at = now()
    if not _claim_exchange(session, row, kind, claimed_at):
        # Another request consumed it, or it expired after it was read.
        raise PairingExpired
    created = auth_service.create_session(session, row.user_id, kind, " ".join(scopes), label=label, lifetime=lifetime)
    email = session.get(User, row.user_id).email
    session.commit()
    return IssuedToken(created.token, created.expires_at, email, scopes)


def active_sessions(session: Session, user_id: int, kind: str) -> list[UserSession]:
    query = (select(UserSession)
             .where(UserSession.user_id == user_id, UserSession.kind == kind,
                    UserSession.revoked_at.is_(None), UserSession.expires_at > now()))
    if kind == "mobile":  # idle mobile tokens no longer authenticate (see auth.authenticate)
        query = query.where(UserSession.last_used_at > now() - timedelta(days=settings.mobile_idle_days))
    return list(session.scalars(query.order_by(UserSession.created_at.desc())).all())


def revoke_session_of_kind(session: Session, user_id: int, session_id: int, kind: str) -> bool:
    row = session.get(UserSession, session_id)
    if row is None or row.user_id != user_id or row.kind != kind:
        return False
    return auth_service.revoke_session(session, session_id, user_id)


def active_extension_sessions(session: Session, user_id: int) -> list[UserSession]:
    return active_sessions(session, user_id, "extension")


def revoke_extension_session(session: Session, user_id: int, session_id: int) -> bool:
    return revoke_session_of_kind(session, user_id, session_id, "extension")


__all__ = ["RateLimited", "PairingNotFound", "PairingExpired", "PairingPending"]
