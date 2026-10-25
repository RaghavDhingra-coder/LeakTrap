"""Sessions, extension pairing, email verification, rate limiting and the
ownership-claim audit trail (migration 0004).

Tokens and codes are stored only as SHA-256 hashes; the raw values are given
to the client once and never kept.
"""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.mixins import CreatedAtMixin, IdMixin

SESSION_KINDS = ("web", "extension", "mobile")
# Which kind of client a pairing connects; it decides the session kind and scopes issued.
PAIRING_KINDS = ("extension", "mobile")
CLAIMABLE_TABLES = ("signups", "consent_receipts", "mail_log", "incidents")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


class UserSession(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "user_sessions"

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # Space-separated; empty for web sessions (full access to the user's own data).
    scopes: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    label: Mapped[str | None] = mapped_column(String(100))
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_in("kind", SESSION_KINDS), name="kind_allowed"),
        Index("ix_user_sessions_user_id_kind", "user_id", "kind"),
    )


class ExtensionPairing(IdMixin, CreatedAtMixin, Base):
    """A pending connection between a browser extension or a mobile device and an account."""

    __tablename__ = "extension_pairings"

    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The extension keeps a secret; only its holder can exchange the approved pairing.
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Added in migration 0006. Existing pairings are extension pairings.
    client_kind: Mapped[str] = mapped_column(String(16), nullable=False, server_default="extension")
    # Name the device gave itself, shown to the user before approval (mobile only).
    device_label: Mapped[str | None] = mapped_column(String(100))

    __table_args__ = (CheckConstraint(_in("client_kind", PAIRING_KINDS), name="client_kind_allowed"),)


class EmailVerificationToken(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "email_verification_tokens"

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthEvent(IdMixin, CreatedAtMixin, Base):
    """Rate-limit and audit events. key_hash is a keyed hash of an IP or email."""

    __tablename__ = "auth_events"

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (Index("ix_auth_events_kind_key_hash_created_at", "kind", "key_hash", "created_at"),)


class OwnershipClaim(IdMixin, Base):
    """Audit trail for explicitly assigning a historical record to a user.

    Nothing in LeakTrace writes here automatically.
    """

    __tablename__ = "ownership_claims"

    table_name: Mapped[str] = mapped_column(String(32), nullable=False)
    record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    previous_user_id: Mapped[int | None] = mapped_column(BigInteger)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    note: Mapped[str | None] = mapped_column(Text)
    reversed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (CheckConstraint(_in("table_name", CLAIMABLE_TABLES), name="table_name_allowed"),)
