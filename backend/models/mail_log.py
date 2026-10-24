"""Metadata about email received on a signup alias."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base
from backend.models.mixins import CreatedAtMixin, IdMixin

if TYPE_CHECKING:
    from backend.models.signup import Signup
    from backend.models.user import User

# Whether the recipient was attributed to an account's signup (added in 0005).
INGEST_STATUSES = ("matched", "unmatched", "failed")
STATUS_REASONS = ("unknown_alias", "unowned_alias", "ambiguous_alias", "analysis_failed")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IS NULL OR {column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


class MailLog(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "mail_log"

    user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="RESTRICT")
    )
    signup_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("signups.id", ondelete="SET NULL")
    )
    alias: Mapped[str | None] = mapped_column(String(320))
    sender: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(Text)
    is_spam: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Added in migration 0002 for email ingestion.
    # SHA-256 of the provider Message-ID (or of the message's key fields when it
    # has none). The unique index makes retried deliveries idempotent.
    message_id_hash: Mapped[str | None] = mapped_column(String(64))
    # Domain of the claimed sender. Stored instead of the full address; it is
    # a claim and may be forged.
    sender_domain: Mapped[str | None] = mapped_column(String(253), index=True)
    # Matcher outcome ("matched", "ambiguous", "no_match") and confidence.
    match_status: Mapped[str | None] = mapped_column(String(32))
    match_confidence: Mapped[str | None] = mapped_column(String(16))
    # Added in migration 0005 for the inbox. Rows from before it have
    # ingest_status NULL; they are never shown as unread and their sender and
    # subject columns are never displayed.
    # "matched": the envelope recipient is exactly one owned signup's alias.
    # "unmatched": it is not (status_reason says why); no account owns the row.
    # "failed": attributed, but the leak analysis raised; retried on redelivery.
    ingest_status: Mapped[str | None] = mapped_column(String(16))
    status_reason: Mapped[str | None] = mapped_column(String(32))
    # Display name from the From header. Untrusted, like sender and subject.
    sender_name: Mapped[str | None] = mapped_column(String(200))
    # Compact SPF/DKIM/DMARC verdicts from Cloudflare's ARC-Authentication-Results
    # header, e.g. "spf=pass dkim=pass dmarc=pass". Not verified by LeakTrace.
    auth_results: Mapped[str | None] = mapped_column(String(100))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User | None"] = relationship()
    signup: Mapped["Signup | None"] = relationship(back_populates="mail_logs")

    __table_args__ = (
        Index("ix_mail_log_received_at", received_at),
        Index("ix_mail_log_user_id_received_at", user_id, received_at),
        Index("ix_mail_log_signup_id_received_at", signup_id, received_at),
        Index("ix_mail_log_alias_lower", func.lower(alias)),
        Index("uq_mail_log_message_id_hash", message_id_hash, unique=True),
        Index("ix_mail_log_user_id_unread", user_id,
              postgresql_where=read_at.is_(None) & ingest_status.is_not(None)),
        CheckConstraint(_in("ingest_status", INGEST_STATUSES), name="ingest_status_allowed"),
        CheckConstraint(_in("status_reason", STATUS_REASONS), name="status_reason_allowed"),
    )
