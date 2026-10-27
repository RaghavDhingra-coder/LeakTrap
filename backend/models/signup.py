"""A website signup and the identity variants used for it."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, false, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base
from backend.models.mixins import IdMixin, TimestampMixin

if TYPE_CHECKING:
    from backend.models.consent_receipt import ConsentReceipt
    from backend.models.mail_log import MailLog
    from backend.models.user import User


class Signup(IdMixin, TimestampMixin, Base):
    __tablename__ = "signups"

    # RESTRICT: deleting a user must be handled explicitly, never by silently
    # removing or orphaning their records.
    user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    site_name: Mapped[str] = mapped_column(String(255), nullable=False)
    site_domain: Mapped[str | None] = mapped_column(String(253), index=True)
    alias_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active", server_default="active", index=True
    )
    alias_status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    block_promotional_emails: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # Full email address (local part and domain), up to the RFC 5321 limit.
    alias: Mapped[str | None] = mapped_column(String(320))
    nickname: Mapped[str | None] = mapped_column(String(100))
    surname_variant: Mapped[str | None] = mapped_column(String(100))
    real_name_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    real_name_used: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )

    user: Mapped["User | None"] = relationship()
    consent_receipts: Mapped[list["ConsentReceipt"]] = relationship(
        back_populates="signup", passive_deletes=True
    )
    mail_logs: Mapped[list["MailLog"]] = relationship(back_populates="signup", passive_deletes=True)

    __table_args__ = (
        CheckConstraint("alias_status IN ('active', 'revoked')", name="alias_status_allowed"),
        # An email address routes to exactly one mailbox, so a full address
        # (case-insensitive) may belong to only one signup. Different users on a
        # shared domain simply use different local parts.
        Index(
            "uq_signups_alias_lower",
            func.lower(alias),
            unique=True,
            postgresql_where=alias.is_not(None),
        ),
        # A nickname is a marker only if it is unique within its owner's
        # signups. NULLS NOT DISTINCT makes rows without a user share one scope
        # (requires PostgreSQL 15+).
        Index(
            "uq_signups_user_id_nickname_lower",
            user_id,
            func.lower(nickname),
            unique=True,
            postgresql_where=nickname.is_not(None),
            postgresql_nulls_not_distinct=True,
        ),
        # Non-unique lookup so later phases can detect the same nickname being
        # used across different owners.
        Index("ix_signups_nickname_lower", func.lower(nickname)),
    )
