"""Cached public-domain evidence and encrypted Gemini credentials."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, JSON, SmallInteger, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class DomainEvidenceCache(Base):
    __tablename__ = "domain_evidence_cache"

    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    organization_claim: Mapped[str | None] = mapped_column(String(200))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    error_code: Mapped[str | None] = mapped_column(String(40))


class DomainVerificationCredential(Base):
    __tablename__ = "domain_verification_credentials"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    encrypted_api_key: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (CheckConstraint("id = 1", name="singleton_id"),)
