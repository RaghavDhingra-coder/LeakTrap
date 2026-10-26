"""Minimal, user-confirmed community observations about an exact hostname."""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.mixins import IdMixin

CATEGORIES = ("personal_marker_match", "suspicious_message_link")
STATUSES = ("unverified", "verified", "rejected")


class WebsiteReport(IdMixin, Base):
    __tablename__ = "website_reports"

    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    reporter_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="unverified")

    __table_args__ = (
        UniqueConstraint("reporter_user_id", "domain", "category", name="uq_website_reports_reporter_domain_category"),
        CheckConstraint("category IN ('personal_marker_match', 'suspicious_message_link')", name="category_allowed"),
        CheckConstraint("verification_status IN ('unverified', 'verified', 'rejected')", name="verification_status_allowed"),
        Index("ix_website_reports_domain_category_status", "domain", "category", "verification_status"),
    )
