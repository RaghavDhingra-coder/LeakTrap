"""A user's review of a sender domain for one of their website aliases."""

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.mixins import CreatedAtMixin, IdMixin


class SenderDomainReview(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "sender_domain_reviews"

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    signup_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("signups.id", ondelete="RESTRICT"), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    review_status: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint("signup_id", "domain", name="uq_sender_domain_reviews_signup_domain"),
        CheckConstraint("review_status IN ('expected', 'unexpected')", name="sender_domain_review_status_allowed"),
    )
