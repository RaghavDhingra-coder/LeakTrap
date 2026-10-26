"""Per-signup user reviews of sender domains.

Revision ID: 0008
Revises: 0007
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008"
down_revision: Union[str, Sequence[str], None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sender_domain_reviews",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("signup_id", sa.BigInteger(), sa.ForeignKey("signups.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("review_status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("signup_id", "domain", name="uq_sender_domain_reviews_signup_domain"),
        sa.CheckConstraint("review_status IN ('expected', 'unexpected')", name="ck_sender_domain_reviews_sender_domain_review_status_allowed"),
    )
    op.create_index("ix_sender_domain_reviews_user_id", "sender_domain_reviews", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_sender_domain_reviews_user_id", table_name="sender_domain_reviews")
    op.drop_table("sender_domain_reviews")
