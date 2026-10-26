"""Add exact-domain community reports, separate from legacy private reports.

Revision ID: 0007
Revises: 0006
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "website_reports",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("reporter_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("verification_status", sa.String(16), server_default="unverified", nullable=False),
        sa.UniqueConstraint("reporter_user_id", "domain", "category", name="uq_website_reports_reporter_domain_category"),
        sa.CheckConstraint("category IN ('personal_marker_match', 'suspicious_message_link')", name="ck_website_reports_category_allowed"),
        sa.CheckConstraint("verification_status IN ('unverified', 'verified', 'rejected')", name="ck_website_reports_verification_status_allowed"),
    )
    op.create_index("ix_website_reports_domain_category_status", "website_reports", ["domain", "category", "verification_status"])


def downgrade() -> None:
    op.drop_index("ix_website_reports_domain_category_status", table_name="website_reports")
    op.drop_table("website_reports")
