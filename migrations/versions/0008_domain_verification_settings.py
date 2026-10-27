"""Add public-domain evidence cache and encrypted Gemini key settings.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-27
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
        "domain_evidence_cache",
        sa.Column("domain", sa.String(253), primary_key=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("organization_claim", sa.String(200), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(40), nullable=True),
    )
    op.create_index("ix_domain_evidence_cache_expires_at", "domain_evidence_cache", ["expires_at"])
    op.create_table(
        "domain_verification_credentials",
        sa.Column("id", sa.SmallInteger(), primary_key=True),
        sa.Column("encrypted_api_key", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_by", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint("id = 1", name=op.f("ck_domain_verification_credentials_singleton_id")),
    )


def downgrade() -> None:
    op.drop_table("domain_verification_credentials")
    op.drop_index("ix_domain_evidence_cache_expires_at", table_name="domain_evidence_cache")
    op.drop_table("domain_evidence_cache")
