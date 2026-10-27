"""Store canonical domains for community website reports.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("site_domain", sa.String(253), nullable=True))
    op.add_column("reports", sa.Column("category", sa.String(40), nullable=True))
    op.create_index("ix_reports_site_domain", "reports", ["site_domain"])
    op.create_index("uq_reports_user_site_domain", "reports", ["user_id", "site_domain"],
                    unique=True, postgresql_where=sa.text("user_id IS NOT NULL AND site_domain IS NOT NULL"))


def downgrade() -> None:
    op.drop_index("uq_reports_user_site_domain", table_name="reports")
    op.drop_index("ix_reports_site_domain", table_name="reports")
    op.drop_column("reports", "category")
    op.drop_column("reports", "site_domain")
