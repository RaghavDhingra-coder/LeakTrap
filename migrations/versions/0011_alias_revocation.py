"""Add persistent alias status for dashboard revocation and Worker enforcement.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    offline = op.get_context().as_sql
    inspector = None if offline else sa.inspect(bind)
    columns = set() if offline else {column["name"] for column in inspector.get_columns("signups")}
    if "alias_status" not in columns:
        op.add_column("signups", sa.Column("alias_status", sa.String(16), nullable=True))
    if "alias_status_changed_at" not in columns:
        op.add_column("signups", sa.Column("alias_status_changed_at", sa.DateTime(timezone=True), nullable=True))

    # Existing signup rows remain active unless already marked revoked.
    op.execute(sa.text("UPDATE signups SET alias_status = 'active' WHERE alias_status IS NULL"))
    op.execute(sa.text("UPDATE signups SET alias_status_changed_at = COALESCE(updated_at, created_at, now()) "
                       "WHERE alias_status_changed_at IS NULL"))
    op.alter_column("signups", "alias_status", nullable=False, server_default="active")
    op.alter_column("signups", "alias_status_changed_at", nullable=False, server_default=sa.func.now())

    checks = set() if offline else {constraint["name"] for constraint in inspector.get_check_constraints("signups")}
    if "ck_signups_alias_status_allowed" not in checks:
        op.create_check_constraint("ck_signups_alias_status_allowed", "signups",
                                   "alias_status IN ('active', 'revoked')")
    indexes = set() if offline else {index["name"] for index in inspector.get_indexes("signups")}
    if "ix_signups_alias_status" not in indexes:
        op.create_index("ix_signups_alias_status", "signups", ["alias_status"])


def downgrade() -> None:
    # The preceding shared-database reconciliation revision notes that an
    # earlier deployment may already own alias_status columns. Do not remove
    # state that may predate this revision when rolling back.
    pass
