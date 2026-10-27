"""Persist deterministic sender attribution snapshots.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("mail_log", sa.Column("sender_attribution", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("mail_log", "sender_attribution")
