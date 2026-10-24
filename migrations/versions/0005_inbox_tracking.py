"""inbox tracking

Additive only: every new column is nullable and no existing row is changed.
Rows from before this migration keep ingest_status NULL, so they are never
counted as unread and their legacy sender/subject columns are never displayed.
- ingest_status / status_reason: whether the envelope recipient was attributed
  to an owned signup ("matched"), could not be ("unmatched", with a reason), or
  was attributed but the leak analysis failed ("failed").
- sender_name: display name from the From header (untrusted).
- auth_results: compact SPF/DKIM/DMARC verdicts from Cloudflare's header.
- read_at: inbox read state; a partial index serves the unread count.
The check constraints are written by hand: autogenerate does not detect them.
Downgrade drops the new columns (read state is lost); other data is untouched.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-24 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('mail_log', sa.Column('ingest_status', sa.String(length=16), nullable=True))
    op.add_column('mail_log', sa.Column('status_reason', sa.String(length=32), nullable=True))
    op.add_column('mail_log', sa.Column('sender_name', sa.String(length=200), nullable=True))
    op.add_column('mail_log', sa.Column('auth_results', sa.String(length=100), nullable=True))
    op.add_column('mail_log', sa.Column('read_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        'ix_mail_log_user_id_unread', 'mail_log', ['user_id'], unique=False,
        postgresql_where=sa.text('read_at IS NULL AND ingest_status IS NOT NULL'),
    )
    op.create_check_constraint(
        op.f('ck_mail_log_ingest_status_allowed'), 'mail_log',
        "ingest_status IS NULL OR ingest_status IN ('matched', 'unmatched', 'failed')",
    )
    op.create_check_constraint(
        op.f('ck_mail_log_status_reason_allowed'), 'mail_log',
        "status_reason IS NULL OR status_reason IN "
        "('unknown_alias', 'unowned_alias', 'ambiguous_alias', 'analysis_failed')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(op.f('ck_mail_log_status_reason_allowed'), 'mail_log', type_='check')
    op.drop_constraint(op.f('ck_mail_log_ingest_status_allowed'), 'mail_log', type_='check')
    op.drop_index('ix_mail_log_user_id_unread', table_name='mail_log',
                  postgresql_where=sa.text('read_at IS NULL AND ingest_status IS NOT NULL'))
    op.drop_column('mail_log', 'read_at')
    op.drop_column('mail_log', 'auth_results')
    op.drop_column('mail_log', 'sender_name')
    op.drop_column('mail_log', 'status_reason')
    op.drop_column('mail_log', 'ingest_status')
