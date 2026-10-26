"""Reconcile the revision id already recorded in the shared Neon database.

Neon's alembic_version is 0010, but the migration file that wrote it was never
committed and cannot be recovered, so its original purpose is unknown. This
revision does not reproduce it. It exists only so Alembic can resolve 0010.

Verified against Neon's catalog before this file was added: every table,
column, index and constraint created by 0001-0009 is present there, with only
the primary/foreign key names on domain_evidence_cache and
domain_verification_credentials differing (same columns, same ON DELETE).
Neon also holds objects no migration here creates and no model maps:
website_reports, sender_domain_reviews, retired_aliases, sender_blocks,
signups.alias_status*, mail_log.delivery*, reports.mail_log_id/reason/signup_id.
They are deliberately left alone; never autogenerate a migration against Neon
without excluding them, or it will propose dropping them.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-27
"""
from typing import Sequence, Union

revision: str = "0010"
down_revision: Union[str, Sequence[str], None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
