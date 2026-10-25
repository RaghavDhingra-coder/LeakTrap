"""mobile device tokens

Additive only: no existing row is changed or deleted.
- user_sessions: "mobile" joins the allowed session kinds (web, extension).
- extension_pairings: client_kind ("extension" or "mobile"; existing rows and
  any insert that omits it are "extension") and device_label, the name a
  mobile device gives itself, shown to the user before approval.
The check constraints are written by hand: autogenerate does not detect them.
Downgrade deletes mobile sessions and mobile pairings first (every paired
mobile device is signed out), then restores the previous constraint and drops
the new columns; web and extension data is untouched.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-24 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0006'
down_revision: Union[str, Sequence[str], None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint(op.f('ck_user_sessions_kind_allowed'), 'user_sessions', type_='check')
    op.create_check_constraint(
        op.f('ck_user_sessions_kind_allowed'), 'user_sessions', "kind IN ('web', 'extension', 'mobile')"
    )
    op.add_column('extension_pairings', sa.Column('client_kind', sa.String(length=16), server_default='extension',
                                                  nullable=False))
    op.add_column('extension_pairings', sa.Column('device_label', sa.String(length=100), nullable=True))
    op.create_check_constraint(
        op.f('ck_extension_pairings_client_kind_allowed'), 'extension_pairings',
        "client_kind IN ('extension', 'mobile')"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM user_sessions WHERE kind = 'mobile'")
    op.execute("DELETE FROM extension_pairings WHERE client_kind = 'mobile'")
    op.drop_constraint(op.f('ck_extension_pairings_client_kind_allowed'), 'extension_pairings', type_='check')
    op.drop_column('extension_pairings', 'device_label')
    op.drop_column('extension_pairings', 'client_kind')
    op.drop_constraint(op.f('ck_user_sessions_kind_allowed'), 'user_sessions', type_='check')
    op.create_check_constraint(
        op.f('ck_user_sessions_kind_allowed'), 'user_sessions', "kind IN ('web', 'extension')"
    )
