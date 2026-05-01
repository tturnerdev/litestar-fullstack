"""Add E911 registration table.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-30 18:00:00.000000

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import GUID, DateTimeUTC

if TYPE_CHECKING:
    from collections.abc import Sequence  # pyright: ignore

__all__ = ("downgrade", "upgrade", "schema_upgrades", "schema_downgrades", "data_upgrades", "data_downgrades")

sa.GUID = GUID  # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore

# revision identifiers, used by Alembic.
revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        with op.get_context().autocommit_block():
            schema_upgrades()
            data_upgrades()


def downgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        with op.get_context().autocommit_block():
            data_downgrades()
            schema_downgrades()


def schema_upgrades() -> None:
    """schema upgrade migrations go here."""
    op.create_table(
        'e911_registration',
        sa.Column('id', sa.GUID(length=16), nullable=False),
        sa.Column('team_id', sa.GUID(length=16), nullable=False),
        sa.Column('phone_number_id', sa.GUID(length=16), nullable=True),
        sa.Column('location_id', sa.GUID(length=16), nullable=True),
        sa.Column('address_line_1', sa.String(length=255), nullable=False),
        sa.Column('address_line_2', sa.String(length=255), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=False),
        sa.Column('state', sa.String(length=100), nullable=False),
        sa.Column('postal_code', sa.String(length=20), nullable=False),
        sa.Column('country', sa.String(length=100), nullable=False, server_default='US'),
        sa.Column('validated', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('validated_at', sa.DateTimeUTC(timezone=True), nullable=True),
        sa.Column('carrier_registration_id', sa.String(length=255), nullable=True),
        sa.Column('sa_orm_sentinel', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTimeUTC(timezone=True), nullable=False, server_default=sa.text('(now() at time zone \'utc\')')),
        sa.Column('updated_at', sa.DateTimeUTC(timezone=True), nullable=False, server_default=sa.text('(now() at time zone \'utc\')')),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], name=op.f('fk_e911_registration_team_id_team'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['phone_number_id'], ['phone_number.id'], name=op.f('fk_e911_registration_phone_number_id_phone_number'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['location_id'], ['location.id'], name=op.f('fk_e911_registration_location_id_location'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_e911_registration')),
        sa.UniqueConstraint('phone_number_id', name=op.f('uq_e911_registration_phone_number_id')),
        comment='E911 address registrations for phone numbers',
    )
    op.create_index(op.f('ix_e911_registration_team_id'), 'e911_registration', ['team_id'], unique=False)


def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    op.drop_index(op.f('ix_e911_registration_team_id'), table_name='e911_registration')
    op.drop_table('e911_registration')


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
