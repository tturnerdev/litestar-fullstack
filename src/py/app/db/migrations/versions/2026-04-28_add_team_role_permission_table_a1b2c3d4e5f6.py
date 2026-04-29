"""add team role permission table

Revision ID: a1b2c3d4e5f6
Revises: b747f9fa6f87
Create Date: 2026-04-28 12:00:00.000000

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import EncryptedString, EncryptedText, GUID, ORA_JSONB, DateTimeUTC, StoredObject, PasswordHash
from sqlalchemy import Text  # pyright: ignore  # noqa: F401

if TYPE_CHECKING:
    from collections.abc import Sequence  # pyright: ignore

__all__ = ("downgrade", "upgrade", "schema_upgrades", "schema_downgrades", "data_upgrades", "data_downgrades")

sa.GUID = GUID # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore
sa.ORA_JSONB = ORA_JSONB  # pyright: ignore
sa.EncryptedString = EncryptedString  # pyright: ignore
sa.EncryptedText = EncryptedText  # pyright: ignore
sa.StoredObject = StoredObject  # pyright: ignore
sa.PasswordHash = PasswordHash  # pyright: ignore

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'b747f9fa6f87'
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
    op.create_table('team_role_permission',
    sa.Column('id', sa.GUID(length=16), nullable=False),
    sa.Column('team_id', sa.GUID(length=16), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.Column('feature_area', sa.String(length=50), nullable=False),
    sa.Column('can_view', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    sa.Column('can_edit', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    sa.Column('sa_orm_sentinel', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTimeUTC(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTimeUTC(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], name=op.f('fk_team_role_permission_team_id_team'), ondelete='cascade'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_team_role_permission')),
    sa.UniqueConstraint('team_id', 'role', 'feature_area', name=op.f('uq_team_role_permission_team_id_role_feature_area')),
    )
    with op.batch_alter_table('team_role_permission', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_team_role_permission_team_id'), ['team_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_team_role_permission_role'), ['role'], unique=False)
        batch_op.create_index(batch_op.f('ix_team_role_permission_feature_area'), ['feature_area'], unique=False)

def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    with op.batch_alter_table('team_role_permission', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_team_role_permission_feature_area'))
        batch_op.drop_index(batch_op.f('ix_team_role_permission_role'))
        batch_op.drop_index(batch_op.f('ix_team_role_permission_team_id'))

    op.drop_table('team_role_permission')

def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""

def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
