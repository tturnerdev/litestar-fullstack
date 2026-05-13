"""add avatar and team logo attachment links

Revision ID: b2e4d6f8a0c1
Revises: a1f3c2d4e5b6
Create Date: 2026-05-13 00:30:00.000000

"""

import warnings

import sqlalchemy as sa
from advanced_alchemy.types import (
    GUID,
    ORA_JSONB,
    DateTimeUTC,
    EncryptedString,
    EncryptedText,
    PasswordHash,
    StoredObject,
)
from alembic import op
from sqlalchemy import Text  # pyright: ignore  # noqa: F401
from sqlalchemy.dialects import postgresql  # noqa: F401

__all__ = ("data_downgrades", "data_upgrades", "downgrade", "schema_downgrades", "schema_upgrades", "upgrade")

sa.GUID = GUID  # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore
sa.ORA_JSONB = ORA_JSONB  # pyright: ignore
sa.EncryptedString = EncryptedString  # pyright: ignore
sa.EncryptedText = EncryptedText  # pyright: ignore
sa.StoredObject = StoredObject  # pyright: ignore
sa.PasswordHash = PasswordHash  # pyright: ignore

# revision identifiers, used by Alembic.
revision = "b2e4d6f8a0c1"
down_revision = "a1f3c2d4e5b6"
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
    """Schema upgrade migrations go here."""
    with op.batch_alter_table("user_account", schema=None) as batch_op:
        batch_op.add_column(sa.Column("avatar_id", sa.GUID(length=16), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f("fk_user_account_avatar_id_attachment"),
            "attachment",
            ["avatar_id"],
            ["id"],
            ondelete="SET NULL",
        )
    with op.batch_alter_table("team", schema=None) as batch_op:
        batch_op.add_column(sa.Column("logo_url", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("logo_id", sa.GUID(length=16), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f("fk_team_logo_id_attachment"),
            "attachment",
            ["logo_id"],
            ["id"],
            ondelete="SET NULL",
        )


def schema_downgrades() -> None:
    """Schema downgrade migrations go here."""
    with op.batch_alter_table("team", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_team_logo_id_attachment"), type_="foreignkey")
        batch_op.drop_column("logo_id")
        batch_op.drop_column("logo_url")
    with op.batch_alter_table("user_account", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("fk_user_account_avatar_id_attachment"), type_="foreignkey")
        batch_op.drop_column("avatar_id")


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
