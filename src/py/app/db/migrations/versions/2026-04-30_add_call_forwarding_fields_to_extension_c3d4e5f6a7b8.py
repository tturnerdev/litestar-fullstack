"""add call forwarding fields to extension

Revision ID: d4e5f6a7b8c9
Revises: b2c3d4e5f6a7
Create Date: 2026-04-30 22:00:00.000000

"""

import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import GUID, DateTimeUTC, EncryptedString, EncryptedText, ORA_JSONB, PasswordHash, StoredObject
from sqlalchemy import Text  # pyright: ignore  # noqa: F401

if TYPE_CHECKING:
    from collections.abc import Sequence  # pyright: ignore

__all__ = ("downgrade", "upgrade", "schema_upgrades", "schema_downgrades", "data_upgrades", "data_downgrades")

sa.GUID = GUID  # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore
sa.ORA_JSONB = ORA_JSONB  # pyright: ignore
sa.EncryptedString = EncryptedString  # pyright: ignore
sa.EncryptedText = EncryptedText  # pyright: ignore
sa.StoredObject = StoredObject  # pyright: ignore
sa.PasswordHash = PasswordHash  # pyright: ignore

# revision identifiers, used by Alembic.
revision = "d4e5f6a7b8c9"
down_revision = "b2c3d4e5f6a7"
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
    op.add_column("extension", sa.Column("forward_always_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("extension", sa.Column("forward_always_destination", sa.String(length=100), nullable=True))
    op.add_column("extension", sa.Column("forward_busy_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("extension", sa.Column("forward_busy_destination", sa.String(length=100), nullable=True))
    op.add_column("extension", sa.Column("forward_no_answer_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("extension", sa.Column("forward_no_answer_destination", sa.String(length=100), nullable=True))
    op.add_column("extension", sa.Column("forward_no_answer_ring_count", sa.Integer(), nullable=False, server_default=sa.text("4")))
    op.add_column("extension", sa.Column("forward_unreachable_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("extension", sa.Column("forward_unreachable_destination", sa.String(length=100), nullable=True))
    op.add_column("extension", sa.Column("dnd_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))


def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    op.drop_column("extension", "dnd_enabled")
    op.drop_column("extension", "forward_unreachable_destination")
    op.drop_column("extension", "forward_unreachable_enabled")
    op.drop_column("extension", "forward_no_answer_ring_count")
    op.drop_column("extension", "forward_no_answer_destination")
    op.drop_column("extension", "forward_no_answer_enabled")
    op.drop_column("extension", "forward_busy_destination")
    op.drop_column("extension", "forward_busy_enabled")
    op.drop_column("extension", "forward_always_destination")
    op.drop_column("extension", "forward_always_enabled")


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
