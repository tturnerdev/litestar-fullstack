"""add music on hold table

Revision ID: d1e2f3a4b5c6
Revises: c6d7e8f9a0b1
Create Date: 2026-04-30 23:00:00.000000

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import GUID, DateTimeUTC, EncryptedString, EncryptedText, ORA_JSONB, PasswordHash, StoredObject
from sqlalchemy import Text  # pyright: ignore  # noqa: F401
from sqlalchemy.dialects import postgresql

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
revision = "d1e2f3a4b5c6"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        with op.get_context().autocommit_block():
            schema_upgrades()
            data_upgrades()


def downgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        with op.get_context().autocommit_block():
            data_downgrades()
            schema_downgrades()


def schema_upgrades() -> None:
    op.create_table(
        "music_on_hold",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("category", sa.String(50), nullable=False, server_default="custom"),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("random_order", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("file_list", postgresql.JSONB(astext_type=Text()), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_music_on_hold_name"),
        comment="Music on Hold classes with audio file lists and playback settings",
    )
    op.create_index(op.f("ix_music_on_hold_name"), "music_on_hold", ["name"])
    op.create_index(op.f("ix_music_on_hold_category"), "music_on_hold", ["category"])


def schema_downgrades() -> None:
    op.drop_index(op.f("ix_music_on_hold_category"), table_name="music_on_hold")
    op.drop_index(op.f("ix_music_on_hold_name"), table_name="music_on_hold")
    op.drop_table("music_on_hold")


def data_upgrades() -> None:
    pass


def data_downgrades() -> None:
    pass
