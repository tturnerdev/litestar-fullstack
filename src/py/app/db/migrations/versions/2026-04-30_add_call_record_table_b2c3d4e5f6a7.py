"""add call record table

Revision ID: b2c3d4e5f6a7
Revises: aa1b2c3d4e5f
Create Date: 2026-04-30 20:00:00.000000

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
revision = "b2c3d4e5f6a7"
down_revision = "aa1b2c3d4e5f"
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
        "call_record",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("team_id", sa.GUID(length=16), nullable=False),
        sa.Column("call_date", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("caller_id", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("destination", sa.String(length=100), nullable=False),
        sa.Column("duration", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("billable_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("direction", sa.String(length=20), nullable=False),
        sa.Column("disposition", sa.String(length=20), nullable=False),
        sa.Column("channel", sa.String(length=100), nullable=True),
        sa.Column("unique_id", sa.String(length=255), nullable=True),
        sa.Column("recording_url", sa.String(length=500), nullable=True),
        sa.Column("cost", sa.Numeric(precision=10, scale=4), nullable=True),
        sa.Column("connection_id", sa.GUID(length=16), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_call_record")),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"], name=op.f("fk_call_record_team_id_team"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connection_id"], ["connection.id"], name=op.f("fk_call_record_connection_id_connection"), ondelete="SET NULL"),
        comment="Call detail records for analytics",
    )
    op.create_index(op.f("ix_call_record_team_id"), "call_record", ["team_id"])
    op.create_index(op.f("ix_call_record_call_date"), "call_record", ["call_date"])
    op.create_index(op.f("ix_call_record_direction"), "call_record", ["direction"])
    op.create_index(op.f("ix_call_record_disposition"), "call_record", ["disposition"])
    op.create_index(op.f("ix_call_record_connection_id"), "call_record", ["connection_id"])


def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    op.drop_index(op.f("ix_call_record_connection_id"), table_name="call_record")
    op.drop_index(op.f("ix_call_record_disposition"), table_name="call_record")
    op.drop_index(op.f("ix_call_record_direction"), table_name="call_record")
    op.drop_index(op.f("ix_call_record_call_date"), table_name="call_record")
    op.drop_index(op.f("ix_call_record_team_id"), table_name="call_record")
    op.drop_table("call_record")


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
