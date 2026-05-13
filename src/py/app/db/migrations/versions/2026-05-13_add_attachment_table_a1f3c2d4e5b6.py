"""add attachment table

Revision ID: a1f3c2d4e5b6
Revises: dc54b25d8b6c
Create Date: 2026-05-13 00:00:00.000000

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
revision = "a1f3c2d4e5b6"
down_revision = "dc54b25d8b6c"
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
    op.create_table(
        "attachment",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("uploaded_by_id", sa.GUID(length=16), nullable=True),
        sa.Column("team_id", sa.GUID(length=16), nullable=True),
        sa.Column("file", sa.StoredObject(backend="uploads"), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"],
            ["user_account.id"],
            name=op.f("fk_attachment_uploaded_by_id_user_account"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
            name=op.f("fk_attachment_team_id_team"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attachment")),
        comment="User-uploaded files stored in object storage",
    )
    with op.batch_alter_table("attachment", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_attachment_purpose"), ["purpose"], unique=False)
        batch_op.create_index(batch_op.f("ix_attachment_team_id"), ["team_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_attachment_uploaded_by_id"), ["uploaded_by_id"], unique=False)


def schema_downgrades() -> None:
    """Schema downgrade migrations go here."""
    with op.batch_alter_table("attachment", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_attachment_uploaded_by_id"))
        batch_op.drop_index(batch_op.f("ix_attachment_team_id"))
        batch_op.drop_index(batch_op.f("ix_attachment_purpose"))

    op.drop_table("attachment")


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
