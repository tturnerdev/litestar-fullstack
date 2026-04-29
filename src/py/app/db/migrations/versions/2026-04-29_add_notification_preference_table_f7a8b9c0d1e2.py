"""add notification preference table

Revision ID: f7a8b9c0d1e2
Revises: a3b7c9d1e5f2
Create Date: 2026-04-29 12:00:00.000000

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import GUID, DateTimeUTC, ORA_JSONB
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from collections.abc import Sequence  # pyright: ignore

__all__ = ("downgrade", "upgrade", "schema_upgrades", "schema_downgrades", "data_upgrades", "data_downgrades")

sa.GUID = GUID  # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore
sa.ORA_JSONB = ORA_JSONB  # pyright: ignore

# revision identifiers, used by Alembic.
revision = "f7a8b9c0d1e2"
down_revision = "a3b7c9d1e5f2"
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
        "notification_preference",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column(
            "user_id",
            sa.GUID(length=16),
            sa.ForeignKey("user_account.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "categories",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text(
                """'{"teams": true, "devices": true, "voice": true, "fax": true, "support": true, "system": true}'::jsonb"""
            ),
        ),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_preference")),
        sa.UniqueConstraint("user_id", name=op.f("uq_notification_preference_user_id")),
        comment="User notification delivery preferences",
    )
    op.create_index(
        op.f("ix_notification_preference_user_id"),
        "notification_preference",
        ["user_id"],
        unique=True,
    )


def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    op.drop_index(op.f("ix_notification_preference_user_id"), table_name="notification_preference")
    op.drop_table("notification_preference")


def data_upgrades() -> None:
    """data upgrade migrations go here."""


def data_downgrades() -> None:
    """data downgrade migrations go here."""
