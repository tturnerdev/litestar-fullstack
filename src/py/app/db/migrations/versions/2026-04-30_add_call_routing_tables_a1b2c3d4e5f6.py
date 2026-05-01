"""add call routing tables

Revision ID: aa1b2c3d4e5f
Revises: 94e85cc5fbd3
Create Date: 2026-04-30 18:00:00.000000

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
revision = "aa1b2c3d4e5f"
down_revision = "94e85cc5fbd3"
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

    # --- time_condition ---
    op.create_table(
        "time_condition",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("team_id", sa.GUID(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("schedule_id", sa.GUID(length=16), nullable=True),
        sa.Column("match_destination", sa.String(length=255), nullable=False),
        sa.Column("no_match_destination", sa.String(length=255), nullable=False),
        sa.Column("override_mode", sa.String(length=50), nullable=False, server_default="none"),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_time_condition")),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"], name=op.f("fk_time_condition_team_id_team"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["schedule_id"], ["schedule.id"], name=op.f("fk_time_condition_schedule_id_schedule"), ondelete="SET NULL"),
        comment="Time-based call routing conditions",
    )
    op.create_index(op.f("ix_time_condition_team_id"), "time_condition", ["team_id"])
    op.create_index(op.f("ix_time_condition_name"), "time_condition", ["name"])
    op.create_index(op.f("ix_time_condition_schedule_id"), "time_condition", ["schedule_id"])

    # --- ivr_menu ---
    op.create_table(
        "ivr_menu",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("team_id", sa.GUID(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("greeting_type", sa.String(length=50), nullable=False, server_default="none"),
        sa.Column("greeting_text", sa.String(length=2000), nullable=True),
        sa.Column("greeting_file_url", sa.String(length=500), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("timeout_destination", sa.String(length=255), nullable=True),
        sa.Column("invalid_destination", sa.String(length=255), nullable=True),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ivr_menu")),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"], name=op.f("fk_ivr_menu_team_id_team"), ondelete="CASCADE"),
        comment="IVR auto-attendant menus",
    )
    op.create_index(op.f("ix_ivr_menu_team_id"), "ivr_menu", ["team_id"])
    op.create_index(op.f("ix_ivr_menu_name"), "ivr_menu", ["name"])

    # --- ivr_menu_option ---
    op.create_table(
        "ivr_menu_option",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("ivr_menu_id", sa.GUID(length=16), nullable=False),
        sa.Column("digit", sa.String(length=2), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("destination", sa.String(length=255), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ivr_menu_option")),
        sa.ForeignKeyConstraint(["ivr_menu_id"], ["ivr_menu.id"], name=op.f("fk_ivr_menu_option_ivr_menu_id_ivr_menu"), ondelete="CASCADE"),
        sa.UniqueConstraint("ivr_menu_id", "digit", name=op.f("uq_ivr_menu_option_ivr_menu_id")),
        comment="Key-press options for IVR menus",
    )
    op.create_index(op.f("ix_ivr_menu_option_ivr_menu_id"), "ivr_menu_option", ["ivr_menu_id"])

    # --- call_queue ---
    op.create_table(
        "call_queue",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("team_id", sa.GUID(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("number", sa.String(length=20), nullable=False),
        sa.Column("strategy", sa.String(length=50), nullable=False, server_default="ring_all"),
        sa.Column("ring_time", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("max_wait_time", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("max_callers", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("join_empty", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("leave_when_empty", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("music_on_hold_class", sa.String(length=100), nullable=True),
        sa.Column("announce_frequency", sa.Integer(), nullable=True),
        sa.Column("announce_holdtime", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("timeout_destination", sa.String(length=255), nullable=True),
        sa.Column("wrapup_time", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_call_queue")),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"], name=op.f("fk_call_queue_team_id_team"), ondelete="CASCADE"),
        comment="Call queues for distributing incoming calls",
    )
    op.create_index(op.f("ix_call_queue_team_id"), "call_queue", ["team_id"])
    op.create_index(op.f("ix_call_queue_name"), "call_queue", ["name"])
    op.create_index(op.f("ix_call_queue_number"), "call_queue", ["number"])

    # --- call_queue_member ---
    op.create_table(
        "call_queue_member",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("call_queue_id", sa.GUID(length=16), nullable=False),
        sa.Column("extension_id", sa.GUID(length=16), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("penalty", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_paused", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_call_queue_member")),
        sa.ForeignKeyConstraint(["call_queue_id"], ["call_queue.id"], name=op.f("fk_call_queue_member_call_queue_id_call_queue"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["extension_id"], ["extension.id"], name=op.f("fk_call_queue_member_extension_id_extension"), ondelete="SET NULL"),
        comment="Members assigned to call queues",
    )
    op.create_index(op.f("ix_call_queue_member_call_queue_id"), "call_queue_member", ["call_queue_id"])
    op.create_index(op.f("ix_call_queue_member_extension_id"), "call_queue_member", ["extension_id"])

    # --- ring_group ---
    op.create_table(
        "ring_group",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("team_id", sa.GUID(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("number", sa.String(length=20), nullable=False),
        sa.Column("strategy", sa.String(length=50), nullable=False, server_default="ring_all"),
        sa.Column("ring_time", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("no_answer_destination", sa.String(length=255), nullable=True),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ring_group")),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"], name=op.f("fk_ring_group_team_id_team"), ondelete="CASCADE"),
        comment="Ring groups for multi-extension ringing",
    )
    op.create_index(op.f("ix_ring_group_team_id"), "ring_group", ["team_id"])
    op.create_index(op.f("ix_ring_group_name"), "ring_group", ["name"])
    op.create_index(op.f("ix_ring_group_number"), "ring_group", ["number"])

    # --- ring_group_member ---
    op.create_table(
        "ring_group_member",
        sa.Column("id", sa.GUID(length=16), nullable=False),
        sa.Column("ring_group_id", sa.GUID(length=16), nullable=False),
        sa.Column("extension_id", sa.GUID(length=16), nullable=True),
        sa.Column("external_number", sa.String(length=20), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTimeUTC(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ring_group_member")),
        sa.ForeignKeyConstraint(["ring_group_id"], ["ring_group.id"], name=op.f("fk_ring_group_member_ring_group_id_ring_group"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["extension_id"], ["extension.id"], name=op.f("fk_ring_group_member_extension_id_extension"), ondelete="SET NULL"),
        comment="Members assigned to ring groups",
    )
    op.create_index(op.f("ix_ring_group_member_ring_group_id"), "ring_group_member", ["ring_group_id"])
    op.create_index(op.f("ix_ring_group_member_extension_id"), "ring_group_member", ["extension_id"])


def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    op.drop_index(op.f("ix_ring_group_member_extension_id"), table_name="ring_group_member")
    op.drop_index(op.f("ix_ring_group_member_ring_group_id"), table_name="ring_group_member")
    op.drop_table("ring_group_member")

    op.drop_index(op.f("ix_ring_group_number"), table_name="ring_group")
    op.drop_index(op.f("ix_ring_group_name"), table_name="ring_group")
    op.drop_index(op.f("ix_ring_group_team_id"), table_name="ring_group")
    op.drop_table("ring_group")

    op.drop_index(op.f("ix_call_queue_member_extension_id"), table_name="call_queue_member")
    op.drop_index(op.f("ix_call_queue_member_call_queue_id"), table_name="call_queue_member")
    op.drop_table("call_queue_member")

    op.drop_index(op.f("ix_call_queue_number"), table_name="call_queue")
    op.drop_index(op.f("ix_call_queue_name"), table_name="call_queue")
    op.drop_index(op.f("ix_call_queue_team_id"), table_name="call_queue")
    op.drop_table("call_queue")

    op.drop_index(op.f("ix_ivr_menu_option_ivr_menu_id"), table_name="ivr_menu_option")
    op.drop_table("ivr_menu_option")

    op.drop_index(op.f("ix_ivr_menu_name"), table_name="ivr_menu")
    op.drop_index(op.f("ix_ivr_menu_team_id"), table_name="ivr_menu")
    op.drop_table("ivr_menu")

    op.drop_index(op.f("ix_time_condition_schedule_id"), table_name="time_condition")
    op.drop_index(op.f("ix_time_condition_name"), table_name="time_condition")
    op.drop_index(op.f("ix_time_condition_team_id"), table_name="time_condition")
    op.drop_table("time_condition")


def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""


def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
