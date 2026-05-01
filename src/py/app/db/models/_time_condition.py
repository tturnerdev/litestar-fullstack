from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._call_routing_enums import OverrideMode

if TYPE_CHECKING:
    from app.db.models._schedule import Schedule
    from app.db.models._team import Team


class TimeCondition(UUIDv7AuditBase):
    """A time-based routing condition that directs calls based on schedule."""

    __tablename__ = "time_condition"
    __table_args__ = {"comment": "Time-based call routing conditions"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    schedule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("schedule.id", ondelete="set null"),
        nullable=True,
        default=None,
        index=True,
    )
    match_destination: Mapped[str] = mapped_column(String(length=255), nullable=False)
    no_match_destination: Mapped[str] = mapped_column(String(length=255), nullable=False)
    override_mode: Mapped[OverrideMode] = mapped_column(
        String(length=50),
        default=OverrideMode.NONE,
        nullable=False,
    )

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="TimeCondition.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    schedule: Mapped[Schedule | None] = relationship(
        foreign_keys="TimeCondition.schedule_id",
        uselist=False,
        lazy="joined",
    )
