"""Schedule model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._schedule_enums import ScheduleType

if TYPE_CHECKING:
    from app.db.models._schedule_entry import ScheduleEntry
    from app.db.models._team import Team


class Schedule(UUIDv7AuditBase):
    """A named schedule (business hours, holiday, or custom) owned by a team."""

    __tablename__ = "schedule"
    __table_args__ = {"comment": "Schedules for teams (business hours, holidays, custom)"}

    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    timezone: Mapped[str] = mapped_column(String(length=100), default="America/Chicago", nullable=False)
    is_default: Mapped[bool] = mapped_column(default=False, nullable=False)
    schedule_type: Mapped[ScheduleType] = mapped_column(
        String(length=20),
        default=ScheduleType.BUSINESS_HOURS,
        nullable=False,
        index=True,
    )
    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="Schedule.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    entries: Mapped[list[ScheduleEntry]] = relationship(
        back_populates="schedule",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
    )
