"""Schedule entry model."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._schedule import Schedule


class ScheduleEntry(UUIDv7AuditBase):
    """A single time-window entry within a schedule."""

    __tablename__ = "schedule_entry"
    __table_args__ = {"comment": "Individual time entries within a schedule"}

    schedule_id: Mapped[UUID] = mapped_column(
        ForeignKey("schedule.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    day_of_week: Mapped[int | None] = mapped_column(nullable=True, default=None)
    start_time: Mapped[datetime.time] = mapped_column(nullable=False)
    end_time: Mapped[datetime.time] = mapped_column(nullable=False)
    date: Mapped[datetime.date | None] = mapped_column(nullable=True, default=None)
    label: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    is_closed: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    schedule: Mapped[Schedule] = relationship(
        back_populates="entries",
        foreign_keys="ScheduleEntry.schedule_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
