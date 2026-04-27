from __future__ import annotations

from datetime import time
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._voice_enums import DndMode

if TYPE_CHECKING:
    from app.db.models._extension import Extension


class DoNotDisturb(UUIDv7AuditBase):
    """DND schedule and settings."""

    __tablename__ = "do_not_disturb"
    __table_args__ = {"comment": "Do Not Disturb settings per extension"}

    extension_id: Mapped[UUID] = mapped_column(
        ForeignKey("extension.id", ondelete="cascade"), nullable=False, unique=True
    )
    is_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    mode: Mapped[DndMode] = mapped_column(
        String(length=20),
        default=DndMode.OFF,
        nullable=False,
    )
    schedule_start: Mapped[time | None] = mapped_column(nullable=True, default=None)
    schedule_end: Mapped[time | None] = mapped_column(nullable=True, default=None)
    schedule_days: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True, default=None)
    allow_list: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True, default=None)

    extension: Mapped[Extension] = relationship(
        back_populates="do_not_disturb",
        foreign_keys="DoNotDisturb.extension_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
