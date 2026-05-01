from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._call_routing_enums import QueueStrategy

if TYPE_CHECKING:
    from app.db.models._call_queue_member import CallQueueMember
    from app.db.models._team import Team


class CallQueue(UUIDv7AuditBase):
    """A call queue that distributes incoming calls to members."""

    __tablename__ = "call_queue"
    __table_args__ = {"comment": "Call queues for distributing incoming calls"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    number: Mapped[str] = mapped_column(String(length=20), nullable=False, index=True)
    strategy: Mapped[QueueStrategy] = mapped_column(
        String(length=50),
        default=QueueStrategy.RING_ALL,
        nullable=False,
    )
    ring_time: Mapped[int] = mapped_column(default=15, nullable=False)
    max_wait_time: Mapped[int] = mapped_column(default=300, nullable=False)
    max_callers: Mapped[int] = mapped_column(default=10, nullable=False)
    join_empty: Mapped[bool] = mapped_column(default=False, nullable=False)
    leave_when_empty: Mapped[bool] = mapped_column(default=True, nullable=False)
    music_on_hold_class: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    announce_frequency: Mapped[int | None] = mapped_column(nullable=True, default=None)
    announce_holdtime: Mapped[bool] = mapped_column(default=False, nullable=False)
    timeout_destination: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    wrapup_time: Mapped[int] = mapped_column(default=0, nullable=False)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="CallQueue.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    members: Mapped[list[CallQueueMember]] = relationship(
        back_populates="call_queue",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
        order_by="CallQueueMember.priority",
    )
