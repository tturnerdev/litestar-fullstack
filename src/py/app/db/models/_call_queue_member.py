from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._call_queue import CallQueue
    from app.db.models._extension import Extension


class CallQueueMember(UUIDv7AuditBase):
    """A member (agent) assigned to a call queue."""

    __tablename__ = "call_queue_member"
    __table_args__ = {"comment": "Members assigned to call queues"}

    call_queue_id: Mapped[UUID] = mapped_column(
        ForeignKey("call_queue.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    extension_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("extension.id", ondelete="set null"),
        nullable=True,
        default=None,
        index=True,
    )
    priority: Mapped[int] = mapped_column(default=0, nullable=False)
    penalty: Mapped[int] = mapped_column(default=0, nullable=False)
    is_paused: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    call_queue: Mapped[CallQueue] = relationship(
        back_populates="members",
        foreign_keys="CallQueueMember.call_queue_id",
        innerjoin=True,
        uselist=False,
    )
    extension: Mapped[Extension | None] = relationship(
        foreign_keys="CallQueueMember.extension_id",
        uselist=False,
        lazy="joined",
    )
