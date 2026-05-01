from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._extension import Extension
    from app.db.models._ring_group import RingGroup


class RingGroupMember(UUIDv7AuditBase):
    """A member (extension or external number) in a ring group."""

    __tablename__ = "ring_group_member"
    __table_args__ = {"comment": "Members assigned to ring groups"}

    ring_group_id: Mapped[UUID] = mapped_column(
        ForeignKey("ring_group.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    extension_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("extension.id", ondelete="set null"),
        nullable=True,
        default=None,
        index=True,
    )
    external_number: Mapped[str | None] = mapped_column(String(length=20), nullable=True, default=None)
    sort_order: Mapped[int] = mapped_column(default=0, nullable=False)

    # Relationships
    ring_group: Mapped[RingGroup] = relationship(
        back_populates="members",
        foreign_keys="RingGroupMember.ring_group_id",
        innerjoin=True,
        uselist=False,
    )
    extension: Mapped[Extension | None] = relationship(
        foreign_keys="RingGroupMember.extension_id",
        uselist=False,
        lazy="joined",
    )
