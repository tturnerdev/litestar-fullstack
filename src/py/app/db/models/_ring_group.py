from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._call_routing_enums import RingGroupStrategy

if TYPE_CHECKING:
    from app.db.models._ring_group_member import RingGroupMember
    from app.db.models._team import Team


class RingGroup(UUIDv7AuditBase):
    """A ring group that rings multiple extensions simultaneously or sequentially."""

    __tablename__ = "ring_group"
    __table_args__ = {"comment": "Ring groups for multi-extension ringing"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    number: Mapped[str] = mapped_column(String(length=20), nullable=False, index=True)
    strategy: Mapped[RingGroupStrategy] = mapped_column(
        String(length=50),
        default=RingGroupStrategy.RING_ALL,
        nullable=False,
    )
    ring_time: Mapped[int] = mapped_column(default=20, nullable=False)
    no_answer_destination: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="RingGroup.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    members: Mapped[list[RingGroupMember]] = relationship(
        back_populates="ring_group",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
        order_by="RingGroupMember.sort_order",
    )
