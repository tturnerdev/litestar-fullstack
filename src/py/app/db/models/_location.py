"""Location model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._location_type import LocationType

if TYPE_CHECKING:
    from app.db.models._team import Team


class Location(UUIDv7AuditBase):
    """A physical or addressed location that can be associated with devices, extensions, etc."""

    __tablename__ = "location"
    __table_args__ = {"comment": "Physical and addressed locations for teams"}

    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    location_type: Mapped[LocationType] = mapped_column(
        String(length=20),
        default=LocationType.ADDRESSED,
        nullable=False,
        index=True,
    )
    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    parent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("location.id", ondelete="cascade"),
        nullable=True,
        default=None,
        index=True,
    )

    # Address fields (populated for ADDRESSED type only)
    address_line_1: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    address_line_2: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    city: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    state: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    postal_code: Mapped[str | None] = mapped_column(String(length=20), nullable=True, default=None)
    country: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="Location.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    parent: Mapped[Location | None] = relationship(
        remote_side="Location.id",
        foreign_keys="Location.parent_id",
        uselist=False,
        lazy="joined",
    )
    children: Mapped[list[Location]] = relationship(
        foreign_keys="Location.parent_id",
        back_populates="parent",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
    )
