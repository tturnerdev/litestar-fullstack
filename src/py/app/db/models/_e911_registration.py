"""E911 Registration model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.types import DateTimeUTC
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._location import Location
    from app.db.models._phone_number import PhoneNumber
    from app.db.models._team import Team


class E911Registration(UUIDv7AuditBase):
    """An E911 address registration linked to a phone number."""

    __tablename__ = "e911_registration"
    __table_args__ = (
        UniqueConstraint("phone_number_id", name="uq_e911_registration_phone_number_id"),
        {"comment": "E911 address registrations for phone numbers"},
    )

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    phone_number_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("phone_number.id", ondelete="set null"),
        nullable=True,
        default=None,
    )
    location_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("location.id", ondelete="set null"),
        nullable=True,
        default=None,
    )
    address_line_1: Mapped[str] = mapped_column(String(length=255), nullable=False)
    address_line_2: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    city: Mapped[str] = mapped_column(String(length=100), nullable=False)
    state: Mapped[str] = mapped_column(String(length=100), nullable=False)
    postal_code: Mapped[str] = mapped_column(String(length=20), nullable=False)
    country: Mapped[str] = mapped_column(String(length=100), nullable=False, default="US")
    validated: Mapped[bool] = mapped_column(default=False, nullable=False)
    validated_at: Mapped[datetime | None] = mapped_column(DateTimeUTC(timezone=True), nullable=True, default=None)
    carrier_registration_id: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="E911Registration.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    phone_number: Mapped[PhoneNumber | None] = relationship(
        foreign_keys="E911Registration.phone_number_id",
        uselist=False,
        lazy="joined",
    )
    location: Mapped[Location | None] = relationship(
        foreign_keys="E911Registration.location_id",
        uselist=False,
        lazy="joined",
    )
