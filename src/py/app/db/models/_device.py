from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._device_status import DeviceStatus
from app.db.models._device_type import DeviceType

if TYPE_CHECKING:
    from app.db.models._device_line_assignment import DeviceLineAssignment
    from app.db.models._team import Team
    from app.db.models._user import User


class Device(UUIDv7AuditBase):
    """A physical or virtual device (desk phone, softphone, ATA, etc.)."""

    __tablename__ = "device"
    __table_args__ = {"comment": "Devices registered to user accounts"}

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("team.id", ondelete="set null"),
        nullable=True,
        default=None,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    device_type: Mapped[DeviceType] = mapped_column(
        String(length=50),
        default=DeviceType.OTHER,
        nullable=False,
        index=True,
    )
    mac_address: Mapped[str | None] = mapped_column(String(length=17), nullable=True, default=None)
    device_model: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    manufacturer: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    firmware_version: Mapped[str | None] = mapped_column(String(length=50), nullable=True, default=None)
    ip_address: Mapped[str | None] = mapped_column(String(length=45), nullable=True, default=None)
    sip_username: Mapped[str] = mapped_column(String(length=100), nullable=False)
    sip_server: Mapped[str] = mapped_column(String(length=255), nullable=False)
    status: Mapped[DeviceStatus] = mapped_column(
        String(length=50),
        default=DeviceStatus.OFFLINE,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    provisioned_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    config_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)

    # Relationships
    user: Mapped[User] = relationship(
        foreign_keys="Device.user_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    team: Mapped[Team | None] = relationship(
        foreign_keys="Device.team_id",
        uselist=False,
        lazy="joined",
    )
    lines: Mapped[list[DeviceLineAssignment]] = relationship(
        back_populates="device",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
    )
