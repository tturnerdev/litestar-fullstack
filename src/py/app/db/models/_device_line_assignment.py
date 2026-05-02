from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._device_line_type import DeviceLineType

if TYPE_CHECKING:
    from app.db.models._device import Device
    from app.db.models._extension import Extension


class DeviceLineAssignment(UUIDv7AuditBase):
    """Maps extensions/lines to device line keys."""

    __tablename__ = "device_line_assignment"
    __table_args__ = (
        UniqueConstraint("device_id", "line_number"),
        {"comment": "Line key assignments for devices"},
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("device.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    line_number: Mapped[int] = mapped_column(nullable=False)
    extension_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("extension.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    label: Mapped[str] = mapped_column(String(length=50), nullable=False)
    line_type: Mapped[DeviceLineType] = mapped_column(
        String(length=50),
        default=DeviceLineType.PRIVATE,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    device: Mapped[Device] = relationship(
        back_populates="lines",
        foreign_keys="DeviceLineAssignment.device_id",
        innerjoin=True,
        uselist=False,
    )
    extension: Mapped[Extension | None] = relationship(
        foreign_keys="DeviceLineAssignment.extension_id",
        uselist=False,
        lazy="joined",
    )
