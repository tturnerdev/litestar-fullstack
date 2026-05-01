"""Device template model for wireframe and provisioning configuration."""

from __future__ import annotations

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models._device_type import DeviceType


class DeviceTemplate(UUIDv7AuditBase):
    """A device template storing wireframe layout and provisioning configuration."""

    __tablename__ = "device_template"
    __table_args__ = (
        UniqueConstraint("manufacturer", "model", name="uq_device_template_manufacturer_model"),
        {"comment": "Device templates with wireframe layouts and provisioning configs"},
    )

    manufacturer: Mapped[str] = mapped_column(String(length=100), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(length=100), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(length=255), nullable=False)
    device_type: Mapped[DeviceType] = mapped_column(
        String(length=50),
        default=DeviceType.DESK_PHONE,
        nullable=False,
        index=True,
    )
    wireframe_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    provisioning_template: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    template_variables: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
    image_url: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
