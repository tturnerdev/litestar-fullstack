"""Device schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class DeviceLineAssignment(CamelizedBaseStruct):
    """Line assignment representation."""

    id: UUID
    line_number: int
    label: str
    line_type: str
    extension_id: UUID | None = None
    is_active: bool = True


class Device(CamelizedBaseStruct):
    """Full device representation."""

    id: UUID
    user_id: UUID
    name: str
    device_type: str
    sip_username: str
    sip_server: str
    status: str
    team_id: UUID | None = None
    mac_address: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None
    is_active: bool = True
    last_seen_at: datetime | None = None
    provisioned_at: datetime | None = None
    lines: list[DeviceLineAssignment] = []


class DeviceCreate(CamelizedBaseStruct):
    """Schema for creating a device."""

    name: str
    device_type: str
    mac_address: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    sip_username: str | None = None
    team_id: UUID | None = None


class DeviceUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a device."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    mac_address: str | msgspec.UnsetType | None = msgspec.UNSET
    model: str | msgspec.UnsetType | None = msgspec.UNSET
    manufacturer: str | msgspec.UnsetType | None = msgspec.UNSET
    firmware_version: str | msgspec.UnsetType | None = msgspec.UNSET
    ip_address: str | msgspec.UnsetType | None = msgspec.UNSET
    config_json: dict | msgspec.UnsetType | None = msgspec.UNSET
