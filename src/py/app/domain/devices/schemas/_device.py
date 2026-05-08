"""Device schemas."""

import datetime as dt
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class DeviceLineAssignment(CamelizedBaseStruct):
    """Line assignment representation."""

    id: UUID
    line_number: int
    label: str
    line_type: str
    extension_id: UUID | None = None
    extension_number: str | None = None
    extension_display_name: str | None = None
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
    location_id: UUID | None = None
    location_name: str | None = None
    connection_id: UUID | None = None
    connection_name: str | None = None
    mac_address: str | None = None
    device_model: str | None = None
    manufacturer: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None
    is_active: bool = True
    last_seen_at: dt.datetime | None = None
    provisioned_at: dt.datetime | None = None
    lines: list[DeviceLineAssignment] = []
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class DeviceCreate(CamelizedBaseStruct):
    """Schema for creating a device."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    device_type: Annotated[str, Meta(min_length=1, max_length=100)]
    mac_address: Annotated[str, Meta(min_length=1, max_length=17)] | None = None
    device_model: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    manufacturer: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    sip_username: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    team_id: UUID | None = None
    location_id: UUID | None = None
    connection_id: UUID | None = None


class DeviceUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a device."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    mac_address: Annotated[str, Meta(min_length=1, max_length=17)] | msgspec.UnsetType | None = msgspec.UNSET
    device_model: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    manufacturer: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    firmware_version: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType | None = msgspec.UNSET
    ip_address: Annotated[str, Meta(min_length=1, max_length=45)] | msgspec.UnsetType | None = msgspec.UNSET
    config_json: dict | msgspec.UnsetType | None = msgspec.UNSET
    location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    connection_id: UUID | msgspec.UnsetType | None = msgspec.UNSET


class DeviceActionResponse(CamelizedBaseStruct):
    """Response from a device management action."""

    device_id: UUID
    action: str
    status: str
    message: str


class DeviceLineAssignmentInput(CamelizedBaseStruct):
    """Input for a single device line assignment."""

    line_number: Annotated[int, Meta(ge=1)]
    label: Annotated[str, Meta(min_length=1, max_length=50)]
    extension_id: UUID | None = None
    line_type: Annotated[str, Meta(min_length=1, max_length=100)] = "private"
    is_active: bool = True


class SetDeviceLinesRequest(CamelizedBaseStruct):
    """Request to set all line assignments on a device."""

    lines: list[DeviceLineAssignmentInput]
