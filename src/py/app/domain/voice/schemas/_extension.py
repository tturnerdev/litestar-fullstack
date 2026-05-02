"""Extension schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class Extension(CamelizedBaseStruct):
    """Extension response."""

    id: UUID
    user_id: UUID
    extension_number: str
    phone_number_id: UUID | None = None
    display_name: str = ""
    is_active: bool = True
    forward_always_enabled: bool = False
    forward_always_destination: str | None = None
    forward_busy_enabled: bool = False
    forward_busy_destination: str | None = None
    forward_no_answer_enabled: bool = False
    forward_no_answer_destination: str | None = None
    forward_no_answer_ring_count: int = 4
    forward_unreachable_enabled: bool = False
    forward_unreachable_destination: str | None = None
    dnd_enabled: bool = False
    e911_status: str = "unknown"
    e911_registration_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ExtensionCreate(CamelizedBaseStruct):
    """Extension create properties."""

    extension_number: str
    display_name: str = ""
    phone_number_id: UUID | None = None
    is_active: bool = True


class ExtensionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Extension update properties."""

    display_name: str | msgspec.UnsetType = msgspec.UNSET
    phone_number_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    forward_always_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    forward_always_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    forward_busy_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    forward_busy_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    forward_no_answer_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    forward_no_answer_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    forward_no_answer_ring_count: int | msgspec.UnsetType = msgspec.UNSET
    forward_unreachable_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    forward_unreachable_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    dnd_enabled: bool | msgspec.UnsetType = msgspec.UNSET


class ExtensionDeviceSummary(CamelizedBaseStruct):
    """Summary of a device assigned to an extension via a line assignment."""

    device_id: UUID
    device_name: str
    device_type: str
    status: str
    line_number: int
    line_label: str
    line_id: UUID
    device_model: str | None = None


class ExtensionSyncResult(CamelizedBaseStruct):
    """Result of a PBX extension sync operation."""

    created: int = 0
    updated: int = 0
    errors: list[str] = []
    connection_name: str | None = None
