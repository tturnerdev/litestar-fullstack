"""IVR menu schemas."""

from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class IvrMenuOption(CamelizedBaseStruct):
    """IVR menu option representation."""

    id: UUID
    ivr_menu_id: UUID
    digit: str
    label: str
    destination: str
    sort_order: int = 0


class IvrMenuOptionCreate(CamelizedBaseStruct):
    """Schema for creating an IVR menu option."""

    digit: str
    label: str
    destination: str
    sort_order: int = 0


class IvrMenuOptionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an IVR menu option."""

    digit: str | msgspec.UnsetType = msgspec.UNSET
    label: str | msgspec.UnsetType = msgspec.UNSET
    destination: str | msgspec.UnsetType = msgspec.UNSET
    sort_order: int | msgspec.UnsetType = msgspec.UNSET


class IvrMenu(CamelizedBaseStruct):
    """Full IVR menu representation."""

    id: UUID
    team_id: UUID
    name: str
    greeting_type: str
    timeout_seconds: int
    max_retries: int
    greeting_text: str | None = None
    greeting_file_url: str | None = None
    timeout_destination: str | None = None
    invalid_destination: str | None = None
    options: list[IvrMenuOption] = []


class IvrMenuCreate(CamelizedBaseStruct):
    """Schema for creating an IVR menu."""

    name: str
    greeting_type: str = "none"
    greeting_text: str | None = None
    greeting_file_url: str | None = None
    timeout_seconds: int = 5
    max_retries: int = 3
    timeout_destination: str | None = None
    invalid_destination: str | None = None


class IvrMenuUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an IVR menu."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    greeting_type: str | msgspec.UnsetType = msgspec.UNSET
    greeting_text: str | msgspec.UnsetType | None = msgspec.UNSET
    greeting_file_url: str | msgspec.UnsetType | None = msgspec.UNSET
    timeout_seconds: int | msgspec.UnsetType = msgspec.UNSET
    max_retries: int | msgspec.UnsetType = msgspec.UNSET
    timeout_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    invalid_destination: str | msgspec.UnsetType | None = msgspec.UNSET
