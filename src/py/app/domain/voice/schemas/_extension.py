"""Extension schemas."""

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
