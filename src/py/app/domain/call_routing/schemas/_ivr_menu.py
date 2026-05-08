"""IVR menu schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

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

    digit: Annotated[str, Meta(min_length=1, max_length=10)]
    label: Annotated[str, Meta(min_length=1, max_length=100)]
    destination: Annotated[str, Meta(min_length=1, max_length=255)]
    sort_order: Annotated[int, Meta(ge=0)] = 0


class IvrMenuOptionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an IVR menu option."""

    digit: Annotated[str, Meta(min_length=1, max_length=10)] | msgspec.UnsetType = msgspec.UNSET
    label: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType = msgspec.UNSET
    destination: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    sort_order: Annotated[int, Meta(ge=0)] | msgspec.UnsetType = msgspec.UNSET


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
    created_at: datetime | None = None
    updated_at: datetime | None = None


class IvrMenuCreate(CamelizedBaseStruct):
    """Schema for creating an IVR menu."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    greeting_type: Annotated[str, Meta(min_length=1, max_length=50)] = "none"
    greeting_text: Annotated[str, Meta(max_length=2000)] | None = None
    greeting_file_url: Annotated[str, Meta(max_length=500)] | None = None
    timeout_seconds: Annotated[int, Meta(ge=1, le=120)] = 5
    max_retries: Annotated[int, Meta(ge=0, le=10)] = 3
    timeout_destination: Annotated[str, Meta(max_length=255)] | None = None
    invalid_destination: Annotated[str, Meta(max_length=255)] | None = None


class IvrMenuUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an IVR menu."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    greeting_type: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    greeting_text: Annotated[str, Meta(max_length=2000)] | msgspec.UnsetType | None = msgspec.UNSET
    greeting_file_url: Annotated[str, Meta(max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    timeout_seconds: Annotated[int, Meta(ge=1, le=120)] | msgspec.UnsetType = msgspec.UNSET
    max_retries: Annotated[int, Meta(ge=0, le=10)] | msgspec.UnsetType = msgspec.UNSET
    timeout_destination: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    invalid_destination: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
