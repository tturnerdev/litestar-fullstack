"""Location schemas."""

from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class LocationChild(CamelizedBaseStruct):
    """Minimal child location representation (used within parent detail)."""

    id: UUID
    name: str
    description: str | None = None


class Location(CamelizedBaseStruct):
    """Full location representation."""

    id: UUID
    name: str
    location_type: str
    team_id: UUID
    description: str | None = None
    parent_id: UUID | None = None
    address_line_1: str | None = None
    address_line_2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    children: list[LocationChild] = []
    device_count: int = 0


class LocationCreate(CamelizedBaseStruct):
    """Schema for creating a location."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    location_type: Annotated[str, Meta(min_length=1, max_length=20)]
    team_id: UUID
    description: Annotated[str, Meta(max_length=500)] | None = None
    parent_id: UUID | None = None
    address_line_1: Annotated[str, Meta(max_length=255)] | None = None
    address_line_2: Annotated[str, Meta(max_length=255)] | None = None
    city: Annotated[str, Meta(max_length=100)] | None = None
    state: Annotated[str, Meta(max_length=100)] | None = None
    postal_code: Annotated[str, Meta(max_length=20)] | None = None
    country: Annotated[str, Meta(max_length=100)] | None = None


class LocationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a location."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    description: Annotated[str, Meta(max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    address_line_2: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    city: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    state: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    postal_code: Annotated[str, Meta(max_length=20)] | msgspec.UnsetType | None = msgspec.UNSET
    country: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
