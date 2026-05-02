"""Location schemas."""

from uuid import UUID

import msgspec

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


class LocationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a location."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    description: str | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: str | msgspec.UnsetType | None = msgspec.UNSET
    address_line_2: str | msgspec.UnsetType | None = msgspec.UNSET
    city: str | msgspec.UnsetType | None = msgspec.UNSET
    state: str | msgspec.UnsetType | None = msgspec.UNSET
    postal_code: str | msgspec.UnsetType | None = msgspec.UNSET
    country: str | msgspec.UnsetType | None = msgspec.UNSET
