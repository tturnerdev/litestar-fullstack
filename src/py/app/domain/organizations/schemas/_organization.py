"""Organization schemas."""

from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class Organization(CamelizedBaseStruct):
    """Schema for organization detail response."""

    id: UUID
    name: str
    slug: str
    description: str | None = None
    logo_url: str | None = None
    website: str | None = None
    email: str | None = None
    phone: str | None = None
    address_line_1: str | None = None
    address_line_2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    timezone: str | None = None
    default_language: str | None = None
    settings: dict | None = None


class OrganizationDetail(CamelizedBaseStruct):
    """Detailed organization response (same as Organization for this domain)."""

    id: UUID
    name: str
    slug: str
    description: str | None = None
    logo_url: str | None = None
    website: str | None = None
    email: str | None = None
    phone: str | None = None
    address_line_1: str | None = None
    address_line_2: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    timezone: str | None = None
    default_language: str | None = None
    settings: dict | None = None


class OrganizationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating organization settings."""

    name: str | msgspec.UnsetType | None = msgspec.UNSET
    description: str | msgspec.UnsetType | None = msgspec.UNSET
    logo_url: str | msgspec.UnsetType | None = msgspec.UNSET
    website: str | msgspec.UnsetType | None = msgspec.UNSET
    email: str | msgspec.UnsetType | None = msgspec.UNSET
    phone: str | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: str | msgspec.UnsetType | None = msgspec.UNSET
    address_line_2: str | msgspec.UnsetType | None = msgspec.UNSET
    city: str | msgspec.UnsetType | None = msgspec.UNSET
    state: str | msgspec.UnsetType | None = msgspec.UNSET
    postal_code: str | msgspec.UnsetType | None = msgspec.UNSET
    country: str | msgspec.UnsetType | None = msgspec.UNSET
    timezone: str | msgspec.UnsetType | None = msgspec.UNSET
    default_language: str | msgspec.UnsetType | None = msgspec.UNSET
    settings: dict | msgspec.UnsetType | None = msgspec.UNSET
