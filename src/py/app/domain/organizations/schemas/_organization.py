"""Organization schemas."""

import datetime as dt
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

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
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


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
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class OrganizationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating organization settings."""

    name: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    description: Annotated[str, Meta(max_length=1000)] | msgspec.UnsetType | None = msgspec.UNSET
    logo_url: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    website: Annotated[str, Meta(max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    email: Annotated[str, Meta(max_length=320)] | msgspec.UnsetType | None = msgspec.UNSET
    phone: Annotated[str, Meta(max_length=20)] | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    address_line_2: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    city: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    state: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    postal_code: Annotated[str, Meta(max_length=20)] | msgspec.UnsetType | None = msgspec.UNSET
    country: Annotated[str, Meta(max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    timezone: Annotated[str, Meta(max_length=50)] | msgspec.UnsetType | None = msgspec.UNSET
    default_language: Annotated[str, Meta(max_length=10)] | msgspec.UnsetType | None = msgspec.UNSET
    settings: dict | msgspec.UnsetType | None = msgspec.UNSET
