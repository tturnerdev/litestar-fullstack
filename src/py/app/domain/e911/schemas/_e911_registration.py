"""E911 Registration schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class E911Registration(CamelizedBaseStruct, kw_only=True):
    id: UUID
    team_id: UUID
    address_line_1: str
    city: str
    state: str
    postal_code: str
    country: str = "US"
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_2: str | None = None
    validated: bool = False
    validated_at: datetime | None = None
    carrier_registration_id: str | None = None
    phone_number_display: str | None = None
    phone_number_label: str | None = None
    location_name: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class E911RegistrationCreate(CamelizedBaseStruct, kw_only=True):
    team_id: UUID
    address_line_1: Annotated[str, Meta(min_length=1, max_length=255)]
    city: Annotated[str, Meta(min_length=1, max_length=255)]
    state: Annotated[str, Meta(min_length=1, max_length=255)]
    postal_code: Annotated[str, Meta(min_length=1, max_length=20)]
    country: Annotated[str, Meta(min_length=2, max_length=2)] = "US"
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_2: Annotated[str, Meta(max_length=255)] | None = None


class E911RegistrationUpdate(CamelizedBaseStruct, omit_defaults=True):
    phone_number_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    address_line_2: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    city: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    state: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    postal_code: Annotated[str, Meta(min_length=1, max_length=20)] | msgspec.UnsetType = msgspec.UNSET
    country: Annotated[str, Meta(min_length=2, max_length=2)] | msgspec.UnsetType = msgspec.UNSET


class UnregisteredPhoneNumber(CamelizedBaseStruct, kw_only=True):
    id: UUID
    number: str
    number_type: str
    user_id: UUID
    label: str | None = None
    team_id: UUID | None = None
