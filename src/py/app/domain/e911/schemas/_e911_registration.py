"""E911 Registration schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

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
    address_line_1: str
    city: str
    state: str
    postal_code: str
    country: str = "US"
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_2: str | None = None


class E911RegistrationUpdate(CamelizedBaseStruct, omit_defaults=True):
    phone_number_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: str | msgspec.UnsetType = msgspec.UNSET
    address_line_2: str | msgspec.UnsetType | None = msgspec.UNSET
    city: str | msgspec.UnsetType = msgspec.UNSET
    state: str | msgspec.UnsetType = msgspec.UNSET
    postal_code: str | msgspec.UnsetType = msgspec.UNSET
    country: str | msgspec.UnsetType = msgspec.UNSET


class UnregisteredPhoneNumber(CamelizedBaseStruct, kw_only=True):
    id: UUID
    number: str
    number_type: str
    user_id: UUID
    label: str | None = None
    team_id: UUID | None = None
