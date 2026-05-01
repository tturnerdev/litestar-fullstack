"""E911 Registration schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class E911Registration(CamelizedBaseStruct):
    """Full E911 registration representation."""

    id: UUID
    team_id: UUID
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_1: str
    address_line_2: str | None = None
    city: str
    state: str
    postal_code: str
    country: str = "US"
    validated: bool = False
    validated_at: datetime | None = None
    carrier_registration_id: str | None = None
    # Enriched from relationships
    phone_number_display: str | None = None
    phone_number_label: str | None = None
    location_name: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class E911RegistrationCreate(CamelizedBaseStruct):
    """Schema for creating an E911 registration."""

    team_id: UUID
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_1: str
    address_line_2: str | None = None
    city: str
    state: str
    postal_code: str
    country: str = "US"


class E911RegistrationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an E911 registration."""

    phone_number_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: str | msgspec.UnsetType = msgspec.UNSET
    address_line_2: str | msgspec.UnsetType | None = msgspec.UNSET
    city: str | msgspec.UnsetType = msgspec.UNSET
    state: str | msgspec.UnsetType = msgspec.UNSET
    postal_code: str | msgspec.UnsetType = msgspec.UNSET
    country: str | msgspec.UnsetType = msgspec.UNSET


class UnregisteredPhoneNumber(CamelizedBaseStruct):
    """Phone number that does not have an E911 registration."""

    id: UUID
    number: str
    label: str | None = None
    number_type: str
    user_id: UUID
    team_id: UUID | None = None
