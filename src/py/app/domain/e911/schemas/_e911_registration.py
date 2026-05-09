"""E911 Registration schemas."""

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class E911Registration(CamelizedBaseStruct, kw_only=True):
    """Full E911 registration representation."""

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
    """Schema for creating an E911 registration."""

    team_id: UUID
    address_line_1: Annotated[str, Meta(min_length=1, max_length=255)]
    city: Annotated[str, Meta(min_length=1, max_length=255)]
    state: Annotated[str, Meta(min_length=1, max_length=255)]
    postal_code: Annotated[str, Meta(min_length=1, max_length=20)]
    country: Annotated[str, Meta(min_length=2, max_length=2)] = "US"
    phone_number_id: UUID | None = None
    location_id: UUID | None = None
    address_line_2: Annotated[str, Meta(min_length=1, max_length=255)] | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Z]{2}", self.state):
            msg = "State must be exactly 2 uppercase letters"
            raise ValueError(msg)
        if not re.fullmatch(r"\d{5}(-\d{4})?", self.postal_code):
            msg = "Postal code must be a 5-digit ZIP or ZIP+4 format (e.g. 12345 or 12345-6789)"
            raise ValueError(msg)


class E911RegistrationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating an E911 registration."""

    phone_number_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    address_line_1: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    address_line_2: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    city: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    state: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    postal_code: Annotated[str, Meta(min_length=1, max_length=20)] | msgspec.UnsetType = msgspec.UNSET
    country: Annotated[str, Meta(min_length=2, max_length=2)] | msgspec.UnsetType = msgspec.UNSET

    def __post_init__(self) -> None:
        if not isinstance(self.state, msgspec.UnsetType) and not re.fullmatch(r"[A-Z]{2}", self.state):
            msg = "State must be exactly 2 uppercase letters"
            raise ValueError(msg)
        if not isinstance(self.postal_code, msgspec.UnsetType) and not re.fullmatch(
            r"\d{5}(-\d{4})?", self.postal_code
        ):
            msg = "Postal code must be a 5-digit ZIP or ZIP+4 format (e.g. 12345 or 12345-6789)"
            raise ValueError(msg)


class UnregisteredPhoneNumber(CamelizedBaseStruct, kw_only=True):
    """Phone number without an E911 registration."""

    id: UUID
    number: str
    number_type: str
    user_id: UUID
    label: str | None = None
    team_id: UUID | None = None
