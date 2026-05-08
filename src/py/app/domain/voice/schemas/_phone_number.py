"""Phone number schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.db.models._voice_enums import PhoneNumberType
from app.lib.schema import CamelizedBaseStruct


class PhoneNumber(CamelizedBaseStruct):
    """Phone number response."""

    id: UUID
    user_id: UUID
    number: str
    label: str | None = None
    number_type: PhoneNumberType = PhoneNumberType.LOCAL
    caller_id_name: str | None = None
    is_active: bool = True
    team_id: UUID | None = None
    e911_registered: bool = False
    e911_registration_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PhoneNumberCreate(CamelizedBaseStruct):
    """Phone number create properties."""

    number: Annotated[str, Meta(min_length=1, max_length=20)]
    label: Annotated[str, Meta(max_length=100)] | None = None
    number_type: PhoneNumberType = PhoneNumberType.LOCAL
    caller_id_name: Annotated[str, Meta(max_length=100)] | None = None
    is_active: bool = True
    team_id: UUID | None = None


class PhoneNumberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Phone number update properties."""

    label: str | msgspec.UnsetType | None = msgspec.UNSET
    caller_id_name: str | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
