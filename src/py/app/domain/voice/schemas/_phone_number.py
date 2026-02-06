"""Phone number schemas."""

from uuid import UUID

import msgspec

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


class PhoneNumberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Phone number update properties."""

    label: str | msgspec.UnsetType | None = msgspec.UNSET
    caller_id_name: str | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
