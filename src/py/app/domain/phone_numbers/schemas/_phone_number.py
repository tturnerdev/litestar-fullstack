"""Phone number CRUD schemas."""

from datetime import datetime
from uuid import UUID

from msgspec import UNSET, UnsetType

from app.lib.schema import CamelizedBaseStruct


class PhoneNumberList(CamelizedBaseStruct, kw_only=True):
    id: UUID
    number: str
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    is_active: bool = True
    user_id: UUID
    team_id: UUID | None = None
    created_at: datetime


class PhoneNumberDetail(CamelizedBaseStruct, kw_only=True):
    id: UUID
    number: str
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    is_active: bool = True
    user_id: UUID
    team_id: UUID | None = None
    created_at: datetime
    updated_at: datetime


class PhoneNumberCreate(CamelizedBaseStruct, kw_only=True):
    number: str
    user_id: UUID
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    is_active: bool = True
    team_id: UUID | None = None


class PhoneNumberUpdate(CamelizedBaseStruct, gc=False, omit_defaults=True):
    label: str | UnsetType | None = UNSET
    number_type: str | UnsetType = UNSET
    caller_id_name: str | UnsetType | None = UNSET
    is_active: bool | UnsetType = UNSET
    team_id: UUID | UnsetType | None = UNSET
