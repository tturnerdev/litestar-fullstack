"""Phone number CRUD schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from msgspec import UNSET, Meta, UnsetType

from app.lib.schema import CamelizedBaseStruct


class PhoneNumberList(CamelizedBaseStruct, kw_only=True):
    """Phone number summary for list views."""

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
    """Full phone number representation."""

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
    number: Annotated[str, Meta(min_length=1, max_length=20)]
    user_id: UUID
    label: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    number_type: Annotated[str, Meta(min_length=1, max_length=50)] = "local"
    caller_id_name: Annotated[str, Meta(min_length=1, max_length=50)] | None = None
    is_active: bool = True
    team_id: UUID | None = None


class PhoneNumberUpdate(CamelizedBaseStruct, gc=False, omit_defaults=True):
    label: Annotated[str, Meta(min_length=1, max_length=100)] | UnsetType | None = UNSET
    number_type: Annotated[str, Meta(min_length=1, max_length=50)] | UnsetType = UNSET
    caller_id_name: Annotated[str, Meta(min_length=1, max_length=50)] | UnsetType | None = UNSET
    is_active: bool | UnsetType = UNSET
    team_id: UUID | UnsetType | None = UNSET
