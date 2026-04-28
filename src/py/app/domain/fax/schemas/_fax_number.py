"""Fax number schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class FaxNumber(CamelizedBaseStruct):
    id: UUID
    user_id: UUID
    number: str
    team_id: UUID | None = None
    label: str | None = None
    is_active: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FaxNumberUpdate(CamelizedBaseStruct, omit_defaults=True):
    label: str | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
