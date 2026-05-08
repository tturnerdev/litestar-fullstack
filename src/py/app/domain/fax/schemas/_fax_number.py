"""Fax number schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class FaxNumber(CamelizedBaseStruct):
    """Full fax number representation."""

    id: UUID
    user_id: UUID
    number: str
    team_id: UUID | None = None
    label: str | None = None
    is_active: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FaxNumberCreate(CamelizedBaseStruct):
    """Schema for creating a fax number."""

    number: Annotated[str, Meta(min_length=1, max_length=20)]
    label: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    is_active: bool = True
    team_id: UUID | None = None


class FaxNumberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a fax number."""

    label: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
