"""Admin Music on Hold schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class MusicOnHoldList(CamelizedBaseStruct, kw_only=True):
    """Summary Music on Hold info for admin lists."""

    id: UUID
    name: str
    category: str
    is_default: bool
    is_active: bool
    file_count: int
    created_at: datetime
    updated_at: datetime


class MusicOnHoldDetail(CamelizedBaseStruct, kw_only=True):
    """Full Music on Hold representation."""

    id: UUID
    name: str
    description: str
    category: str
    is_default: bool
    is_active: bool
    random_order: bool
    file_list: list[str]
    created_at: datetime
    updated_at: datetime


class MusicOnHoldCreate(CamelizedBaseStruct):
    """Schema for creating a Music on Hold class."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    description: Annotated[str, Meta(max_length=1000)] = ""
    category: str = "custom"
    is_default: bool = False
    is_active: bool = True
    random_order: bool = False
    file_list: list[str] = []


class MusicOnHoldUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a Music on Hold class."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    description: Annotated[str, Meta(max_length=1000)] | msgspec.UnsetType = msgspec.UNSET
    category: str | msgspec.UnsetType = msgspec.UNSET
    is_default: bool | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    random_order: bool | msgspec.UnsetType = msgspec.UNSET
    file_list: list[str] | msgspec.UnsetType = msgspec.UNSET
