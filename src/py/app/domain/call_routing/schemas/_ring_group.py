"""Ring group schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class RingGroupMember(CamelizedBaseStruct):
    """Ring group member representation."""

    id: UUID
    ring_group_id: UUID
    sort_order: int
    extension_id: UUID | None = None
    external_number: str | None = None


class RingGroupMemberCreate(CamelizedBaseStruct):
    """Schema for creating a ring group member."""

    extension_id: UUID | None = None
    external_number: Annotated[str, Meta(max_length=20)] | None = None
    sort_order: int = 0


class RingGroupMemberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a ring group member."""

    extension_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    external_number: Annotated[str, Meta(max_length=20)] | msgspec.UnsetType | None = msgspec.UNSET
    sort_order: int | msgspec.UnsetType = msgspec.UNSET


class RingGroup(CamelizedBaseStruct):
    """Full ring group representation."""

    id: UUID
    team_id: UUID
    name: str
    number: str
    strategy: str
    ring_time: int
    no_answer_destination: str | None = None
    members: list[RingGroupMember] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RingGroupCreate(CamelizedBaseStruct):
    """Schema for creating a ring group."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    number: Annotated[str, Meta(min_length=1, max_length=50)]
    strategy: Annotated[str, Meta(min_length=1, max_length=50)] = "ring_all"
    ring_time: Annotated[int, Meta(ge=1, le=600)] = 20
    no_answer_destination: Annotated[str, Meta(max_length=255)] | None = None


class RingGroupUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a ring group."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    number: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    strategy: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    ring_time: Annotated[int, Meta(ge=1, le=600)] | msgspec.UnsetType = msgspec.UNSET
    no_answer_destination: Annotated[str, Meta(max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
