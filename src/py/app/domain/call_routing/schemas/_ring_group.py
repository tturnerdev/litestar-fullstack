"""Ring group schemas."""

from uuid import UUID

import msgspec

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
    external_number: str | None = None
    sort_order: int = 0


class RingGroupMemberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a ring group member."""

    extension_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    external_number: str | msgspec.UnsetType | None = msgspec.UNSET
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


class RingGroupCreate(CamelizedBaseStruct):
    """Schema for creating a ring group."""

    name: str
    number: str
    strategy: str = "ring_all"
    ring_time: int = 20
    no_answer_destination: str | None = None


class RingGroupUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a ring group."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    number: str | msgspec.UnsetType = msgspec.UNSET
    strategy: str | msgspec.UnsetType = msgspec.UNSET
    ring_time: int | msgspec.UnsetType = msgspec.UNSET
    no_answer_destination: str | msgspec.UnsetType | None = msgspec.UNSET
