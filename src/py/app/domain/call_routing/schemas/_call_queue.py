"""Call queue schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class CallQueueMember(CamelizedBaseStruct):
    """Call queue member representation."""

    id: UUID
    call_queue_id: UUID
    priority: int
    penalty: int
    is_paused: bool
    extension_id: UUID | None = None


class CallQueueMemberCreate(CamelizedBaseStruct):
    """Schema for creating a call queue member."""

    extension_id: UUID | None = None
    priority: Annotated[int, Meta(ge=0)] = 0
    penalty: Annotated[int, Meta(ge=0)] = 0
    is_paused: bool = False


class CallQueueMemberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a call queue member."""

    extension_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    priority: Annotated[int, Meta(ge=0)] | msgspec.UnsetType = msgspec.UNSET
    penalty: Annotated[int, Meta(ge=0)] | msgspec.UnsetType = msgspec.UNSET
    is_paused: bool | msgspec.UnsetType = msgspec.UNSET


class CallQueueMemberPause(CamelizedBaseStruct):
    """Schema for pausing/unpausing a queue member."""

    is_paused: bool


class CallQueue(CamelizedBaseStruct):
    """Full call queue representation."""

    id: UUID
    team_id: UUID
    name: str
    number: str
    strategy: str
    ring_time: int
    max_wait_time: int
    max_callers: int
    join_empty: bool
    leave_when_empty: bool
    announce_holdtime: bool
    wrapup_time: int
    music_on_hold_class: str | None = None
    announce_frequency: int | None = None
    timeout_destination: str | None = None
    members: list[CallQueueMember] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CallQueueCreate(CamelizedBaseStruct):
    """Schema for creating a call queue."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    number: Annotated[str, Meta(min_length=1, max_length=20)]
    strategy: Annotated[str, Meta(min_length=1, max_length=50)] = "ring_all"
    ring_time: Annotated[int, Meta(ge=1, le=600)] = 15
    max_wait_time: Annotated[int, Meta(ge=0, le=3600)] = 300
    max_callers: Annotated[int, Meta(ge=1, le=100)] = 10
    join_empty: bool = False
    leave_when_empty: bool = True
    music_on_hold_class: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    announce_frequency: Annotated[int, Meta(ge=0)] | None = None
    announce_holdtime: bool = False
    timeout_destination: Annotated[str, Meta(min_length=1, max_length=255)] | None = None
    wrapup_time: Annotated[int, Meta(ge=0, le=300)] = 0


class CallQueueUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a call queue."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    number: Annotated[str, Meta(min_length=1, max_length=20)] | msgspec.UnsetType = msgspec.UNSET
    strategy: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    ring_time: Annotated[int, Meta(ge=1, le=600)] | msgspec.UnsetType = msgspec.UNSET
    max_wait_time: Annotated[int, Meta(ge=0, le=3600)] | msgspec.UnsetType = msgspec.UNSET
    max_callers: Annotated[int, Meta(ge=1, le=100)] | msgspec.UnsetType = msgspec.UNSET
    join_empty: bool | msgspec.UnsetType = msgspec.UNSET
    leave_when_empty: bool | msgspec.UnsetType = msgspec.UNSET
    music_on_hold_class: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    announce_frequency: Annotated[int, Meta(ge=0)] | msgspec.UnsetType | None = msgspec.UNSET
    announce_holdtime: bool | msgspec.UnsetType = msgspec.UNSET
    timeout_destination: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    wrapup_time: Annotated[int, Meta(ge=0, le=300)] | msgspec.UnsetType = msgspec.UNSET
