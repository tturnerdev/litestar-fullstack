"""Call queue schemas."""

from uuid import UUID

import msgspec

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
    priority: int = 0
    penalty: int = 0
    is_paused: bool = False


class CallQueueMemberUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a call queue member."""

    extension_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    priority: int | msgspec.UnsetType = msgspec.UNSET
    penalty: int | msgspec.UnsetType = msgspec.UNSET
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


class CallQueueCreate(CamelizedBaseStruct):
    """Schema for creating a call queue."""

    name: str
    number: str
    strategy: str = "ring_all"
    ring_time: int = 15
    max_wait_time: int = 300
    max_callers: int = 10
    join_empty: bool = False
    leave_when_empty: bool = True
    music_on_hold_class: str | None = None
    announce_frequency: int | None = None
    announce_holdtime: bool = False
    timeout_destination: str | None = None
    wrapup_time: int = 0


class CallQueueUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a call queue."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    number: str | msgspec.UnsetType = msgspec.UNSET
    strategy: str | msgspec.UnsetType = msgspec.UNSET
    ring_time: int | msgspec.UnsetType = msgspec.UNSET
    max_wait_time: int | msgspec.UnsetType = msgspec.UNSET
    max_callers: int | msgspec.UnsetType = msgspec.UNSET
    join_empty: bool | msgspec.UnsetType = msgspec.UNSET
    leave_when_empty: bool | msgspec.UnsetType = msgspec.UNSET
    music_on_hold_class: str | msgspec.UnsetType | None = msgspec.UNSET
    announce_frequency: int | msgspec.UnsetType | None = msgspec.UNSET
    announce_holdtime: bool | msgspec.UnsetType = msgspec.UNSET
    timeout_destination: str | msgspec.UnsetType | None = msgspec.UNSET
    wrapup_time: int | msgspec.UnsetType = msgspec.UNSET
