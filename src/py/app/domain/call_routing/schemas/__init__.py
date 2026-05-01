"""Call routing domain schemas."""

from app.domain.call_routing.schemas._call_queue import (
    CallQueue,
    CallQueueCreate,
    CallQueueMember,
    CallQueueMemberCreate,
    CallQueueMemberPause,
    CallQueueMemberUpdate,
    CallQueueUpdate,
)
from app.domain.call_routing.schemas._ivr_menu import (
    IvrMenu,
    IvrMenuCreate,
    IvrMenuOption,
    IvrMenuOptionCreate,
    IvrMenuOptionUpdate,
    IvrMenuUpdate,
)
from app.domain.call_routing.schemas._ring_group import (
    RingGroup,
    RingGroupCreate,
    RingGroupMember,
    RingGroupMemberCreate,
    RingGroupMemberUpdate,
    RingGroupUpdate,
)
from app.domain.call_routing.schemas._time_condition import (
    TimeCondition,
    TimeConditionCreate,
    TimeConditionOverride,
    TimeConditionUpdate,
)

__all__ = (
    "CallQueue",
    "CallQueueCreate",
    "CallQueueMember",
    "CallQueueMemberCreate",
    "CallQueueMemberPause",
    "CallQueueMemberUpdate",
    "CallQueueUpdate",
    "IvrMenu",
    "IvrMenuCreate",
    "IvrMenuOption",
    "IvrMenuOptionCreate",
    "IvrMenuOptionUpdate",
    "IvrMenuUpdate",
    "RingGroup",
    "RingGroupCreate",
    "RingGroupMember",
    "RingGroupMemberCreate",
    "RingGroupMemberUpdate",
    "RingGroupUpdate",
    "TimeCondition",
    "TimeConditionCreate",
    "TimeConditionOverride",
    "TimeConditionUpdate",
)
