"""Call routing domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.call_routing.services import (
    CallQueueMemberService,
    CallQueueService,
    IvrMenuOptionService,
    IvrMenuService,
    RingGroupMemberService,
    RingGroupService,
    TimeConditionService,
)
from app.lib.deps import create_service_provider

provide_time_conditions_service = create_service_provider(
    TimeConditionService,
    error_messages={
        "duplicate_key": "Time condition already exists.",
        "integrity": "Time condition operation failed.",
    },
)

provide_ivr_menus_service = create_service_provider(
    IvrMenuService,
    load=[selectinload(m.IvrMenu.options)],
    error_messages={
        "duplicate_key": "IVR menu already exists.",
        "integrity": "IVR menu operation failed.",
    },
)

provide_ivr_menu_options_service = create_service_provider(
    IvrMenuOptionService,
    error_messages={
        "duplicate_key": "IVR menu option already exists for this digit.",
        "integrity": "IVR menu option operation failed.",
    },
)

provide_call_queues_service = create_service_provider(
    CallQueueService,
    load=[selectinload(m.CallQueue.members)],
    error_messages={
        "duplicate_key": "Call queue already exists.",
        "integrity": "Call queue operation failed.",
    },
)

provide_call_queue_members_service = create_service_provider(
    CallQueueMemberService,
    error_messages={
        "duplicate_key": "Call queue member already exists.",
        "integrity": "Call queue member operation failed.",
    },
)

provide_ring_groups_service = create_service_provider(
    RingGroupService,
    load=[selectinload(m.RingGroup.members)],
    error_messages={
        "duplicate_key": "Ring group already exists.",
        "integrity": "Ring group operation failed.",
    },
)

provide_ring_group_members_service = create_service_provider(
    RingGroupMemberService,
    error_messages={
        "duplicate_key": "Ring group member already exists.",
        "integrity": "Ring group member operation failed.",
    },
)

__all__ = (
    "provide_call_queue_members_service",
    "provide_call_queues_service",
    "provide_ivr_menu_options_service",
    "provide_ivr_menus_service",
    "provide_ring_group_members_service",
    "provide_ring_groups_service",
    "provide_time_conditions_service",
)
