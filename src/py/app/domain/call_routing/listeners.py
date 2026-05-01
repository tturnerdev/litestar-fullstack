"""Call routing domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

if TYPE_CHECKING:
    from uuid import UUID

logger = structlog.get_logger()


@listener("time_condition_override_changed")
async def time_condition_override_changed_handler(time_condition_id: UUID, override_mode: str) -> None:
    """Executes when a time condition override mode is changed."""
    await logger.ainfo(
        "Time condition override changed.",
        time_condition_id=time_condition_id,
        override_mode=override_mode,
    )


@listener("call_queue_member_paused")
async def call_queue_member_paused_handler(call_queue_id: UUID, member_id: UUID, is_paused: bool) -> None:
    """Executes when a call queue member is paused or unpaused."""
    await logger.ainfo(
        "Call queue member pause state changed.",
        call_queue_id=call_queue_id,
        member_id=member_id,
        is_paused=is_paused,
    )


__all__ = (
    "call_queue_member_paused_handler",
    "time_condition_override_changed_handler",
)
