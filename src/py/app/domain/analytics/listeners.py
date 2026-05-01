"""Analytics domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.analytics import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

logger = structlog.get_logger()


@listener("call_record_created")
async def call_record_created_event_handler(call_record_id: UUID) -> None:
    """Executes when a new call record is created.

    Logs the event for observability.

    Args:
        call_record_id: The primary key of the call record that was created.
    """
    await logger.ainfo("Processing new call record.", call_record_id=call_record_id)
    async with provide_services(deps.provide_call_records_service) as (service,):
        obj = await service.get_one_or_none(id=call_record_id)
        if obj is None:
            await logger.aerror("Could not locate the call record", id=call_record_id)
        else:
            await logger.ainfo(
                "Call record created",
                call_record_id=str(obj.id),
                direction=obj.direction,
                disposition=obj.disposition,
            )


__all__ = ("call_record_created_event_handler",)
