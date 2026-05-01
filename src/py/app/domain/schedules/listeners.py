"""Schedule domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.schedules import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("schedule_created")
async def schedule_created_event_handler(schedule_id: UUID) -> None:
    """Executes when a new schedule is created.

    Logs the audit event.

    Args:
        schedule_id: The primary key of the schedule that was created.
    """
    await logger.ainfo("Running post schedule creation flow.")
    async with provide_services(deps.provide_schedules_service) as (service,):
        obj = await service.get_one_or_none(id=schedule_id)
        if obj is None:
            await logger.aerror("Could not locate the specified schedule", id=schedule_id)
        else:
            await logger.ainfo(
                "Schedule created",
                schedule_id=str(obj.id),
                name=obj.name,
                schedule_type=obj.schedule_type,
            )


__all__ = ("schedule_created_event_handler",)
