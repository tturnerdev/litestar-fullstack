"""Location domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.locations import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("location_created")
async def location_created_event_handler(location_id: UUID) -> None:
    """Executes when a new location is created.

    Logs the audit event.

    Args:
        location_id: The primary key of the location that was created.
    """
    await logger.ainfo("Running post location creation flow.")
    async with provide_services(deps.provide_locations_service) as (service,):
        obj = await service.get_one_or_none(id=location_id)
        if obj is None:
            await logger.aerror("Could not locate the specified location", id=location_id)
        else:
            await logger.ainfo(
                "Location created",
                location_id=str(obj.id),
                name=obj.name,
                location_type=obj.location_type,
            )


__all__ = ("location_created_event_handler",)
