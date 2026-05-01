"""E911 domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.e911 import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("e911_registration_created")
async def e911_registration_created_event_handler(registration_id: UUID) -> None:
    """Executes when a new E911 registration is created.

    Logs the audit event.

    Args:
        registration_id: The primary key of the registration that was created.
    """
    await logger.ainfo("Running post E911 registration creation flow.")
    async with provide_services(deps.provide_e911_registration_service) as (service,):
        obj = await service.get_one_or_none(id=registration_id)
        if obj is None:
            await logger.aerror("Could not locate the specified E911 registration", id=registration_id)
        else:
            await logger.ainfo(
                "E911 registration created",
                registration_id=str(obj.id),
                team_id=str(obj.team_id),
                phone_number_id=str(obj.phone_number_id) if obj.phone_number_id else None,
            )


__all__ = ("e911_registration_created_event_handler",)
