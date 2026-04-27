"""Device domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.devices import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("device_created")
async def device_created_event_handler(device_id: UUID) -> None:
    """Executes when a new device is created.

    Logs the audit event and could trigger initial provisioning.

    Args:
        device_id: The primary key of the device that was created.
    """
    await logger.ainfo("Running post device creation flow.")
    async with provide_services(deps.provide_devices_service) as (service,):
        obj = await service.get_one_or_none(id=device_id)
        if obj is None:
            await logger.aerror("Could not locate the specified device", id=device_id)
        else:
            await logger.ainfo("Device created", device_id=str(obj.id), name=obj.name, device_type=obj.device_type)


__all__ = ("device_created_event_handler",)
