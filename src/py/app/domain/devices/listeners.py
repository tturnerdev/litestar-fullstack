"""Device domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.devices import deps
from app.domain.notifications import deps as notification_deps
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
    async with provide_services(deps.provide_devices_service, notification_deps.provide_notifications_service) as (
        service,
        notification_service,
    ):
        obj = await service.get_one_or_none(id=device_id)
        if obj is None:
            await logger.aerror("Could not locate the specified device", id=device_id)
        else:
            await logger.ainfo("Device created", device_id=str(obj.id), name=obj.name, device_type=obj.device_type)
            try:
                await notification_service.notify(
                    user_id=obj.user_id,
                    title="Device Added",
                    message=f"A new device has been added: {obj.name}.",
                    category="device",
                    action_url=f"/devices/{device_id}",
                )
            except Exception:
                await logger.aerror("Failed to create notification for device_created", device_id=device_id)


__all__ = ("device_created_event_handler",)
