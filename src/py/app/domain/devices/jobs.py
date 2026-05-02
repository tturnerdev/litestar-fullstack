"""Device background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from app.domain.tasks.jobs import broadcast_entity_event, provide_task_context

if TYPE_CHECKING:
    from saq.types import Context

__all__ = ("device_provision_job", "device_reboot_job", "device_reprovision_job")

logger = get_logger()


async def device_reboot_job(ctx: Context, *, task_id: str) -> dict:
    """Reboot a device via its management interface.

    This is a placeholder that simulates the reboot process.
    The actual implementation will call the device's provisioning API
    or send a SIP NOTIFY message.

    The ``device_id`` is read from the task's stored payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        device_id = (task.payload or {}).get("device_id", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Sending reboot command to device", device_id=device_id)
        await task_service.update_progress(task.id, 50)
        # TODO: Actual device reboot via SIP NOTIFY or provisioning API
        await task_service.update_progress(task.id, 100)
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "reboot"})
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def device_provision_job(ctx: Context, *, task_id: str) -> dict:
    """Provision a new device with SIP credentials and configuration.

    The ``device_id`` is read from the task's stored payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        device_id = (task.payload or {}).get("device_id", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Starting device provisioning", device_id=device_id)
        await task_service.update_progress(task.id, 25)
        # TODO: Generate SIP credentials
        await task_service.update_progress(task.id, 50)
        # TODO: Push configuration to device
        await task_service.update_progress(task.id, 75)
        # TODO: Verify device registration
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "provision"})
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def device_reprovision_job(ctx: Context, *, task_id: str) -> dict:
    """Re-provision an existing device with updated configuration.

    The ``device_id`` is read from the task's stored payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        device_id = (task.payload or {}).get("device_id", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Starting device reprovisioning", device_id=device_id)
        await task_service.update_progress(task.id, 50)
        # TODO: Push updated configuration to device
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "reprovision"})
        await broadcast_entity_event(task)
    return {"status": "completed"}
