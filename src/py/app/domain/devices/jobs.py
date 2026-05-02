"""Device background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from app.domain.tasks.jobs import broadcast_entity_event, provide_task_context

if TYPE_CHECKING:
    from app.db.models._background_task import BackgroundTask
    from saq.types import Context

__all__ = ("device_provision_job", "device_reboot_job", "device_reprovision_job", "device_status_sync_job")

logger = get_logger()


async def broadcast_device_status(task: BackgroundTask, *, status: str, previous_status: str) -> None:
    """Publish a device.status_changed SSE event.

    Creates a short-lived Redis connection to broadcast the event.
    Errors are silently caught so broadcast failures never affect
    job execution.

    Args:
        task: The background task with device info in its payload.
        status: New device status.
        previous_status: Previous device status.
    """
    if not task.entity_id:
        return
    try:
        from redis.asyncio import Redis

        from app.domain.events.services import EventBroadcaster
        from app.lib.settings import get_settings

        settings = get_settings()
        redis = Redis.from_url(settings.saq.REDIS_URL)
        try:
            broadcaster = EventBroadcaster(redis)
            device_name = (task.payload or {}).get("device_name", "Device")
            await broadcaster.publish_device_status_changed(
                team_id=task.team_id,
                device_id=task.entity_id,
                device_name=device_name,
                status=status,
                previous_status=previous_status,
            )
        finally:
            await redis.aclose()
    except Exception:  # noqa: BLE001
        pass  # Never let SSE broadcast failures affect job execution


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
        await broadcast_device_status(task, status="rebooting", previous_status="online")
        await logger.ainfo("Sending reboot command to device", device_id=device_id)
        await task_service.update_progress(task.id, 50)
        # TODO: Actual device reboot via SIP NOTIFY or provisioning API
        await broadcast_device_status(task, status="offline", previous_status="rebooting")
        await task_service.update_progress(task.id, 100)
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "reboot"})
        await broadcast_device_status(task, status="online", previous_status="offline")
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
        await broadcast_device_status(task, status="provisioning", previous_status="unregistered")
        await logger.ainfo("Starting device provisioning", device_id=device_id)
        await task_service.update_progress(task.id, 25)
        # TODO: Generate SIP credentials
        await task_service.update_progress(task.id, 50)
        # TODO: Push configuration to device
        await task_service.update_progress(task.id, 75)
        # TODO: Verify device registration
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "provision"})
        await broadcast_device_status(task, status="online", previous_status="provisioning")
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
        await broadcast_device_status(task, status="provisioning", previous_status="online")
        await logger.ainfo("Starting device reprovisioning", device_id=device_id)
        await task_service.update_progress(task.id, 50)
        # TODO: Push updated configuration to device
        task = await task_service.complete_task(task.id, result={"device_id": device_id, "action": "reprovision"})
        await broadcast_device_status(task, status="online", previous_status="provisioning")
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def device_status_sync_job(_: Context) -> dict[str, int]:
    """SAQ cron job that syncs device statuses.

    In a production deployment, this would poll device management APIs
    or check SIP registrations. For now, it serves as the integration
    point for status change detection and SSE broadcasting.

    Args:
        _: SAQ job context (unused).

    Returns:
        Dictionary with checked and updated counts.
    """
    from app.db import models as m
    from app.domain.devices import deps as device_deps
    from app.lib.deps import provide_services

    updated_count = 0
    async with provide_services(device_deps.provide_devices_service) as (device_service,):
        devices = await device_service.list(m.Device.is_active.is_(True))
        for device in devices:
            # In production: check actual device status via API/SIP registration
            # and call broadcast_device_status when changes are detected.
            pass

    result = {"checked": len(devices), "updated": updated_count}
    await logger.ainfo("Device status sync complete", **result)
    return result
