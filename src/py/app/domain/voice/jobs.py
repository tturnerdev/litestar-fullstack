"""Voice domain background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from app.domain.tasks.jobs import broadcast_entity_event, provide_task_context

if TYPE_CHECKING:
    from saq.types import Context

__all__ = ("extension_create_job", "extension_delete_job", "extension_update_job")

logger = get_logger()


async def extension_create_job(ctx: Context, *, task_id: str) -> dict:
    """Create an extension on the external PBX system.

    Provisions the extension record that was already saved locally
    onto the remote PBX server.  The ``extension_id`` is read from
    the task's stored payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        extension_id = (task.payload or {}).get("extension_id", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Creating extension on PBX", extension_id=extension_id)
        await task_service.update_progress(task.id, 25)
        # TODO: Call PBX API to create extension
        await task_service.update_progress(task.id, 50)
        # TODO: Configure extension settings on PBX
        await task_service.update_progress(task.id, 75)
        # TODO: Verify extension is registered
        task = await task_service.complete_task(task.id, result={"extension_id": extension_id, "action": "extension.create"})
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def extension_update_job(ctx: Context, *, task_id: str) -> dict:
    """Update extension settings on the external PBX system.

    Pushes locally-updated extension configuration to the remote
    PBX server.  The ``extension_id`` is read from the task's stored
    payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        extension_id = (task.payload or {}).get("extension_id", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Updating extension on PBX", extension_id=extension_id)
        await task_service.update_progress(task.id, 25)
        # TODO: Fetch current PBX state for comparison
        await task_service.update_progress(task.id, 50)
        # TODO: Push updated settings to PBX
        await task_service.update_progress(task.id, 75)
        # TODO: Verify settings applied
        task = await task_service.complete_task(task.id, result={"extension_id": extension_id, "action": "extension.update"})
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def extension_delete_job(ctx: Context, *, task_id: str) -> dict:
    """Delete an extension from the external PBX system.

    Removes the extension from the remote PBX after the local record
    has been deleted.  The ``extension_id`` and ``extension_number``
    are read from the task's stored payload.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Returns:
        Dictionary with completion status.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        payload = task.payload or {}
        extension_id = payload.get("extension_id", "unknown")
        extension_number = payload.get("extension_number", "unknown")
        await task_service.start_task(task.id)
        await logger.ainfo("Deleting extension from PBX", extension_id=extension_id, extension_number=extension_number)
        await task_service.update_progress(task.id, 33)
        # TODO: Remove extension from PBX
        await task_service.update_progress(task.id, 66)
        # TODO: Confirm extension no longer registered
        task = await task_service.complete_task(
            task.id,
            result={"extension_id": extension_id, "extension_number": extension_number, "action": "extension.delete"},
        )
        await broadcast_entity_event(task, action="deleted")
    return {"status": "completed"}
