"""SAQ job utilities for background task tracking."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from app.domain.tasks import deps as task_deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from app.db.models._background_task import BackgroundTask
    from app.domain.tasks.services import BackgroundTaskService
    from saq.types import Context


@asynccontextmanager
async def provide_task_context(ctx: Context, task_id: str) -> AsyncIterator[tuple[BackgroundTaskService, BackgroundTask]]:
    """Provide a task service and task record for SAQ job functions.

    Opens a service session, retrieves the task by ID, and yields
    the service and task. On exception, marks the task as failed
    before re-raising.

    Args:
        ctx: SAQ job context.
        task_id: The background task ID.

    Yields:
        Tuple of (BackgroundTaskService, BackgroundTask).
    """
    async with provide_services(task_deps.provide_background_tasks_service) as (task_service,):
        task = await task_service.get(task_id)
        try:
            yield task_service, task
        except Exception as exc:
            await task_service.fail_task(task_id, str(exc))
            raise


async def cleanup_stale_tasks(ctx: Context) -> dict[str, int]:
    """SAQ cron job that cleans up old completed/failed/cancelled tasks.

    Args:
        ctx: SAQ job context.

    Returns:
        Dictionary with count of deleted tasks.
    """
    async with provide_services(task_deps.provide_background_tasks_service) as (task_service,):
        count = await task_service.cleanup_stale_tasks(older_than_days=30)
    return {"deleted": count}
