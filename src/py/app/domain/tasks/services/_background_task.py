"""Background task service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.lib.deps import CompositeServiceMixin

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID


class BackgroundTaskService(CompositeServiceMixin, service.SQLAlchemyAsyncRepositoryService[m.BackgroundTask]):
    """Handles CRUD operations on BackgroundTask resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.BackgroundTask]):
        """BackgroundTask Repository."""

        model_type = m.BackgroundTask

    repository_type = Repo

    async def _broadcast_task_event(self, task: m.BackgroundTask) -> None:
        """Publish a task status event to Redis for SSE streaming.

        Creates a short-lived Redis connection to broadcast the event.
        Errors are silently caught so broadcast failures never affect
        task operations.

        Args:
            task: The task whose status should be broadcast.
        """
        try:
            from redis.asyncio import Redis

            from app.domain.events.services import EventBroadcaster
            from app.lib.settings import get_settings

            settings = get_settings()
            redis = Redis.from_url(settings.saq.REDIS_URL)
            try:
                broadcaster = EventBroadcaster(redis)
                await broadcaster.publish_task_update(
                    team_id=task.team_id,
                    task_id=task.id,
                    task_type=task.task_type,
                    status=task.status,
                    progress=task.progress,
                    entity_type=task.entity_type,
                    entity_id=task.entity_id,
                    result=task.result,
                    error_message=task.error_message,
                )
            finally:
                await redis.aclose()
        except Exception:  # noqa: BLE001
            pass  # Never let SSE broadcast failures affect task operations

    async def create_task(
        self,
        task_type: str,
        team_id: UUID,
        initiated_by_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        payload: dict[str, Any] | None = None,
    ) -> m.BackgroundTask:
        """Create a new pending background task record.

        Args:
            task_type: Type of background task (e.g., 'bulk_export', 'bulk_delete').
            team_id: Team this task belongs to.
            initiated_by_id: User who initiated the task.
            entity_type: Type of entity the task operates on.
            entity_id: ID of the entity the task operates on.
            payload: Input data for the task.

        Returns:
            The created BackgroundTask.
        """
        return await self.create(
            {
                "task_type": task_type,
                "status": m.BackgroundTaskStatus.PENDING,
                "progress": 0,
                "team_id": team_id,
                "initiated_by_id": initiated_by_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "payload": payload,
            }
        )

    async def start_task(self, task_id: Any) -> m.BackgroundTask:
        """Mark a task as running.

        Args:
            task_id: The task ID to start.

        Returns:
            The updated BackgroundTask.
        """
        now = datetime.now(UTC)
        updated = await self.update(
            {"status": m.BackgroundTaskStatus.RUNNING, "started_at": now},
            item_id=task_id,
        )
        await self._broadcast_task_event(updated)
        return updated

    async def update_progress(self, task_id: Any, progress: int) -> m.BackgroundTask:
        """Update task progress percentage.

        Args:
            task_id: The task ID to update.
            progress: Progress percentage (0-100).

        Returns:
            The updated BackgroundTask.
        """
        updated = await self.update(
            {"progress": min(max(progress, 0), 100)},
            item_id=task_id,
        )
        await self._broadcast_task_event(updated)
        return updated

    async def complete_task(self, task_id: Any, result: dict[str, Any] | None = None) -> m.BackgroundTask:
        """Mark a task as completed.

        Args:
            task_id: The task ID to complete.
            result: Output data from the task.

        Returns:
            The updated BackgroundTask.
        """
        now = datetime.now(UTC)
        updated = await self.update(
            {
                "status": m.BackgroundTaskStatus.COMPLETED,
                "progress": 100,
                "completed_at": now,
                "result": result,
            },
            item_id=task_id,
        )
        await self._broadcast_task_event(updated)
        try:
            from app.domain.notifications import deps as notification_deps
            from app.lib.deps import provide_services

            if updated.initiated_by_id:
                async with provide_services(notification_deps.provide_notifications_service) as (notification_service,):
                    task_label = updated.task_type.replace(".", " ").replace("_", " ").title()
                    await notification_service.notify(
                        user_id=updated.initiated_by_id,
                        title=f"{task_label} Complete",
                        message=f"Your {task_label.lower()} task has completed successfully.",
                        category="system",
                        action_url=f"/tasks/{updated.id}",
                    )
        except Exception:  # noqa: BLE001
            pass  # Never let notification failures affect task operations
        return updated

    async def fail_task(self, task_id: Any, error_message: str) -> m.BackgroundTask:
        """Mark a task as failed.

        Args:
            task_id: The task ID to fail.
            error_message: Description of the error.

        Returns:
            The updated BackgroundTask.
        """
        now = datetime.now(UTC)
        updated = await self.update(
            {
                "status": m.BackgroundTaskStatus.FAILED,
                "completed_at": now,
                "error_message": error_message,
            },
            item_id=task_id,
        )
        await self._broadcast_task_event(updated)
        try:
            from app.domain.notifications import deps as notification_deps
            from app.lib.deps import provide_services

            if updated.initiated_by_id:
                async with provide_services(notification_deps.provide_notifications_service) as (notification_service,):
                    task_label = updated.task_type.replace(".", " ").replace("_", " ").title()
                    await notification_service.notify(
                        user_id=updated.initiated_by_id,
                        title=f"{task_label} Failed",
                        message=f"Your {task_label.lower()} task has failed: {error_message or 'Unknown error'}",
                        category="system",
                        action_url=f"/tasks/{updated.id}",
                    )
        except Exception:  # noqa: BLE001
            pass  # Never let notification failures affect task operations
        return updated

    async def cancel_task(self, task_id: Any) -> m.BackgroundTask:
        """Cancel a pending or running task.

        Also attempts to abort the SAQ job if one is associated.

        Args:
            task_id: The task ID to cancel.

        Returns:
            The updated BackgroundTask.
        """
        from app.lib.deps import get_task_queue

        db_obj = await self.get(task_id)
        now = datetime.now(UTC)
        updated = await self.update(
            {
                "status": m.BackgroundTaskStatus.CANCELLED,
                "completed_at": now,
            },
            item_id=task_id,
        )
        # Attempt to abort the SAQ job if one is associated
        if db_obj.saq_job_key:
            try:
                queue = await get_task_queue()
                await queue.abort(db_obj.saq_job_key)
            except Exception:
                pass
        await self._broadcast_task_event(updated)
        return updated

    async def list_active_for_user(self, user_id: Any) -> list[m.BackgroundTask]:
        """List pending/running tasks for a specific user.

        Args:
            user_id: The user ID to filter by.

        Returns:
            List of active BackgroundTask records.
        """
        results, _ = await self.list_and_count(
            m.BackgroundTask.initiated_by_id == user_id,
            m.BackgroundTask.status.in_([
                m.BackgroundTaskStatus.PENDING,
                m.BackgroundTaskStatus.RUNNING,
            ]),
        )
        return list(results)

    async def cleanup_stale_tasks(self, older_than_days: int = 30) -> int:
        """Delete completed/failed/cancelled tasks older than the threshold.

        Args:
            older_than_days: Number of days after which to delete tasks.

        Returns:
            Count of deleted tasks.
        """
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        results, _ = await self.list_and_count(
            m.BackgroundTask.status.in_([
                m.BackgroundTaskStatus.COMPLETED,
                m.BackgroundTaskStatus.FAILED,
                m.BackgroundTaskStatus.CANCELLED,
            ]),
            m.BackgroundTask.completed_at < cutoff,
        )
        count = len(results)
        for task in results:
            await self.delete(task.id)
        return count

    async def enqueue_tracked_task(
        self,
        task_type: str,
        job_function: Callable[..., Any],
        team_id: UUID,
        initiated_by_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        payload: dict[str, Any] | None = None,
        timeout: int = 300,
    ) -> m.BackgroundTask:
        """Create a task record and enqueue a SAQ job in one step.

        Args:
            task_type: Type of background task.
            job_function: The SAQ job function to enqueue.
            team_id: Team this task belongs to.
            initiated_by_id: User who initiated the task.
            entity_type: Type of entity the task operates on.
            entity_id: ID of the entity the task operates on.
            payload: Input data for the task.
            timeout: Job timeout in seconds.

        Returns:
            The created BackgroundTask with saq_job_key set.
        """
        from app.lib.deps import get_task_queue

        task = await self.create_task(
            task_type=task_type,
            team_id=team_id,
            initiated_by_id=initiated_by_id,
            entity_type=entity_type,
            entity_id=entity_id,
            payload=payload,
        )
        queue = await get_task_queue()
        job = await queue.enqueue(job_function, task_id=str(task.id), timeout=timeout)
        if job and job.key:
            task = await self.update(
                {"saq_job_key": job.key},
                item_id=task.id,
            )
        return task
