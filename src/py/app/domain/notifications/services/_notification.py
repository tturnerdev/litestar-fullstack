"""Notification service."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from advanced_alchemy import repository, service
from sqlalchemy import func, select, update

from app.db import models as m


class NotificationService(service.SQLAlchemyAsyncRepositoryService[m.Notification]):
    """Handles CRUD and business operations for Notification resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Notification]):
        """Notification Repository."""

        model_type = m.Notification

    repository_type = Repo
    match_fields = ["user_id", "title"]

    async def _broadcast_notification_event(self, notification: m.Notification) -> None:
        """Publish a notification creation event to Redis for SSE streaming.

        Creates a short-lived Redis connection to broadcast the event.
        Errors are silently caught so broadcast failures never affect
        notification operations.

        Args:
            notification: The notification to broadcast.
        """
        try:
            from redis.asyncio import Redis

            from app.domain.events.services import EventBroadcaster
            from app.lib.settings import get_settings

            settings = get_settings()
            redis = Redis.from_url(settings.saq.REDIS_URL)
            try:
                broadcaster = EventBroadcaster(redis)
                await broadcaster.publish_notification_created(
                    user_id=notification.user_id,
                    notification_id=notification.id,
                    title=notification.title,
                    category=notification.category,
                    action_url=notification.action_url,
                )
            finally:
                await redis.aclose()
        except Exception:  # noqa: BLE001
            pass  # Never let SSE broadcast failures affect notification operations

    async def notify(
        self,
        user_id: UUID,
        title: str,
        message: str,
        category: str,
        action_url: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> m.Notification:
        """Create a notification for a user.

        Args:
            user_id: The recipient user ID.
            title: Notification title.
            message: Notification message body.
            category: Category (ticket, team, device, system, voice, fax).
            action_url: Optional URL to navigate to.
            metadata: Optional structured metadata.

        Returns:
            The created notification.
        """
        notification = await self.create(
            {
                "user_id": user_id,
                "title": title,
                "message": message,
                "category": category,
                "action_url": action_url,
                "metadata_": metadata,
            },
        )
        await self._broadcast_notification_event(notification)
        return notification

    async def mark_read(self, notification_id: UUID, user_id: UUID) -> m.Notification:
        """Mark a single notification as read.

        Args:
            notification_id: The notification to mark.
            user_id: The owning user (for authorization).

        Returns:
            The updated notification.
        """
        return await self.update(
            item_id=notification_id,
            data={"is_read": True},
        )

    async def mark_all_read(self, user_id: UUID) -> None:
        """Mark all unread notifications as read for a user.

        Args:
            user_id: The user whose notifications to mark.
        """
        stmt = (
            update(m.Notification)
            .where(
                m.Notification.user_id == user_id,
                m.Notification.is_read.is_(False),
            )
            .values(is_read=True)
        )
        await self.repository.session.execute(stmt)
        await self.repository.session.flush()

    async def delete_read(self, user_id: UUID) -> int:
        """Delete all read notifications for a user.

        Args:
            user_id: The user whose read notifications to delete.

        Returns:
            Number of deleted notifications.
        """
        from sqlalchemy import delete as sa_delete

        stmt = sa_delete(m.Notification).where(
            m.Notification.user_id == user_id,
            m.Notification.is_read.is_(True),
        )
        result = await self.repository.session.execute(stmt)
        await self.repository.session.flush()
        return result.rowcount  # type: ignore[return-value]

    async def get_unread_count(self, user_id: UUID) -> int:
        """Count unread notifications for a user.

        Args:
            user_id: The user to count for.

        Returns:
            Number of unread notifications.
        """
        stmt = select(func.count()).where(
            m.Notification.user_id == user_id,
            m.Notification.is_read.is_(False),
        )
        result = await self.repository.session.execute(stmt)
        return result.scalar_one()
