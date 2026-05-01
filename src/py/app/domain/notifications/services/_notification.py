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
        return await self.create(
            {
                "user_id": user_id,
                "title": title,
                "message": message,
                "category": category,
                "action_url": action_url,
                "metadata_": metadata,
            },
        )

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
