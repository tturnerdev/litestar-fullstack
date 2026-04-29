"""Notification Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.exceptions import NotFoundException, PermissionDeniedException
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.notifications.schemas import Notification, NotificationUpdate, UnreadCount
from app.domain.notifications.services import NotificationService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class NotificationController(Controller):
    """Notifications."""

    tags = ["Notifications"]
    path = "/api/notifications"
    dependencies = create_service_dependencies(
        NotificationService,
        key="notifications_service",
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(operation_id="ListNotifications")
    async def list_notifications(
        self,
        notifications_service: NotificationService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Notification]:
        """List notifications for the current user.

        Args:
            notifications_service: The notification service.
            current_user: The current authenticated user.
            filters: The filters to apply.

        Returns:
            Paginated list of notifications.
        """
        results, total = await notifications_service.list_and_count(
            *filters,
            m.Notification.user_id == current_user.id,
        )
        return notifications_service.to_schema(results, total, filters, schema_type=Notification)

    @get(operation_id="GetUnreadNotificationCount", path="/unread-count")
    async def get_unread_count(
        self,
        notifications_service: NotificationService,
        current_user: m.User,
    ) -> UnreadCount:
        """Get the count of unread notifications for the current user.

        Args:
            notifications_service: The notification service.
            current_user: The current authenticated user.

        Returns:
            The unread count.
        """
        count = await notifications_service.get_unread_count(current_user.id)
        return UnreadCount(count=count)

    @patch(operation_id="MarkNotificationRead", path="/{notification_id:uuid}/read")
    async def mark_read(
        self,
        notifications_service: NotificationService,
        current_user: m.User,
        notification_id: Annotated[
            UUID, Parameter(title="Notification ID", description="The notification to mark as read.")
        ],
    ) -> Notification:
        """Mark a notification as read.

        Args:
            notifications_service: The notification service.
            current_user: The current authenticated user.
            notification_id: The notification ID.

        Returns:
            The updated notification.
        """
        db_obj = await notifications_service.get_one_or_none(id=notification_id)
        if db_obj is None:
            raise NotFoundException(detail="Notification not found.")
        if db_obj.user_id != current_user.id:
            raise PermissionDeniedException(detail="Cannot access this notification.")
        db_obj = await notifications_service.mark_read(notification_id, current_user.id)
        return notifications_service.to_schema(db_obj, schema_type=Notification)

    @post(operation_id="MarkAllNotificationsRead", path="/mark-all-read")
    async def mark_all_read(
        self,
        notifications_service: NotificationService,
        current_user: m.User,
    ) -> UnreadCount:
        """Mark all notifications as read for the current user.

        Args:
            notifications_service: The notification service.
            current_user: The current authenticated user.

        Returns:
            The new unread count (0).
        """
        await notifications_service.mark_all_read(current_user.id)
        return UnreadCount(count=0)

    @delete(operation_id="DeleteNotification", path="/{notification_id:uuid}", return_dto=None)
    async def delete_notification(
        self,
        notifications_service: NotificationService,
        current_user: m.User,
        notification_id: Annotated[
            UUID, Parameter(title="Notification ID", description="The notification to delete.")
        ],
    ) -> None:
        """Delete a notification.

        Args:
            notifications_service: The notification service.
            current_user: The current authenticated user.
            notification_id: The notification ID.
        """
        db_obj = await notifications_service.get_one_or_none(id=notification_id)
        if db_obj is None:
            raise NotFoundException(detail="Notification not found.")
        if db_obj.user_id != current_user.id:
            raise PermissionDeniedException(detail="Cannot access this notification.")
        _ = await notifications_service.delete(notification_id)
