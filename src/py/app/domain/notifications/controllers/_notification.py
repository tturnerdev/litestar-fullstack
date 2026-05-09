"""Notification Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import NotFoundException, PermissionDeniedException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.accounts.guards import requires_active_user
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.schemas import Notification, UnreadCount
from app.domain.notifications.services import NotificationService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.domain.admin.services import AuditLogService


class NotificationController(Controller):
    """Notifications."""

    tags = ["Notifications"]
    path = "/api/notifications"
    guards = [requires_active_user]
    dependencies = create_service_dependencies(
        NotificationService,
        key="notifications_service",
        filters={
            "search": "title",
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListNotifications",
        summary="List notifications",
        description="Retrieve a paginated list of notifications for the current user. Supports search by title, date range filtering, and sorting.",
    )
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

    @get(
        operation_id="GetUnreadNotificationCount",
        summary="Get unread notification count",
        description="Return the total number of unread notifications for the current user.",
        path="/unread-count",
    )
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

    @patch(
        operation_id="MarkNotificationRead",
        summary="Mark a notification as read",
        description="Mark a single notification as read for the current user. Returns 403 if the notification belongs to a different user.",
        path="/{notification_id:uuid}/read",
    )
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

    @post(
        operation_id="MarkAllNotificationsRead",
        summary="Mark all notifications as read",
        description="Mark every unread notification as read for the current user. Logs an audit entry and returns the new unread count of zero.",
        path="/mark-all-read",
    )
    async def mark_all_read(
        self,
        request: Request[m.User, Any, Any],
        notifications_service: NotificationService,
        audit_service: AuditLogService,
        current_user: m.User,
    ) -> UnreadCount:
        """Mark all notifications as read for the current user.

        Args:
            request: The current request.
            notifications_service: The notification service.
            audit_service: Audit Log Service.
            current_user: The current authenticated user.

        Returns:
            The new unread count (0).
        """
        await notifications_service.mark_all_read(current_user.id)
        await log_audit(
            audit_service,
            action="notification.all_marked_read",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="notification",
            target_id=current_user.id,
            target_label="all",
            request=request,
        )
        return UnreadCount(count=0)

    @delete(
        operation_id="DeleteReadNotifications",
        path="/read",
        summary="Delete all read notifications",
        description="Permanently delete all read notifications for the current user.",
        return_dto=None,
        status_code=204,
    )
    async def delete_read_notifications(
        self,
        request: Request[m.User, Any, Any],
        notifications_service: NotificationService,
        audit_service: AuditLogService,
        current_user: m.User,
    ) -> None:
        request.app.emit(event_id="notifications_bulk_deleted")
        await notifications_service.delete_read(current_user.id)
        await log_audit(
            audit_service,
            action="notification.bulk_deleted_read",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="notification",
            target_id=current_user.id,
            target_label="read",
            request=request,
        )

    @delete(
        operation_id="DeleteNotification",
        summary="Delete a notification",
        description="Permanently delete a single notification. Emits a notification_deleted event and logs an audit entry with the before-state snapshot.",
        path="/{notification_id:uuid}",
        return_dto=None,
        status_code=HTTP_204_NO_CONTENT,
    )
    async def delete_notification(
        self,
        request: Request[m.User, Any, Any],
        notifications_service: NotificationService,
        audit_service: AuditLogService,
        current_user: m.User,
        notification_id: Annotated[
            UUID, Parameter(title="Notification ID", description="The notification to delete.")
        ],
    ) -> None:
        """Delete a notification.

        Args:
            request: The current request.
            notifications_service: The notification service.
            audit_service: Audit Log Service.
            current_user: The current authenticated user.
            notification_id: The notification ID.
        """
        db_obj = await notifications_service.get_one_or_none(id=notification_id)
        if db_obj is None:
            raise NotFoundException(detail="Notification not found.")
        if db_obj.user_id != current_user.id:
            raise PermissionDeniedException(detail="Cannot access this notification.")
        before = capture_snapshot(db_obj)
        target_label = db_obj.title
        request.app.emit(event_id="notification_deleted", notification_id=notification_id)
        _ = await notifications_service.delete(notification_id)
        await log_audit(
            audit_service,
            action="notification.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="notification",
            target_id=notification_id,
            target_label=target_label,
            before=before,
            request=request,
        )
