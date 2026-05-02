"""Notification Controllers."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import NotFoundException, PermissionDeniedException
from litestar.params import Dependency, Parameter
from litestar.response import Response
from sqlalchemy import inspect as sa_inspect

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.schemas import Notification, NotificationUpdate, UnreadCount
from app.domain.notifications.services import NotificationService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.domain.admin.services import AuditLogService

_SNAPSHOT_EXCLUDE: frozenset[str] = frozenset(
    {"id", "sa_orm_sentinel", "created_at", "updated_at", "hashed_password", "totp_secret", "backup_codes"}
)


def _capture_snapshot(obj: Any) -> dict[str, Any]:
    """Serialize a SQLAlchemy model instance to a plain dict for audit details."""
    mapper = sa_inspect(type(obj))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        key = col.key
        if key in _SNAPSHOT_EXCLUDE:
            continue
        try:
            value = getattr(obj, key)
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, (datetime, date)):
            value = value.isoformat()
        result[key] = value
    return result


async def _log_audit(
    audit_service: AuditLogService,
    *,
    action: str,
    actor: m.User,
    target_type: str,
    target_id: UUID,
    target_label: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request: Request[Any, Any, Any] | None = None,
) -> None:
    """Write an audit log entry with optional before/after diff."""
    details: dict[str, Any] = {}
    if before is not None or after is not None:
        if before is None:
            details = {"before": None, "after": after}
        elif after is None:
            details = {"before": before, "after": None}
        else:
            changed_before: dict[str, Any] = {}
            changed_after: dict[str, Any] = {}
            for key in set(before) | set(after):
                if before.get(key) != after.get(key):
                    changed_before[key] = before.get(key)
                    changed_after[key] = after.get(key)
            if changed_before or changed_after:
                details = {"before": changed_before, "after": changed_after}

    await audit_service.log_action(
        action=action,
        actor_id=actor.id,
        actor_email=actor.email,
        actor_name=actor.name,
        target_type=target_type,
        target_id=str(target_id),
        target_label=target_label,
        details=details or None,
        request=request,
    )


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
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

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
        await _log_audit(
            audit_service,
            action="notification.all_marked_read",
            actor=current_user,
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
        await notifications_service.delete_read(current_user.id)
        await _log_audit(
            audit_service,
            action="notification.bulk_deleted_read",
            actor=current_user,
            target_type="notification",
            target_id=current_user.id,
            target_label="read",
            request=request,
        )

    @delete(operation_id="DeleteNotification", path="/{notification_id:uuid}", return_dto=None)
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
        before = _capture_snapshot(db_obj)
        target_label = db_obj.title
        _ = await notifications_service.delete(notification_id)
        await _log_audit(
            audit_service,
            action="notification.deleted",
            actor=current_user,
            target_type="notification",
            target_id=notification_id,
            target_label=target_label,
            before=before,
            request=request,
        )
