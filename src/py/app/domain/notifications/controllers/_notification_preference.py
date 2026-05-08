"""Notification Preference Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import Controller, Request, get, patch
from litestar.di import Provide

from app.db import models as m
from app.domain.accounts.guards import requires_active_user
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notification_preference_service
from app.domain.notifications.schemas import NotificationPreference, NotificationPreferenceUpdate
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationPreferenceService


class NotificationPreferenceController(Controller):
    """Handles notification preference operations for the current user."""

    tags = ["Notifications"]
    path = "/api/notifications/preferences"
    guards = [requires_active_user]
    dependencies = {
        "notification_preference_service": Provide(provide_notification_preference_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="GetNotificationPreferences",
        summary="Get notification preferences",
        description="Get the current user's notification preferences.",
    )
    async def get_preferences(
        self,
        notification_preference_service: NotificationPreferenceService,
        current_user: m.User,
    ) -> NotificationPreference:
        """Get the current user's notification preferences.

        Returns:
            The notification preference record.
        """
        db_obj = await notification_preference_service.get_or_create_for_user(current_user.id)
        return notification_preference_service.to_schema(db_obj, schema_type=NotificationPreference)

    @patch(
        operation_id="UpdateNotificationPreferences",
        summary="Update notification preferences",
        description="Update the current user's notification preferences.",
    )
    async def update_preferences(
        self,
        request: Request[m.User, Any, Any],
        notification_preference_service: NotificationPreferenceService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: NotificationPreferenceUpdate,
    ) -> NotificationPreference:
        """Update the current user's notification preferences.

        Args:
            request: The current request.
            notification_preference_service: The notification preference service.
            audit_service: Audit Log Service.
            current_user: The current user.
            data: The update data.

        Returns:
            The updated notification preference record.
        """
        existing = await notification_preference_service.get_or_create_for_user(current_user.id)
        before = capture_snapshot(existing)
        db_obj = await notification_preference_service.update_for_user(
            user_id=current_user.id,
            data=data.to_dict(),
        )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="notification_preference.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="notification_preference",
            target_id=db_obj.id,
            target_label=current_user.email,
            before=before,
            after=after,
            request=request,
        )
        return notification_preference_service.to_schema(db_obj, schema_type=NotificationPreference)
