"""Notification Preference Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar import Controller, get, patch
from litestar.di import Provide

from app.domain.notifications.deps import provide_notification_preference_service
from app.domain.notifications.schemas import NotificationPreference, NotificationPreferenceUpdate

if TYPE_CHECKING:
    from app.db import models as m
    from app.domain.notifications.services import NotificationPreferenceService

logger = structlog.get_logger()


class NotificationPreferenceController(Controller):
    """Handles notification preference operations for the current user."""

    tags = ["Notifications"]
    path = "/api/notifications/preferences"
    dependencies = {
        "notification_preference_service": Provide(provide_notification_preference_service),
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
        notification_preference_service: NotificationPreferenceService,
        current_user: m.User,
        data: NotificationPreferenceUpdate,
    ) -> NotificationPreference:
        """Update the current user's notification preferences.

        Args:
            notification_preference_service: The notification preference service.
            current_user: The current user.
            data: The update data.

        Returns:
            The updated notification preference record.
        """
        db_obj = await notification_preference_service.update_for_user(
            user_id=current_user.id,
            data=data.to_dict(),
        )
        return notification_preference_service.to_schema(db_obj, schema_type=NotificationPreference)
