"""Notification domain dependencies."""

from __future__ import annotations

from app.domain.notifications.services import NotificationPreferenceService, NotificationService
from app.lib.deps import create_service_provider

provide_notifications_service = create_service_provider(
    NotificationService,
    error_messages={
        "duplicate_key": "This notification already exists.",
        "integrity": "Notification operation failed.",
    },
)

provide_notification_preference_service = create_service_provider(
    NotificationPreferenceService,
    error_messages={
        "duplicate_key": "Notification preference already exists for this user.",
        "integrity": "Notification preference operation failed.",
    },
)

__all__ = ("provide_notification_preference_service", "provide_notifications_service")
