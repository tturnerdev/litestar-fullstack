"""Notification domain controllers."""

from app.domain.notifications.controllers._notification import NotificationController
from app.domain.notifications.controllers._notification_preference import NotificationPreferenceController

__all__ = ("NotificationController", "NotificationPreferenceController")
