"""Notification domain schemas."""

from app.domain.notifications.schemas._notification import (
    Notification,
    NotificationCreate,
    NotificationUpdate,
    UnreadCount,
)
from app.domain.notifications.schemas._notification_preference import (
    NotificationPreference,
    NotificationPreferenceUpdate,
)

__all__ = (
    "Notification",
    "NotificationCreate",
    "NotificationPreference",
    "NotificationPreferenceUpdate",
    "NotificationUpdate",
    "UnreadCount",
)
