"""Notification domain schemas."""

from app.domain.notifications.schemas._notification import (
    Notification,
    NotificationCreate,
    NotificationUpdate,
    UnreadCount,
)

__all__ = (
    "Notification",
    "NotificationCreate",
    "NotificationUpdate",
    "UnreadCount",
)
