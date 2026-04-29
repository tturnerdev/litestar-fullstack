"""Notification domain dependencies."""

from __future__ import annotations

from app.domain.notifications.services import NotificationService
from app.lib.deps import create_service_provider

provide_notifications_service = create_service_provider(
    NotificationService,
    error_messages={
        "duplicate_key": "This notification already exists.",
        "integrity": "Notification operation failed.",
    },
)

__all__ = ("provide_notifications_service",)
