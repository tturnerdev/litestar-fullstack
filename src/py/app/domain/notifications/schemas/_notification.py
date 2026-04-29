"""Notification schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class Notification(CamelizedBaseStruct):
    """Notification list/detail schema."""

    id: UUID
    user_id: UUID
    title: str
    message: str
    category: str
    is_read: bool
    created_at: datetime
    updated_at: datetime
    action_url: str | None = None
    metadata_: dict[str, Any] | None = None


class NotificationCreate(CamelizedBaseStruct):
    """Schema for creating a notification (internal use)."""

    user_id: UUID
    title: str
    message: str
    category: str
    action_url: str | None = None
    metadata_: dict[str, Any] | None = None


class NotificationUpdate(CamelizedBaseStruct):
    """Schema for updating a notification (mark read)."""

    is_read: bool | msgspec.UnsetType = msgspec.UNSET


class UnreadCount(CamelizedBaseStruct):
    """Unread notification count response."""

    count: int
