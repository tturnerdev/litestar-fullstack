"""Notification schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import msgspec
from msgspec import Meta

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
    title: Annotated[str, Meta(min_length=1, max_length=255)]
    message: Annotated[str, Meta(min_length=1, max_length=5000)]
    category: Annotated[str, Meta(min_length=1, max_length=50)]
    action_url: Annotated[str, Meta(min_length=1, max_length=2048)] | None = None
    metadata_: dict[str, Any] | None = None


class NotificationUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a notification (mark read)."""

    is_read: bool | msgspec.UnsetType = msgspec.UNSET


class UnreadCount(CamelizedBaseStruct):
    """Unread notification count response."""

    count: int
