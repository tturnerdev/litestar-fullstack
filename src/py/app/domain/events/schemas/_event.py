"""Event payload schemas."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class TaskEvent(CamelizedBaseStruct):
    """Payload for ``task.updated`` / ``task.completed`` / ``task.failed`` events."""

    task_id: UUID
    task_type: str
    status: str
    progress: int = 0
    entity_type: str | None = None
    entity_id: UUID | None = None
    result: dict[str, Any] | None = None
    error_message: str | None = None


class DeviceStatusEvent(CamelizedBaseStruct):
    """Payload for ``device.status_changed`` events."""

    device_id: UUID
    status: str
    previous_status: str
    device_name: str


class NotificationEvent(CamelizedBaseStruct):
    """Payload for ``notification.created`` events."""

    notification_id: UUID
    title: str
    category: str
    action_url: str | None = None


class EntityUpdatedEvent(CamelizedBaseStruct):
    """Payload for ``entity.updated`` events."""

    entity_type: str
    entity_id: UUID
    action: str = "updated"
