"""Event broadcaster for publishing real-time events to Redis Pub/Sub."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import msgspec

if TYPE_CHECKING:
    from uuid import UUID

    from redis.asyncio import Redis


class EventBroadcaster:
    """Publishes real-time events to Redis Pub/Sub channels.

    A lightweight utility (not a repository service) that any domain service
    can call to publish events. Events are sent to team-scoped or user-scoped
    Redis channels where SSE subscribers pick them up and stream them to
    connected clients.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def publish_to_team(
        self,
        team_id: UUID,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Publish an event to all members of a team.

        Args:
            team_id: The team to publish the event to.
            event_type: The SSE event name (e.g., ``task.updated``).
            data: The event payload dict (must be JSON-serializable).
        """
        channel = f"events:team:{team_id}"
        payload = {"event": event_type, "data": data}
        await self.redis.publish(channel, msgspec.json.encode(payload))

    async def publish_to_user(
        self,
        user_id: UUID,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Publish an event to a specific user.

        Args:
            user_id: The user to publish the event to.
            event_type: The SSE event name (e.g., ``notification.created``).
            data: The event payload dict (must be JSON-serializable).
        """
        channel = f"events:user:{user_id}"
        payload = {"event": event_type, "data": data}
        await self.redis.publish(channel, msgspec.json.encode(payload))

    async def publish_task_update(
        self,
        team_id: UUID,
        task_id: UUID,
        task_type: str,
        status: str,
        progress: int = 0,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        result: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        """Publish a task lifecycle event.

        Chooses the SSE event type (``task.updated``, ``task.completed``,
        ``task.failed``) based on the *status* value.

        Args:
            team_id: Team that owns the task.
            task_id: The background task ID.
            task_type: Task kind (e.g., ``device.reboot``).
            status: Current task status string.
            progress: Progress percentage (0-100).
            entity_type: Optional entity type the task operates on.
            entity_id: Optional entity ID.
            result: Optional result payload (for completed tasks).
            error_message: Optional error message (for failed tasks).
        """
        event_type = {
            "completed": "task.completed",
            "failed": "task.failed",
        }.get(status, "task.updated")
        data: dict[str, Any] = {
            "taskId": str(task_id),
            "taskType": task_type,
            "status": status,
            "progress": progress,
        }
        if entity_type:
            data["entityType"] = entity_type
        if entity_id:
            data["entityId"] = str(entity_id)
        if result:
            data["result"] = result
        if error_message:
            data["errorMessage"] = error_message
        await self.publish_to_team(team_id, event_type, data)

    async def publish_device_status_changed(
        self,
        team_id: UUID,
        device_id: UUID,
        device_name: str,
        status: str,
        previous_status: str,
    ) -> None:
        """Publish a device status change event.

        Args:
            team_id: Team that owns the device.
            device_id: The device ID.
            device_name: Human-readable device name.
            status: New device status.
            previous_status: Previous device status.
        """
        await self.publish_to_team(
            team_id,
            "device.status_changed",
            {
                "deviceId": str(device_id),
                "status": status,
                "previousStatus": previous_status,
                "deviceName": device_name,
            },
        )

    async def publish_entity_updated(
        self,
        team_id: UUID,
        entity_type: str,
        entity_id: UUID,
        action: str = "updated",
    ) -> None:
        """Publish a generic entity update event for cache invalidation.

        Args:
            team_id: Team that owns the entity.
            entity_type: Entity kind (e.g., ``device``, ``extension``).
            entity_id: The entity ID.
            action: The action performed (default ``updated``).
        """
        await self.publish_to_team(
            team_id,
            "entity.updated",
            {
                "entityType": entity_type,
                "entityId": str(entity_id),
                "action": action,
            },
        )

    async def publish_notification_created(
        self,
        user_id: UUID,
        notification_id: UUID,
        title: str,
        category: str,
        action_url: str | None = None,
    ) -> None:
        """Publish a notification creation event to a specific user.

        Args:
            user_id: The user who should receive the notification.
            notification_id: The notification ID.
            title: Notification title.
            category: Notification category (e.g., ``device``, ``voicemail``).
            action_url: Optional URL for the notification action.
        """
        await self.publish_to_user(
            user_id,
            "notification.created",
            {
                "notificationId": str(notification_id),
                "title": title,
                "category": category,
                "actionUrl": action_url,
            },
        )
