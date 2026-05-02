"""Event subscriber for consuming real-time events from Redis Pub/Sub."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import msgspec

if TYPE_CHECKING:
    from uuid import UUID

    from redis.asyncio import Redis
    from redis.asyncio.client import PubSub


class EventSubscriber:
    """Subscribes to Redis Pub/Sub channels and yields events for SSE streaming.

    One instance is created per SSE connection. It subscribes to all team
    channels the authenticated user belongs to, plus the user's personal
    channel, and yields ``(event_type, data)`` tuples as they arrive.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis
        self.pubsub: PubSub | None = None

    async def subscribe(self, team_ids: list[UUID], user_id: UUID) -> None:
        """Subscribe to all relevant channels for the authenticated user.

        Args:
            team_ids: IDs of teams the user belongs to.
            user_id: The user's ID for user-scoped events.
        """
        self.pubsub = self.redis.pubsub()
        channels = [f"events:team:{tid}" for tid in team_ids]
        channels.append(f"events:user:{user_id}")
        await self.pubsub.subscribe(*channels)

    async def listen(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """Yield ``(event_type, data)`` tuples as they arrive from Redis.

        Raises:
            RuntimeError: If :meth:`subscribe` has not been called.

        Yields:
            A tuple of ``(event_type, data)`` for each received message.
        """
        if not self.pubsub:
            msg = "Must call subscribe() before listen()"
            raise RuntimeError(msg)
        async for message in self.pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                payload = msgspec.json.decode(message["data"])
                yield payload["event"], payload["data"]
            except Exception:  # noqa: BLE001
                continue

    async def unsubscribe(self) -> None:
        """Clean up the subscription and close the PubSub connection."""
        if self.pubsub:
            await self.pubsub.unsubscribe()
            await self.pubsub.close()
