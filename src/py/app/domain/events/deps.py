"""Events domain dependencies."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from redis.asyncio import Redis

from app.domain.events.services import EventBroadcaster, EventSubscriber
from app.lib.settings import get_settings


async def provide_event_broadcaster() -> AsyncGenerator[EventBroadcaster, None]:
    """Provide an ``EventBroadcaster`` instance backed by Redis.

    Uses the same Redis URL configured for SAQ so no additional
    infrastructure is required.

    Yields:
        An ``EventBroadcaster`` that publishes to Redis Pub/Sub.
    """
    settings = get_settings()
    redis = Redis.from_url(settings.saq.REDIS_URL)
    try:
        yield EventBroadcaster(redis)
    finally:
        await redis.aclose()


async def provide_event_subscriber() -> AsyncGenerator[EventSubscriber, None]:
    """Provide an ``EventSubscriber`` instance backed by Redis.

    Each SSE connection gets its own subscriber with a dedicated Redis
    connection for Pub/Sub listening.

    Yields:
        An ``EventSubscriber`` for consuming Redis Pub/Sub messages.
    """
    settings = get_settings()
    redis = Redis.from_url(settings.saq.REDIS_URL)
    try:
        yield EventSubscriber(redis)
    finally:
        await redis.aclose()


__all__ = (
    "provide_event_broadcaster",
    "provide_event_subscriber",
)
