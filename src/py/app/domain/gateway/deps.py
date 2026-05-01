"""Gateway domain dependencies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redis.asyncio import Redis

from app.domain.connections.services import ConnectionService
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db import models as m


async def provide_gateway_connections(db_session: AsyncSession) -> list[m.Connection]:
    """Load all connections for gateway fan-out queries.

    This provides the raw list of ``Connection`` rows.  The gateway
    service filters by ``is_enabled`` and provider support at query time.

    Args:
        db_session: The current database session.

    Returns:
        A list of all Connection model instances.
    """
    svc = ConnectionService(session=db_session)
    results, _ = await svc.list_and_count()
    return list(results)


async def provide_gateway_redis() -> Redis:
    """Provide a Redis client for gateway response caching.

    Uses the same Redis URL configured for SAQ so no additional
    infrastructure is required.

    Returns:
        An async Redis client instance.
    """
    settings = get_settings()
    return Redis.from_url(settings.saq.REDIS_URL, decode_responses=False)


__all__ = ("provide_gateway_connections", "provide_gateway_redis")
