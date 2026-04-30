"""Gateway domain dependencies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.domain.connections.services import ConnectionService

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


__all__ = ("provide_gateway_connections",)
