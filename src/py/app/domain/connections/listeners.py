"""Connections domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.connections import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("connection_created")
async def connection_created_event_handler(connection_id: UUID) -> None:
    """Executes when a new connection is created.

    Logs the audit event.

    Args:
        connection_id: The primary key of the connection that was created.
    """
    await logger.ainfo("Running post connection creation flow.")
    async with provide_services(deps.provide_connections_service) as (service,):
        obj = await service.get_one_or_none(id=connection_id)
        if obj is None:
            await logger.aerror("Could not locate the specified connection", id=connection_id)
        else:
            await logger.ainfo(
                "Connection created",
                connection_id=str(obj.id),
                name=obj.name,
                connection_type=obj.connection_type,
                provider=obj.provider,
            )


__all__ = ("connection_created_event_handler",)
