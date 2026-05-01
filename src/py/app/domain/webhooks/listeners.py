"""Webhook domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.webhooks import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID


logger = structlog.get_logger()


@listener("webhook_created")
async def webhook_created_event_handler(webhook_id: UUID) -> None:
    """Executes when a new webhook is created.

    Args:
        webhook_id: The primary key of the webhook that was created.
    """
    await logger.ainfo("Running post webhook creation flow.")
    async with provide_services(deps.provide_webhooks_service) as (service,):
        obj = await service.get_one_or_none(id=webhook_id)
        if obj is None:
            await logger.aerror("Could not locate the specified webhook", id=webhook_id)
        else:
            await logger.ainfo("Webhook created", webhook_id=str(obj.id), name=obj.name, url=obj.url)


__all__ = ("webhook_created_event_handler",)
