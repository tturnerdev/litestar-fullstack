"""Webhook service."""

from __future__ import annotations

from typing import Any

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import JSONB

from app.db import models as m


class WebhookService(service.SQLAlchemyAsyncRepositoryService[m.Webhook]):
    """Handles CRUD operations on Webhook resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Webhook]):
        """Webhook Repository."""

        model_type = m.Webhook

    repository_type = Repo
    match_fields = ["name"]

    async def get_active_for_event(self, event: str) -> list[m.Webhook]:
        """Return all active webhooks that subscribe to a given event.

        Args:
            event: The event name to filter by (e.g. "device.created").

        Returns:
            A list of active Webhook instances that include the event.
        """
        results = await self.list(
            m.Webhook.is_active == True,  # noqa: E712
            cast(m.Webhook.events, JSONB).op("@>")(cast([event], JSONB)),
        )
        return list(results)

    async def update(self, data: Any, item_id: Any | None = None, **kwargs: Any) -> m.Webhook:
        return await super().update(data, item_id=item_id, **kwargs)
