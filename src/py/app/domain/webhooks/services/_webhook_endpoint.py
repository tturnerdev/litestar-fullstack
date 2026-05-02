"""Webhook endpoint service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class WebhookEndpointService(service.SQLAlchemyAsyncRepositoryService[m.WebhookEndpoint]):
    """Service for webhook endpoint CRUD operations."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.WebhookEndpoint]):
        """WebhookEndpoint SQLAlchemy Repository."""

        model_type = m.WebhookEndpoint

    repository_type = Repo
    match_fields = ["url"]

    async def get_active_endpoints_for_event(self, event_type: str) -> list[m.WebhookEndpoint]:
        """Get all active webhook endpoints subscribed to a specific event type.

        Args:
            event_type: The event type to filter by.

        Returns:
            List of active endpoints that subscribe to this event type.
        """
        all_active = await self.list(
            m.WebhookEndpoint.is_active.is_(True),
        )
        # Filter in Python since ARRAY contains operations vary by DB
        return [
            endpoint for endpoint in all_active
            if event_type in endpoint.events
        ]
