"""Webhook delivery service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class WebhookDeliveryService(service.SQLAlchemyAsyncRepositoryService[m.WebhookDelivery]):
    """Handles CRUD operations on WebhookDelivery resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.WebhookDelivery]):
        """WebhookDelivery Repository."""

        model_type = m.WebhookDelivery

    repository_type = Repo
