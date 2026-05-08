"""Webhook service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import JSONB

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


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

    async def to_model_on_create(self, data: ModelDictT[m.Webhook]) -> ModelDictT[m.Webhook]:
        """Validate that no webhook with the same name already exists."""
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("A webhook with this name already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.Webhook], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.Webhook]:
        """Validate that no other webhook with the same name already exists."""
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
            if "name" in data:
                data["name"] = data["name"].strip()
                existing = await self.repository.list(
                    CollectionFilter(field_name="name", values=[data["name"]]),
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException("A webhook with this name already exists.")
        return data

    async def to_model_on_upsert(self, data: ModelDictT[m.Webhook]) -> ModelDictT[m.Webhook]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "name" in data:
                data["name"] = data["name"].strip()
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
        return data

    async def update(self, data: Any, item_id: Any | None = None, **kwargs: Any) -> m.Webhook:
        return await super().update(data, item_id=item_id, **kwargs)
