"""Organization service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin

if TYPE_CHECKING:
    from advanced_alchemy.service.typing import ModelDictT


class OrganizationService(
    AutoSlugServiceMixin[m.Organization],
    service.SQLAlchemyAsyncRepositoryService[m.Organization],
):
    """Handles database operations for Organization resources."""

    class Repo(repository.SQLAlchemyAsyncSlugRepository[m.Organization]):
        """Organization Repository."""

        model_type = m.Organization

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.Organization]) -> ModelDictT[m.Organization]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("An organization with this name already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.Organization], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.Organization]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "name" in data:
                data["name"] = data["name"].strip()
                existing = await self.repository.list(
                    CollectionFilter(field_name="name", values=[data["name"]]),
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException("An organization with this name already exists.")
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
        return data

    async def to_model_on_upsert(self, data: ModelDictT[m.Organization]) -> ModelDictT[m.Organization]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "name" in data:
                data["name"] = data["name"].strip()
            if "description" in data and data["description"]:
                data["description"] = data["description"].strip()
        return data
