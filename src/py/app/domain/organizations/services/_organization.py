"""Organization service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin

_DUPLICATE_ORG_NAME_MSG = "An organization with this name already exists."

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
            if data.get("description"):
                data["description"] = data["description"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException(_DUPLICATE_ORG_NAME_MSG)
        return await super().to_model_on_create(data)

    async def to_model_on_update(self, data: ModelDictT[m.Organization], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.Organization]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "name" in data:
                data["name"] = data["name"].strip()
                existing = await self.repository.list(
                    CollectionFilter(field_name="name", values=[data["name"]]),
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException(_DUPLICATE_ORG_NAME_MSG)
            if data.get("description"):
                data["description"] = data["description"].strip()
        return await super().to_model_on_update(data)

    async def to_model_on_upsert(self, data: ModelDictT[m.Organization]) -> ModelDictT[m.Organization]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "name" in data:
                data["name"] = data["name"].strip()
            if data.get("description"):
                data["description"] = data["description"].strip()
        return await super().to_model_on_upsert(data)
