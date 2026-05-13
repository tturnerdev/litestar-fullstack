from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin

_DUPLICATE_ROLE_NAME_MSG = "A role with this name already exists."

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class RoleService(AutoSlugServiceMixin[m.Role], service.SQLAlchemyAsyncRepositoryService[m.Role]):
    """Handles database operations for users."""

    class Repo(repository.SQLAlchemyAsyncSlugRepository[m.Role]):
        """User SQLAlchemy Repository."""

        model_type = m.Role

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: service.ModelDictT[m.Role]) -> service.ModelDictT[m.Role]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException(_DUPLICATE_ROLE_NAME_MSG)
        return await super().to_model_on_create(data)

    async def to_model_on_update(
        self, data: ModelDictT[m.Role], item_id: Any | None = None, **kwargs: Any
    ) -> ModelDictT[m.Role]:
        """Validate that no other role with the same name already exists."""
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException(_DUPLICATE_ROLE_NAME_MSG)
        return await super().to_model_on_update(data)
