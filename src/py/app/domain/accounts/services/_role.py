from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin


class RoleService(AutoSlugServiceMixin[m.Role], service.SQLAlchemyAsyncRepositoryService[m.Role]):
    """Handles database operations for users."""

    class Repo(repository.SQLAlchemyAsyncSlugRepository[m.Role]):
        """User SQLAlchemy Repository."""

        model_type = m.Role

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(
        self, data: service.ModelDictT[m.Role]
    ) -> service.ModelDictT[m.Role]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("A role with this name already exists.")
        return await super().to_model_on_create(data)
