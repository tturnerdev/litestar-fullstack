from __future__ import annotations

from advanced_alchemy import repository, service
from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.utils.text import slugify
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin


class TagService(AutoSlugServiceMixin[m.Tag], service.SQLAlchemyAsyncRepositoryService[m.Tag]):
    """Handles basic lookup operations for an Tag."""

    class Repo(repository.SQLAlchemyAsyncSlugRepository[m.Tag]):
        """Tag Repository."""

        model_type = m.Tag

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(
        self, data: service.ModelDictT[m.Tag]
    ) -> service.ModelDictT[m.Tag]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            slug = slugify(data["name"])
            existing = await self.repository.list(
                CollectionFilter(field_name="slug", values=[slug]),
            )
            if existing:
                raise ValidationException("A tag with this name already exists.")
        return await super().to_model_on_create(data)
