"""Time condition service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class TimeConditionService(service.SQLAlchemyAsyncRepositoryService[m.TimeCondition]):
    """Handles CRUD operations on TimeCondition resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TimeCondition]):
        """TimeCondition Repository."""

        model_type = m.TimeCondition

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.TimeCondition]) -> ModelDictT[m.TimeCondition]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("A time condition with this name already exists.")
        return data
