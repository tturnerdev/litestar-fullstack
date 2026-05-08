from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class FaxNumberService(service.SQLAlchemyAsyncRepositoryService[m.FaxNumber]):
    """Handles CRUD operations on FaxNumber resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.FaxNumber]):
        """FaxNumber Repository."""

        model_type = m.FaxNumber

    repository_type = Repo
    match_fields = ["number"]

    async def to_model_on_create(self, data: ModelDictT[m.FaxNumber]) -> ModelDictT[m.FaxNumber]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["number"] = data["number"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="number", values=[data["number"]]),
            )
            if existing:
                raise ValidationException("A fax number with this number already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.FaxNumber], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.FaxNumber]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "number" in data:
            data["number"] = data["number"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="number", values=[data["number"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("A fax number with this number already exists.")
        return data
