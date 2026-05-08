"""Music on Hold service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service.typing import ModelDictT


class MusicOnHoldService(service.SQLAlchemyAsyncRepositoryService[m.MusicOnHold]):
    """Handles CRUD operations on MusicOnHold resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.MusicOnHold]):
        """MusicOnHold Repository."""

        model_type = m.MusicOnHold

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.MusicOnHold]) -> ModelDictT[m.MusicOnHold]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("A music on hold entry with this name already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.MusicOnHold], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.MusicOnHold]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("A music on hold entry with this name already exists.")
        return data

    async def get_default(self) -> m.MusicOnHold | None:
        """Get the default Music on Hold class.

        Returns:
            The default MusicOnHold or None if no default is set.
        """
        results = await self.list(
            m.MusicOnHold.is_default.is_(True),
            m.MusicOnHold.is_active.is_(True),
        )
        return results[0] if results else None
