"""IVR menu service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class IvrMenuService(service.SQLAlchemyAsyncRepositoryService[m.IvrMenu]):
    """Handles CRUD operations on IvrMenu resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.IvrMenu]):
        """IvrMenu Repository."""

        model_type = m.IvrMenu

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.IvrMenu]) -> ModelDictT[m.IvrMenu]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("An IVR menu with this name already exists.")
        return data

    async def to_model_on_upsert(self, data: ModelDictT[m.IvrMenu]) -> ModelDictT[m.IvrMenu]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
        return data

    async def to_model_on_update(self, data: ModelDictT[m.IvrMenu], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.IvrMenu]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("An IVR menu with this name already exists.")
        return data


class IvrMenuOptionService(service.SQLAlchemyAsyncRepositoryService[m.IvrMenuOption]):
    """Handles CRUD operations on IvrMenuOption resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.IvrMenuOption]):
        """IvrMenuOption Repository."""

        model_type = m.IvrMenuOption

    repository_type = Repo
    match_fields = ["ivr_menu_id", "digit"]

    async def to_model_on_create(self, data: ModelDictT[m.IvrMenuOption]) -> ModelDictT[m.IvrMenuOption]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["digit"] = data["digit"].strip()
            existing = await self.repository.list(
                m.IvrMenuOption.ivr_menu_id == data["ivr_menu_id"],
                m.IvrMenuOption.digit == data["digit"],
            )
            if existing:
                raise ValidationException("This digit is already assigned in this IVR menu.")
        return data

    async def to_model_on_upsert(self, data: ModelDictT[m.IvrMenuOption]) -> ModelDictT[m.IvrMenuOption]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "digit" in data:
            data["digit"] = data["digit"].strip()
        return data

    async def to_model_on_update(self, data: ModelDictT[m.IvrMenuOption], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.IvrMenuOption]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "digit" in data:
            data["digit"] = data["digit"].strip()
            ivr_menu_id = data.get("ivr_menu_id")
            if ivr_menu_id:
                existing = await self.repository.list(
                    m.IvrMenuOption.ivr_menu_id == ivr_menu_id,
                    m.IvrMenuOption.digit == data["digit"],
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException("This digit is already assigned in this IVR menu.")
        return data
