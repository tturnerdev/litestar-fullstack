"""Device template service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service.typing import ModelDictT


class DeviceTemplateService(service.SQLAlchemyAsyncRepositoryService[m.DeviceTemplate]):
    """Handles CRUD operations on DeviceTemplate resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.DeviceTemplate]):
        """DeviceTemplate Repository."""

        model_type = m.DeviceTemplate

    repository_type = Repo
    match_fields = ["manufacturer", "model"]

    async def to_model_on_create(self, data: ModelDictT[m.DeviceTemplate]) -> ModelDictT[m.DeviceTemplate]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.DeviceTemplate.manufacturer == data["manufacturer"],
                m.DeviceTemplate.model == data["model"],
            )
            if existing:
                raise ValidationException("A device template for this manufacturer and model already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.DeviceTemplate], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.DeviceTemplate]:
        data = service.schema_dump(data)
        if service.is_dict(data) and ("manufacturer" in data or "model" in data):
            existing = await self.repository.list(
                m.DeviceTemplate.manufacturer == data["manufacturer"],
                m.DeviceTemplate.model == data["model"],
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("A device template for this manufacturer and model already exists.")
        return data

    async def to_model(
        self,
        data: ModelDictT[m.DeviceTemplate],
        operation: str | None = None,
    ) -> m.DeviceTemplate:
        # DeviceTemplate has a column named "model" which collides with
        # model_from_dict(model=..., **data).  Construct directly when dict.
        if isinstance(data, dict):
            return self.model_type(**data)
        return await super().to_model(data, operation)

    async def get_by_manufacturer_model(
        self,
        manufacturer: str,
        model: str,
    ) -> m.DeviceTemplate | None:
        """Look up a template by manufacturer and model.

        Args:
            manufacturer: Device manufacturer name.
            model: Device model name.

        Returns:
            The matching DeviceTemplate or None.
        """
        results = await self.list(
            m.DeviceTemplate.manufacturer.ilike(manufacturer),
            m.DeviceTemplate.model.ilike(model),
            m.DeviceTemplate.is_active.is_(True),
        )
        return results[0] if results else None
