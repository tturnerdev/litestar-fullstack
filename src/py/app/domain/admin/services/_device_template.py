"""Device template service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from advanced_alchemy.extensions.litestar import repository, service

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

    async def to_model(
        self,
        data: ModelDictT[m.DeviceTemplate],
        operation: Optional[str] = None,
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
