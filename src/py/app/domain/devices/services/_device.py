"""Device service."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class DeviceService(service.SQLAlchemyAsyncRepositoryService[m.Device]):
    """Handles CRUD operations on Device resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Device]):
        """Device Repository."""

        model_type = m.Device

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.Device]) -> ModelDictT[m.Device]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if not data.get("sip_username"):
                data["sip_username"] = f"dev_{secrets.token_hex(8)}"
            if not data.get("sip_server"):
                data["sip_server"] = "sip.default.local"
        return data

    async def update(self, data: ModelDictT[m.Device], item_id: Any | None = None, **kwargs: Any) -> m.Device:
        """Update a device.

        Returns:
            The updated device object.
        """
        return await super().update(data, item_id=item_id, **kwargs)
