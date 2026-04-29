"""Device service."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any
from uuid import UUID

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
        return await super().update(data, item_id=item_id, **kwargs)

    async def reboot_device(self, device_id: UUID) -> m.Device:
        return await self.update(
            item_id=device_id,
            data={"status": m.DeviceStatus.REBOOTING},
        )

    async def reprovision_device(self, device_id: UUID) -> m.Device:
        return await self.update(
            item_id=device_id,
            data={"status": m.DeviceStatus.PROVISIONING},
        )

    async def set_device_lines(
        self,
        device_id: UUID,
        lines_data: list[dict[str, Any]],
    ) -> m.Device:
        line_svc = DeviceLineAssignmentService(session=self.repository.session)
        existing = await line_svc.list(m.DeviceLineAssignment.device_id == device_id)
        for line in existing:
            await line_svc.delete(line.id)
        for line_data in lines_data:
            line_data["device_id"] = device_id
            await line_svc.create(line_data)
        return await self.get(device_id)


class DeviceLineAssignmentService(service.SQLAlchemyAsyncRepositoryService[m.DeviceLineAssignment]):

    class Repo(repository.SQLAlchemyAsyncRepository[m.DeviceLineAssignment]):
        model_type = m.DeviceLineAssignment

    repository_type = Repo
