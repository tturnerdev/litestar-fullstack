"""Device service."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any, Sequence
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.domain.devices.schemas import Device as DeviceSchema

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT

    from app.domain.devices.schemas import DeviceLineAssignment as DeviceLineAssignmentSchema


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

    @staticmethod
    def _enrich_line_schema(line: m.DeviceLineAssignment, schema: DeviceLineAssignmentSchema) -> None:
        """Populate denormalized extension fields on a line assignment schema.

        Args:
            line: The DeviceLineAssignment model instance.
            schema: The corresponding schema to enrich in-place.
        """
        try:
            if line.extension is not None:
                object.__setattr__(schema, "extension_number", line.extension.extension_number)
                object.__setattr__(schema, "extension_display_name", line.extension.display_name)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _enrich_schema(db_obj: m.Device) -> dict[str, Any]:
        """Extract relationship data for schema enrichment.

        Args:
            db_obj: The Device model instance.

        Returns:
            Extra keyword arguments for schema construction.
        """
        extra: dict[str, Any] = {}
        try:
            if db_obj.location is not None:
                extra["location_name"] = db_obj.location.name
        except Exception:  # noqa: BLE001
            pass
        try:
            if db_obj.connection is not None:
                extra["connection_name"] = db_obj.connection.name
        except Exception:  # noqa: BLE001
            pass
        return extra

    def _enrich_device(self, db_obj: m.Device, schema: DeviceSchema) -> None:
        """Enrich a device schema with relationship data including line extensions.

        Args:
            db_obj: The Device model instance.
            schema: The Device schema to enrich in-place.
        """
        extra = self._enrich_schema(db_obj)
        for k, v in extra.items():
            object.__setattr__(schema, k, v)
        for line_model, line_schema in zip(db_obj.lines, schema.lines, strict=False):
            self._enrich_line_schema(line_model, line_schema)

    def to_schema_enriched(
        self,
        obj: m.Device | Sequence[m.Device],
        total: int | None = None,
        filters: Any | None = None,
    ) -> Any:
        """Convert model(s) to schema with relationship enrichment.

        Args:
            obj: Single model or sequence of models.
            total: Total count for pagination.
            filters: Filters for pagination.

        Returns:
            Schema or paginated schema response.
        """
        if isinstance(obj, m.Device):
            schema = self.to_schema(obj, schema_type=DeviceSchema)
            self._enrich_device(obj, schema)
            return schema

        if total is not None and filters is not None:
            paginated = self.to_schema(obj, total, filters, schema_type=DeviceSchema)
            for device_model, device_schema in zip(obj, paginated.items, strict=False):
                self._enrich_device(device_model, device_schema)
            return paginated

        schemas = []
        for item in obj:
            schema = self.to_schema(item, schema_type=DeviceSchema)
            self._enrich_device(item, schema)
            schemas.append(schema)
        return schemas

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
