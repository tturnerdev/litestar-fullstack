from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException
from sqlalchemy import select

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT

logger = logging.getLogger(__name__)
from app.domain.voice.schemas import Extension as ExtensionSchema
from app.domain.voice.schemas import ExtensionDeviceSummary


class ExtensionService(service.SQLAlchemyAsyncRepositoryService[m.Extension]):
    """Extension Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Extension]):
        """Extension Repository."""

        model_type = m.Extension

    repository_type = Repo

    async def to_model_on_create(self, data: ModelDictT[m.Extension]) -> ModelDictT[m.Extension]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["extension_number"] = data["extension_number"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="extension_number", values=[data["extension_number"]]),
            )
            if existing:
                raise ValidationException("An extension with this extension number already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.Extension], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.Extension]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "extension_number" in data:
            data["extension_number"] = data["extension_number"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="extension_number", values=[data["extension_number"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("An extension with this extension number already exists.")
        return data

    @staticmethod
    def _enrich_schema(db_obj: m.Extension) -> dict[str, Any]:
        """Extract E911 status from loaded phone_number relationship.

        Args:
            db_obj: The Extension model instance.

        Returns:
            Extra keyword arguments for schema construction.
        """
        extra: dict[str, Any] = {}
        try:
            phone = db_obj.phone_number
            if phone is None:
                extra["e911_status"] = "no_phone_number"
                return extra
            try:
                e911 = phone.e911_registration
                if e911 is not None:
                    extra["e911_status"] = "registered"
                    extra["e911_registration_id"] = e911.id
                else:
                    extra["e911_status"] = "unregistered"
            except Exception:  # noqa: BLE001
                logger.warning("Failed to load e911_registration for phone_number on extension", exc_info=True)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to load phone_number relationship on extension", exc_info=True)
        return extra

    def to_schema_enriched(self, obj: m.Extension) -> ExtensionSchema:
        """Convert a single Extension model to schema with E911 enrichment.

        Args:
            obj: The Extension model instance.

        Returns:
            Enriched Extension schema.
        """
        schema = self.to_schema(obj, schema_type=ExtensionSchema)
        extra = self._enrich_schema(obj)
        for k, v in extra.items():
            object.__setattr__(schema, k, v)
        return schema

    async def get_assigned_devices(self, extension_id: UUID) -> list[ExtensionDeviceSummary]:
        """Return devices that have this extension assigned to a line.

        Args:
            extension_id: The extension UUID to look up assignments for.

        Returns:
            A list of ``ExtensionDeviceSummary`` schemas.
        """
        stmt = (
            select(
                m.Device.id,
                m.Device.name,
                m.Device.device_model,
                m.Device.device_type,
                m.Device.status,
                m.DeviceLineAssignment.line_number,
                m.DeviceLineAssignment.label,
                m.DeviceLineAssignment.id.label("line_id"),
            )
            .join(m.DeviceLineAssignment, m.DeviceLineAssignment.device_id == m.Device.id)
            .where(m.DeviceLineAssignment.extension_id == extension_id)
            .order_by(m.Device.name, m.DeviceLineAssignment.line_number)
        )
        result = await self.repository.session.execute(stmt)
        return [
            ExtensionDeviceSummary(
                device_id=row.id,
                device_name=row.name,
                device_model=row.device_model,
                device_type=row.device_type,
                status=row.status,
                line_number=row.line_number,
                line_label=row.label,
                line_id=row.line_id,
            )
            for row in result.all()
        ]

    async def get_by_extension_number(self, extension_number: str) -> m.Extension | None:
        """Look up an extension by its extension number.

        Args:
            extension_number: The extension number to search for.

        Returns:
            The matching Extension model instance, or ``None`` if not found.
        """
        results, _ = await self.list_and_count(m.Extension.extension_number == extension_number)
        return results[0] if results else None
