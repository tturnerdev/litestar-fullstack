from __future__ import annotations

from typing import Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.domain.voice.schemas import Extension as ExtensionSchema


class ExtensionService(service.SQLAlchemyAsyncRepositoryService[m.Extension]):
    """Extension Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Extension]):
        """Extension Repository."""

        model_type = m.Extension

    repository_type = Repo

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
                pass
        except Exception:  # noqa: BLE001
            pass
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

    async def get_by_extension_number(self, extension_number: str) -> m.Extension | None:
        """Look up an extension by its extension number.

        Args:
            extension_number: The extension number to search for.

        Returns:
            The matching Extension model instance, or ``None`` if not found.
        """
        results, _ = await self.list_and_count(m.Extension.extension_number == extension_number)
        return results[0] if results else None
