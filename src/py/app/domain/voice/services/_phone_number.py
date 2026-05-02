from __future__ import annotations

from typing import Any, Sequence

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.domain.voice.schemas import PhoneNumber as PhoneNumberSchema


class PhoneNumberService(service.SQLAlchemyAsyncRepositoryService[m.PhoneNumber]):
    """Phone Number Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.PhoneNumber]):
        """Phone Number Repository."""

        model_type = m.PhoneNumber

    repository_type = Repo

    @staticmethod
    def _enrich_schema(db_obj: m.PhoneNumber) -> dict[str, Any]:
        """Extract relationship data for schema enrichment.

        Args:
            db_obj: The PhoneNumber model instance.

        Returns:
            Extra keyword arguments for schema construction.
        """
        extra: dict[str, Any] = {}
        try:
            if db_obj.e911_registration is not None:
                extra["e911_registered"] = True
                extra["e911_registration_id"] = db_obj.e911_registration.id
        except Exception:  # noqa: BLE001
            pass
        return extra

    def to_schema_enriched(
        self,
        obj: m.PhoneNumber | Sequence[m.PhoneNumber],
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
        if isinstance(obj, m.PhoneNumber):
            schema = self.to_schema(obj, schema_type=PhoneNumberSchema)
            extra = self._enrich_schema(obj)
            for k, v in extra.items():
                object.__setattr__(schema, k, v)
            return schema

        if total is not None and filters is not None:
            paginated = self.to_schema(obj, total, filters, schema_type=PhoneNumberSchema)
            for phone_model, phone_schema in zip(obj, paginated.items, strict=False):
                extra = self._enrich_schema(phone_model)
                for k, v in extra.items():
                    object.__setattr__(phone_schema, k, v)
            return paginated

        schemas = []
        for item in obj:
            schema = self.to_schema(item, schema_type=PhoneNumberSchema)
            extra = self._enrich_schema(item)
            for k, v in extra.items():
                object.__setattr__(schema, k, v)
            schemas.append(schema)
        return schemas
