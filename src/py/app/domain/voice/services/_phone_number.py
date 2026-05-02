from __future__ import annotations

from typing import Any, Sequence
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import select

from app.db import models as m
from app.domain.voice.schemas import PhoneNumber as PhoneNumberSchema


class PhoneNumberService(service.SQLAlchemyAsyncRepositoryService[m.PhoneNumber]):
    """Phone Number Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.PhoneNumber]):
        """Phone Number Repository."""

        model_type = m.PhoneNumber

    repository_type = Repo

    async def get_unregistered_e911_numbers(self, team_id: UUID) -> list[m.PhoneNumber]:
        """Get active phone numbers belonging to a team that have no E911 registration.

        Args:
            team_id: The team ID to filter by.

        Returns:
            A list of PhoneNumber objects without an E911 registration.
        """
        registered_subq = (
            select(m.E911Registration.phone_number_id)
            .where(m.E911Registration.phone_number_id.isnot(None))
            .scalar_subquery()
        )
        stmt = (
            select(m.PhoneNumber)
            .where(
                m.PhoneNumber.team_id == team_id,
                m.PhoneNumber.is_active.is_(True),
                m.PhoneNumber.id.notin_(registered_subq),
            )
            .order_by(m.PhoneNumber.number)
        )
        result = await self.repository.session.execute(stmt)
        return list(result.scalars().all())

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
