"""E911 Registration service."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Sequence
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import select

from app.db import models as m
from app.domain.e911.schemas import E911Registration as E911RegistrationSchema


class E911RegistrationService(service.SQLAlchemyAsyncRepositoryService[m.E911Registration]):
    """Handles CRUD operations on E911Registration resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.E911Registration]):
        """E911Registration Repository."""

        model_type = m.E911Registration

    repository_type = Repo
    match_fields = ["phone_number_id"]

    @staticmethod
    def _enrich_schema(db_obj: m.E911Registration) -> dict[str, Any]:
        """Extract relationship data for schema enrichment.

        Args:
            db_obj: The E911Registration model instance.

        Returns:
            Extra keyword arguments for schema construction.
        """
        extra: dict[str, Any] = {}
        try:
            if db_obj.phone_number is not None:
                extra["phone_number_display"] = db_obj.phone_number.number
                extra["phone_number_label"] = db_obj.phone_number.label
        except Exception:  # noqa: BLE001
            pass
        try:
            if db_obj.location is not None:
                extra["location_name"] = db_obj.location.name
        except Exception:  # noqa: BLE001
            pass
        return extra

    def to_schema_enriched(
        self,
        obj: m.E911Registration | Sequence[m.E911Registration],
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
        if isinstance(obj, m.E911Registration):
            schema = self.to_schema(obj, schema_type=E911RegistrationSchema)
            extra = self._enrich_schema(obj)
            for k, v in extra.items():
                object.__setattr__(schema, k, v)
            return schema

        schemas = []
        for item in obj:
            schema = self.to_schema(item, schema_type=E911RegistrationSchema)
            extra = self._enrich_schema(item)
            for k, v in extra.items():
                object.__setattr__(schema, k, v)
            schemas.append(schema)

        if total is not None and filters is not None:
            return self.to_schema(obj, total, filters, schema_type=E911RegistrationSchema)

        return schemas

    async def validate_registration(self, item_id: UUID) -> m.E911Registration:
        """Mark an E911 registration as validated.

        In production this would call a carrier API for address validation.
        For now it simply sets the validated flag and timestamp.

        Args:
            item_id: The registration ID.

        Returns:
            The updated registration.
        """
        return await self.update(
            data={
                "validated": True,
                "validated_at": datetime.now(UTC),
            },
            item_id=item_id,
        )

    async def get_unregistered_numbers(self, team_id: UUID) -> list[m.PhoneNumber]:
        """Get phone numbers belonging to a team that have no E911 registration.

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

    async def update(self, data: Any, item_id: Any | None = None, **kwargs: Any) -> m.E911Registration:
        """Update an E911 registration.

        Returns:
            The updated registration object.
        """
        return await super().update(data, item_id=item_id, **kwargs)
