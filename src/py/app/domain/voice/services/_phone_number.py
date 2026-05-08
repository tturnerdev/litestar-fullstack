from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException
from sqlalchemy import select

from app.db import models as m
from app.domain.voice.schemas import PhoneNumber as PhoneNumberSchema

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT

logger = logging.getLogger(__name__)


class PhoneNumberService(service.SQLAlchemyAsyncRepositoryService[m.PhoneNumber]):
    """Phone Number Service.

    Consolidated service for all phone number operations including CRUD,
    bulk import, E911 lookups, and schema enrichment.
    """

    class Repo(repository.SQLAlchemyAsyncRepository[m.PhoneNumber]):
        """Phone Number Repository."""

        model_type = m.PhoneNumber

    repository_type = Repo
    match_fields = ["number"]

    async def to_model_on_create(self, data: ModelDictT[m.PhoneNumber]) -> ModelDictT[m.PhoneNumber]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                CollectionFilter(field_name="number", values=[data["number"]]),
            )
            if existing:
                raise ValidationException("A phone number with this number already exists.")
        return data

    async def check_duplicates(self, numbers: list[str]) -> set[str]:
        """Check which phone numbers already exist in the database.

        Args:
            numbers: List of E.164 phone numbers to check.

        Returns:
            Set of numbers that already exist.
        """
        if not numbers:
            return set()
        existing = await self.list(m.PhoneNumber.number.in_(numbers))
        return {pn.number for pn in existing}

    async def bulk_create(self, items: list[dict[str, Any]]) -> list[m.PhoneNumber]:
        """Create multiple phone numbers in a single operation.

        Args:
            items: List of dicts with phone number field data.

        Returns:
            List of created PhoneNumber model instances.
        """
        return list(await self.create_many(items, auto_commit=True))

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
            logger.warning("Failed to load e911_registration relationship on phone number", exc_info=True)
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
