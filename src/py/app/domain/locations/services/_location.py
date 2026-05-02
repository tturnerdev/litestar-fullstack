"""Location service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Sequence
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import func, select

from app.db import models as m
from app.domain.locations.schemas import Location as LocationSchema

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class LocationService(service.SQLAlchemyAsyncRepositoryService[m.Location]):
    """Handles CRUD operations on Location resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Location]):
        """Location Repository."""

        model_type = m.Location

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.Location]) -> ModelDictT[m.Location]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            location_type = data.get("location_type", m.LocationType.ADDRESSED)
            # Clear address fields for PHYSICAL type locations
            if location_type == m.LocationType.PHYSICAL:
                for field in ("address_line_1", "address_line_2", "city", "state", "postal_code", "country"):
                    data.pop(field, None)
            # Ensure PHYSICAL locations have a parent_id
            if location_type == m.LocationType.PHYSICAL and not data.get("parent_id"):
                msg = "Physical locations must have a parent_id."
                raise ValueError(msg)
            # Ensure ADDRESSED locations do not have a parent_id
            if location_type == m.LocationType.ADDRESSED:
                data.pop("parent_id", None)
        return data

    async def update(self, data: ModelDictT[m.Location], item_id: Any | None = None, **kwargs: Any) -> m.Location:
        """Update a location.

        Returns:
            The updated location object.
        """
        return await super().update(data, item_id=item_id, **kwargs)

    async def get_device_count(self, location_id: UUID) -> int:
        """Get the number of devices assigned to a location.

        Args:
            location_id: Location ID

        Returns:
            Number of devices at this location.
        """
        result = await self.repository.session.execute(
            select(func.count(m.Device.id)).where(m.Device.location_id == location_id),
        )
        return result.scalar_one()

    async def get_device_counts(self, location_ids: Sequence[UUID]) -> dict[UUID, int]:
        """Get device counts for multiple locations in a single query.

        Args:
            location_ids: Sequence of location IDs.

        Returns:
            Mapping of location_id to device count.
        """
        if not location_ids:
            return {}
        result = await self.repository.session.execute(
            select(m.Device.location_id, func.count(m.Device.id))
            .where(m.Device.location_id.in_(location_ids))
            .group_by(m.Device.location_id),
        )
        counts = dict(result.all())
        return {lid: counts.get(lid, 0) for lid in location_ids}

    async def to_schema_enriched(
        self,
        obj: m.Location | Sequence[m.Location],
        total: int | None = None,
        filters: Any | None = None,
    ) -> Any:
        """Convert model(s) to schema with computed device_count.

        Args:
            obj: Single model or sequence of models.
            total: Total count for pagination.
            filters: Filters for pagination.

        Returns:
            Schema or paginated schema response.
        """
        if isinstance(obj, m.Location):
            schema = self.to_schema(obj, schema_type=LocationSchema)
            count = await self.get_device_count(obj.id)
            object.__setattr__(schema, "device_count", count)
            return schema

        if total is not None and filters is not None:
            paginated = self.to_schema(obj, total, filters, schema_type=LocationSchema)
            location_ids = [loc.id for loc in obj]
            counts = await self.get_device_counts(location_ids)
            for loc_model, loc_schema in zip(obj, paginated.items, strict=False):
                object.__setattr__(loc_schema, "device_count", counts.get(loc_model.id, 0))
            return paginated

        schemas = []
        location_ids = [loc.id for loc in obj]
        counts = await self.get_device_counts(location_ids)
        for item in obj:
            schema = self.to_schema(item, schema_type=LocationSchema)
            object.__setattr__(schema, "device_count", counts.get(item.id, 0))
            schemas.append(schema)
        return schemas
