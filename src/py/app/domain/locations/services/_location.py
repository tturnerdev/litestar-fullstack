"""Location service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m

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
