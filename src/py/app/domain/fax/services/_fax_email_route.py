from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class FaxEmailRouteService(service.SQLAlchemyAsyncRepositoryService[m.FaxEmailRoute]):
    """Handles CRUD operations on FaxEmailRoute resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.FaxEmailRoute]):
        """FaxEmailRoute Repository."""

        model_type = m.FaxEmailRoute

    repository_type = Repo
    match_fields = ["fax_number_id", "email_address"]

    async def to_model_on_create(self, data: ModelDictT[m.FaxEmailRoute]) -> ModelDictT[m.FaxEmailRoute]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.FaxEmailRoute.fax_number_id == data["fax_number_id"],
                m.FaxEmailRoute.email_address == data["email_address"],
            )
            if existing:
                raise ValidationException("This email address is already routed to this fax number.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.FaxEmailRoute], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.FaxEmailRoute]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "fax_number_id" in data and "email_address" in data:
            existing = await self.repository.list(
                m.FaxEmailRoute.fax_number_id == data["fax_number_id"],
                m.FaxEmailRoute.email_address == data["email_address"],
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("This email address is already routed to this fax number.")
        return data
