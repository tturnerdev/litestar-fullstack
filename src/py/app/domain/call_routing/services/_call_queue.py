"""Call queue service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.filters import CollectionFilter
from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class CallQueueService(service.SQLAlchemyAsyncRepositoryService[m.CallQueue]):
    """Handles CRUD operations on CallQueue resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.CallQueue]):
        """CallQueue Repository."""

        model_type = m.CallQueue

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.CallQueue]) -> ModelDictT[m.CallQueue]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException("A call queue with this name already exists.")
        return data


class CallQueueMemberService(service.SQLAlchemyAsyncRepositoryService[m.CallQueueMember]):
    """Handles CRUD operations on CallQueueMember resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.CallQueueMember]):
        """CallQueueMember Repository."""

        model_type = m.CallQueueMember

    repository_type = Repo
    match_fields = ["call_queue_id", "extension_id"]

    async def to_model_on_create(self, data: ModelDictT[m.CallQueueMember]) -> ModelDictT[m.CallQueueMember]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.CallQueueMember.call_queue_id == data["call_queue_id"],
                m.CallQueueMember.extension_id == data["extension_id"],
            )
            if existing:
                raise ValidationException("This extension is already a member of this call queue.")
        return data
