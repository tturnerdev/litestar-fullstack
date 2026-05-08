"""Ring group service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class RingGroupService(service.SQLAlchemyAsyncRepositoryService[m.RingGroup]):
    """Handles CRUD operations on RingGroup resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroup]):
        """RingGroup Repository."""

        model_type = m.RingGroup

    repository_type = Repo
    match_fields = ["name"]


class RingGroupMemberService(service.SQLAlchemyAsyncRepositoryService[m.RingGroupMember]):
    """Handles CRUD operations on RingGroupMember resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroupMember]):
        """RingGroupMember Repository."""

        model_type = m.RingGroupMember

    repository_type = Repo

    async def to_model_on_create(self, data: ModelDictT[m.RingGroupMember]) -> ModelDictT[m.RingGroupMember]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.RingGroupMember.ring_group_id == data["ring_group_id"],
                m.RingGroupMember.extension_id == data["extension_id"],
            )
            if existing:
                raise ValidationException("This extension is already a member of this ring group.")
        return data
