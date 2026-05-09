"""Ring group service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m

_DUPLICATE_NAME_MSG = "A ring group with this name already exists."
_DUPLICATE_MEMBER_MSG = "This extension is already a member of this ring group."

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class RingGroupService(service.SQLAlchemyAsyncRepositoryService[m.RingGroup]):
    """Handles CRUD operations on RingGroup resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroup]):
        """RingGroup Repository."""

        model_type = m.RingGroup

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.RingGroup]) -> ModelDictT[m.RingGroup]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing:
                raise ValidationException(_DUPLICATE_NAME_MSG)
        return data

    async def to_model_on_upsert(self, data: ModelDictT[m.RingGroup]) -> ModelDictT[m.RingGroup]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
        return data

    async def to_model_on_update(self, data: ModelDictT[m.RingGroup], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.RingGroup]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "name" in data:
            data["name"] = data["name"].strip()
            existing = await self.repository.list(
                CollectionFilter(field_name="name", values=[data["name"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException(_DUPLICATE_NAME_MSG)
        return data


class RingGroupMemberService(service.SQLAlchemyAsyncRepositoryService[m.RingGroupMember]):
    """Handles CRUD operations on RingGroupMember resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroupMember]):
        """RingGroupMember Repository."""

        model_type = m.RingGroupMember

    repository_type = Repo
    match_fields = ["ring_group_id", "extension_id"]

    async def to_model_on_create(self, data: ModelDictT[m.RingGroupMember]) -> ModelDictT[m.RingGroupMember]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.RingGroupMember.ring_group_id == data["ring_group_id"],
                m.RingGroupMember.extension_id == data["extension_id"],
            )
            if existing:
                raise ValidationException(_DUPLICATE_MEMBER_MSG)
        return data

    async def to_model_on_update(self, data: ModelDictT[m.RingGroupMember], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.RingGroupMember]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "extension_id" in data:
            ring_group_id = data.get("ring_group_id")
            if ring_group_id:
                existing = await self.repository.list(
                    m.RingGroupMember.ring_group_id == ring_group_id,
                    m.RingGroupMember.extension_id == data["extension_id"],
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException(_DUPLICATE_MEMBER_MSG)
        return data
