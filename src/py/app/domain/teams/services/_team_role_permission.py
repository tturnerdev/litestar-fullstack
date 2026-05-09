from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

_DUPLICATE_ROLE_PERMISSION_MSG = "This permission already exists for this role."

if TYPE_CHECKING:
    from advanced_alchemy.service.typing import ModelDictT


class TeamRolePermissionService(service.SQLAlchemyAsyncRepositoryService[m.TeamRolePermission]):
    """Team Role Permission Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TeamRolePermission]):
        """Team Role Permission Repository."""

        model_type = m.TeamRolePermission

    repository_type = Repo
    match_fields = ["team_id", "role", "feature_area"]

    async def to_model_on_create(self, data: ModelDictT[m.TeamRolePermission]) -> ModelDictT[m.TeamRolePermission]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.TeamRolePermission.team_id == data["team_id"],
                m.TeamRolePermission.role == data["role"],
                m.TeamRolePermission.feature_area == data["feature_area"],
            )
            if existing:
                raise ValidationException(_DUPLICATE_ROLE_PERMISSION_MSG)
        return data

    async def to_model_on_update(self, data: ModelDictT[m.TeamRolePermission], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.TeamRolePermission]:
        data = service.schema_dump(data)
        if service.is_dict(data) and ("team_id" in data or "role" in data or "feature_area" in data):
            existing = await self.repository.list(
                m.TeamRolePermission.team_id == data["team_id"],
                m.TeamRolePermission.role == data["role"],
                m.TeamRolePermission.feature_area == data["feature_area"],
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException(_DUPLICATE_ROLE_PERMISSION_MSG)
        return data
