from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class UserRoleService(service.SQLAlchemyAsyncRepositoryService[m.UserRole]):
    """Handles database operations for user roles."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.UserRole]):
        """User Role SQLAlchemy Repository."""

        model_type = m.UserRole

    repository_type = Repo
    match_fields = ["user_id", "role_id"]

    async def to_model_on_create(self, data: ModelDictT[m.UserRole]) -> ModelDictT[m.UserRole]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.UserRole.user_id == data["user_id"],
                m.UserRole.role_id == data["role_id"],
            )
            if existing:
                raise ValidationException("This role is already assigned to this user.")
        return data
