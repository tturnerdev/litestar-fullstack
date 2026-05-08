from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class TeamMemberService(service.SQLAlchemyAsyncRepositoryService[m.TeamMember]):
    """Team Member Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TeamMember]):
        """Team Member Repository."""

        model_type = m.TeamMember

    repository_type = Repo
    match_fields = ["user_id", "team_id"]

    async def to_model_on_create(self, data: ModelDictT[m.TeamMember]) -> ModelDictT[m.TeamMember]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.TeamMember.user_id == data["user_id"],
                m.TeamMember.team_id == data["team_id"],
            )
            if existing:
                raise ValidationException("This user is already a member of this team.")
        return data
