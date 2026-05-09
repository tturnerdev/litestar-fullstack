from __future__ import annotations

from typing import Any

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

_DUPLICATE_TEAM_INVITATION_MSG = "An invitation for this email already exists in this team."


class TeamInvitationService(service.SQLAlchemyAsyncRepositoryService[m.TeamInvitation]):
    """Team Invitation Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TeamInvitation]):
        """Team Invitation Repository."""

        model_type = m.TeamInvitation

    repository_type = Repo
    match_fields = ["team_id", "email"]

    async def to_model_on_create(
        self, data: service.ModelDictT[m.TeamInvitation]
    ) -> service.ModelDictT[m.TeamInvitation]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            if "email" in data:
                data["email"] = data["email"].strip().lower()
            existing = await self.repository.list(
                m.TeamInvitation.team_id == data["team_id"],
                m.TeamInvitation.email == data["email"],
            )
            if existing:
                raise ValidationException(_DUPLICATE_TEAM_INVITATION_MSG)
        return await self._populate_inviter(data)

    async def to_model_on_update(
        self, data: service.ModelDictT[m.TeamInvitation], item_id: Any | None = None, **kwargs: Any
    ) -> service.ModelDictT[m.TeamInvitation]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "email" in data:
            data["email"] = data["email"].strip().lower()
            if "team_id" in data:
                existing = await self.repository.list(
                    m.TeamInvitation.team_id == data["team_id"],
                    m.TeamInvitation.email == data["email"],
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException(_DUPLICATE_TEAM_INVITATION_MSG)
        return await self._populate_inviter(data)

    async def to_model_on_upsert(
        self, data: service.ModelDictT[m.TeamInvitation]
    ) -> service.ModelDictT[m.TeamInvitation]:
        data = service.schema_dump(data)
        return await self._populate_inviter(data)

    async def _populate_inviter(
        self, data: service.ModelDictT[m.TeamInvitation]
    ) -> service.ModelDictT[m.TeamInvitation]:
        if not service.is_dict(data):
            return data
        if (inviter := data.pop("invited_by", None)) is None:
            return data
        if service.is_dict_without_field(data, "invited_by_id"):
            data["invited_by_id"] = inviter.id
        if service.is_dict_without_field(data, "invited_by_email"):
            data["invited_by_email"] = inviter.email
        return data
