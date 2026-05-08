"""Team invitation schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from msgspec import Meta

from app.db.models._team_roles import TeamRoles
from app.lib.schema import CamelizedBaseStruct


class TeamInvitationCreate(CamelizedBaseStruct):
    email: Annotated[str, Meta(min_length=1, max_length=255)]
    role: TeamRoles


class TeamInvitation(CamelizedBaseStruct):
    id: UUID
    email: str
    role: TeamRoles
    created_at: datetime
    updated_at: datetime
    is_accepted: bool = False
