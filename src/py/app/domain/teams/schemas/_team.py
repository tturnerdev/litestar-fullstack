"""Team schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.domain.teams.schemas._member import TeamMember
from app.lib.schema import CamelizedBaseStruct


class TeamTag(CamelizedBaseStruct):
    """Tag associated with a team."""

    id: UUID
    slug: str
    name: str


class Team(CamelizedBaseStruct):
    """Full team representation."""

    id: UUID
    name: str
    slug: str
    description: str | None = None
    is_active: bool = True
    members: list[TeamMember] = []
    tags: list[TeamTag] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TeamCreate(CamelizedBaseStruct):
    """Schema for creating a team."""

    name: Annotated[str, Meta(min_length=1, max_length=100)]
    description: Annotated[str, Meta(min_length=1, max_length=500)] | None = None
    tags: list[str] = []


class TeamUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a team."""

    name: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    description: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    tags: list[str] | msgspec.UnsetType | None = msgspec.UNSET
