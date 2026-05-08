"""Time condition schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class TimeCondition(CamelizedBaseStruct):
    """Full time condition representation."""

    id: UUID
    team_id: UUID
    name: str
    match_destination: str
    no_match_destination: str
    override_mode: str
    schedule_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TimeConditionCreate(CamelizedBaseStruct):
    """Schema for creating a time condition."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    match_destination: Annotated[str, Meta(min_length=1, max_length=255)]
    no_match_destination: Annotated[str, Meta(min_length=1, max_length=255)]
    schedule_id: UUID | None = None
    override_mode: Annotated[str, Meta(min_length=1, max_length=50)] = "none"


class TimeConditionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a time condition."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    match_destination: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    no_match_destination: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    schedule_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    override_mode: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET


class TimeConditionOverride(CamelizedBaseStruct):
    """Schema for setting override mode on a time condition."""

    override_mode: Annotated[str, Meta(min_length=1, max_length=50)]
