"""Time condition schemas."""

from uuid import UUID

import msgspec

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


class TimeConditionCreate(CamelizedBaseStruct):
    """Schema for creating a time condition."""

    name: str
    match_destination: str
    no_match_destination: str
    schedule_id: UUID | None = None
    override_mode: str = "none"


class TimeConditionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a time condition."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    match_destination: str | msgspec.UnsetType = msgspec.UNSET
    no_match_destination: str | msgspec.UnsetType = msgspec.UNSET
    schedule_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    override_mode: str | msgspec.UnsetType = msgspec.UNSET


class TimeConditionOverride(CamelizedBaseStruct):
    """Schema for setting override mode on a time condition."""

    override_mode: str
