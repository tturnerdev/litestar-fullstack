"""Schedule schemas."""

import datetime as dt
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class ScheduleEntryList(CamelizedBaseStruct, kw_only=True):
    """Minimal schedule entry representation for lists."""

    id: UUID
    schedule_id: UUID
    start_time: dt.time
    end_time: dt.time
    day_of_week: int | None = None
    date: dt.date | None = None
    label: str | None = None
    is_closed: bool = False


class ScheduleEntryDetail(CamelizedBaseStruct, kw_only=True):
    """Full schedule entry representation."""

    id: UUID
    schedule_id: UUID
    start_time: dt.time
    end_time: dt.time
    day_of_week: int | None = None
    date: dt.date | None = None
    label: str | None = None
    is_closed: bool = False


class ScheduleEntryCreate(CamelizedBaseStruct, kw_only=True):
    """Schema for creating a schedule entry."""

    start_time: dt.time
    end_time: dt.time
    day_of_week: int | None = None
    date: dt.date | None = None
    label: str | None = None
    is_closed: bool = False


class ScheduleEntryUpdate(CamelizedBaseStruct, omit_defaults=True, kw_only=True):
    """Schema for updating a schedule entry."""

    day_of_week: int | msgspec.UnsetType | None = msgspec.UNSET
    start_time: dt.time | msgspec.UnsetType = msgspec.UNSET
    end_time: dt.time | msgspec.UnsetType = msgspec.UNSET
    date: dt.date | msgspec.UnsetType | None = msgspec.UNSET
    label: str | msgspec.UnsetType | None = msgspec.UNSET
    is_closed: bool | msgspec.UnsetType = msgspec.UNSET


class ScheduleList(CamelizedBaseStruct):
    """Minimal schedule representation for list views."""

    id: UUID
    name: str
    timezone: str
    is_default: bool
    schedule_type: str
    team_id: UUID


class ScheduleDetail(CamelizedBaseStruct, kw_only=True):
    """Full schedule representation with entries."""

    id: UUID
    name: str
    timezone: str
    is_default: bool
    schedule_type: str
    team_id: UUID
    entries: list[ScheduleEntryList] = []


class ScheduleCreate(CamelizedBaseStruct, kw_only=True):
    """Schema for creating a schedule."""

    name: str
    team_id: UUID
    timezone: str = "America/Chicago"
    is_default: bool = False
    schedule_type: str = "business_hours"


class ScheduleUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a schedule."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    timezone: str | msgspec.UnsetType = msgspec.UNSET
    is_default: bool | msgspec.UnsetType = msgspec.UNSET
    schedule_type: str | msgspec.UnsetType = msgspec.UNSET


class ScheduleCheckResponse(CamelizedBaseStruct, kw_only=True):
    """Response for checking if a schedule is currently open."""

    is_open: bool
    current_entry: ScheduleEntryDetail | None = None
    next_change_at: dt.datetime | None = None
