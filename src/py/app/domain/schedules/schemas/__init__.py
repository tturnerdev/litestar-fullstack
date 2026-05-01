"""Schedules domain schemas."""

from app.domain.schedules.schemas._schedule import (
    ScheduleCheckResponse,
    ScheduleCreate,
    ScheduleDetail,
    ScheduleEntryCreate,
    ScheduleEntryDetail,
    ScheduleEntryList,
    ScheduleEntryUpdate,
    ScheduleList,
    ScheduleUpdate,
)
from app.lib.schema import Message

__all__ = (
    "Message",
    "ScheduleCheckResponse",
    "ScheduleCreate",
    "ScheduleDetail",
    "ScheduleEntryCreate",
    "ScheduleEntryDetail",
    "ScheduleEntryList",
    "ScheduleEntryUpdate",
    "ScheduleList",
    "ScheduleUpdate",
)
