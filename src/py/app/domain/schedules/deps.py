"""Schedule domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.schedules.services import ScheduleEntryService, ScheduleService
from app.lib.deps import create_service_provider

provide_schedules_service = create_service_provider(
    ScheduleService,
    load=[selectinload(m.Schedule.entries)],
    error_messages={"duplicate_key": "This schedule already exists.", "integrity": "Schedule operation failed."},
)

provide_schedule_entries_service = create_service_provider(
    ScheduleEntryService,
    error_messages={"duplicate_key": "This schedule entry already exists.", "integrity": "Schedule entry operation failed."},
)

__all__ = ("provide_schedule_entries_service", "provide_schedules_service")
