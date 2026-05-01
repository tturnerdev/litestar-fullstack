"""Schedule service."""

from __future__ import annotations

from datetime import datetime, time, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID
from zoneinfo import ZoneInfo

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.domain.schedules.schemas._schedule import ScheduleCheckResponse, ScheduleEntryDetail

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class ScheduleService(service.SQLAlchemyAsyncRepositoryService[m.Schedule]):
    """Handles CRUD operations on Schedule resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Schedule]):
        """Schedule Repository."""

        model_type = m.Schedule

    repository_type = Repo
    match_fields = ["name"]

    async def to_model_on_create(self, data: ModelDictT[m.Schedule]) -> ModelDictT[m.Schedule]:
        data = service.schema_dump(data)
        return data

    async def update(self, data: ModelDictT[m.Schedule], item_id: Any | None = None, **kwargs: Any) -> m.Schedule:
        """Update a schedule.

        Returns:
            The updated schedule object.
        """
        return await super().update(data, item_id=item_id, **kwargs)

    async def check_schedule(
        self,
        schedule_id: UUID,
        check_time: datetime | None = None,
    ) -> ScheduleCheckResponse:
        """Determine whether the schedule is open at a given time.

        Args:
            schedule_id: The schedule to check.
            check_time: The time to evaluate (defaults to now in the schedule's timezone).

        Returns:
            ScheduleCheckResponse indicating open/closed state and next transition.
        """
        schedule = await self.get(schedule_id)
        tz = ZoneInfo(schedule.timezone)

        if check_time is None:
            check_time = datetime.now(tz=tz)
        else:
            check_time = check_time.astimezone(tz)

        local_date = check_time.date()
        local_time = check_time.time()
        local_weekday = check_time.weekday()  # 0=Mon .. 6=Sun

        # Check holiday / specific-date entries first (higher priority)
        for entry in schedule.entries:
            if entry.date is not None and entry.date == local_date:
                if entry.is_closed:
                    # Closed for this specific date — find next opening
                    next_change = _find_next_open(schedule.entries, check_time, tz)
                    return ScheduleCheckResponse(is_open=False, current_entry=None, next_change_at=next_change)
                if entry.start_time <= local_time < entry.end_time:
                    entry_schema = _entry_to_schema(entry)
                    next_change = _make_aware(local_date, entry.end_time, tz)
                    return ScheduleCheckResponse(is_open=True, current_entry=entry_schema, next_change_at=next_change)

        # Check day-of-week entries
        for entry in schedule.entries:
            if entry.day_of_week is not None and entry.day_of_week == local_weekday and entry.date is None:
                if entry.is_closed:
                    next_change = _find_next_open(schedule.entries, check_time, tz)
                    return ScheduleCheckResponse(is_open=False, current_entry=None, next_change_at=next_change)
                if entry.start_time <= local_time < entry.end_time:
                    entry_schema = _entry_to_schema(entry)
                    next_change = _make_aware(local_date, entry.end_time, tz)
                    return ScheduleCheckResponse(is_open=True, current_entry=entry_schema, next_change_at=next_change)

        # No matching entry — schedule is closed
        next_change = _find_next_open(schedule.entries, check_time, tz)
        return ScheduleCheckResponse(is_open=False, current_entry=None, next_change_at=next_change)


class ScheduleEntryService(service.SQLAlchemyAsyncRepositoryService[m.ScheduleEntry]):
    """Handles CRUD operations on ScheduleEntry resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.ScheduleEntry]):
        """ScheduleEntry Repository."""

        model_type = m.ScheduleEntry

    repository_type = Repo


def _entry_to_schema(entry: m.ScheduleEntry) -> ScheduleEntryDetail:
    """Convert a ScheduleEntry model instance to a detail schema."""
    return ScheduleEntryDetail(
        id=entry.id,
        schedule_id=entry.schedule_id,
        day_of_week=entry.day_of_week,
        start_time=entry.start_time,
        end_time=entry.end_time,
        date=entry.date,
        label=entry.label,
        is_closed=entry.is_closed,
    )


def _make_aware(d: Any, t: time, tz: ZoneInfo) -> datetime:
    """Combine a date and time into a timezone-aware datetime."""
    return datetime.combine(d, t, tzinfo=tz)


def _find_next_open(
    entries: list[m.ScheduleEntry],
    check_time: datetime,
    tz: ZoneInfo,
) -> datetime | None:
    """Find the next time the schedule opens after check_time.

    Scans up to 7 days ahead for the nearest day-of-week entry that starts
    after the current time.

    Returns:
        Timezone-aware datetime of the next opening, or None if undetermined.
    """
    local_date = check_time.date()

    for day_offset in range(0, 8):
        candidate_date = local_date + timedelta(days=day_offset)
        candidate_weekday = candidate_date.weekday()

        for entry in entries:
            if entry.is_closed:
                continue

            # Match specific-date entries
            if entry.date is not None and entry.date == candidate_date:
                candidate_dt = _make_aware(candidate_date, entry.start_time, tz)
                if candidate_dt > check_time:
                    return candidate_dt

            # Match day-of-week entries (skip if a specific-date entry already handled this day)
            if entry.day_of_week is not None and entry.day_of_week == candidate_weekday and entry.date is None:
                candidate_dt = _make_aware(candidate_date, entry.start_time, tz)
                if candidate_dt > check_time:
                    return candidate_dt

    return None
