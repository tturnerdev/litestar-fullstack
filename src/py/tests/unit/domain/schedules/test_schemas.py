"""Tests for schedule schema validation."""

from __future__ import annotations

import datetime as dt

import pytest

from app.domain.schedules.schemas._schedule import ScheduleEntryCreate


class TestScheduleEntryCreate:
    def test_valid(self) -> None:
        entry = ScheduleEntryCreate(
            start_time=dt.time(9, 0),
            end_time=dt.time(17, 0),
        )
        assert entry.start_time == dt.time(9, 0)
        assert entry.end_time == dt.time(17, 0)

    def test_start_after_end_raises(self) -> None:
        with pytest.raises(ValueError, match="start_time must be before end_time"):
            ScheduleEntryCreate(
                start_time=dt.time(17, 0),
                end_time=dt.time(9, 0),
            )

    def test_start_equals_end_raises(self) -> None:
        with pytest.raises(ValueError, match="start_time must be before end_time"):
            ScheduleEntryCreate(
                start_time=dt.time(12, 0),
                end_time=dt.time(12, 0),
            )

    def test_with_day_of_week(self) -> None:
        entry = ScheduleEntryCreate(
            start_time=dt.time(8, 0),
            end_time=dt.time(12, 0),
            day_of_week=1,
        )
        assert entry.day_of_week == 1

    def test_with_label(self) -> None:
        entry = ScheduleEntryCreate(
            start_time=dt.time(8, 0),
            end_time=dt.time(12, 0),
            label="Morning shift",
        )
        assert entry.label == "Morning shift"
