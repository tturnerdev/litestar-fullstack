"""Schedule type enum."""

from __future__ import annotations

from enum import StrEnum


class ScheduleType(StrEnum):
    """Valid schedule types."""

    BUSINESS_HOURS = "business_hours"
    HOLIDAY = "holiday"
    CUSTOM = "custom"
