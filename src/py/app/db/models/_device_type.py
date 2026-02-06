from __future__ import annotations

from enum import StrEnum


class DeviceType(StrEnum):
    """Valid device types."""

    DESK_PHONE = "desk_phone"
    SOFTPHONE = "softphone"
    ATA = "ata"
    CONFERENCE = "conference"
    OTHER = "other"
