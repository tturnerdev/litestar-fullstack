from __future__ import annotations

from enum import StrEnum


class DeviceLineType(StrEnum):
    """Valid line types for device line assignments."""

    PRIVATE = "private"
    SHARED = "shared"
    MONITORED = "monitored"
