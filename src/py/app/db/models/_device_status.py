from __future__ import annotations

from enum import StrEnum


class DeviceStatus(StrEnum):
    """Valid device statuses."""

    ONLINE = "online"
    OFFLINE = "offline"
    RINGING = "ringing"
    IN_USE = "in_use"
    REBOOTING = "rebooting"
    PROVISIONING = "provisioning"
    ERROR = "error"
