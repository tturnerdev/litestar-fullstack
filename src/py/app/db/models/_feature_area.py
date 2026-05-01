from __future__ import annotations

from enum import StrEnum


class FeatureArea(StrEnum):
    """Feature areas available for team role permissions."""

    CALL_ROUTING = "CALL_ROUTING"
    CONNECTIONS = "CONNECTIONS"
    DEVICES = "DEVICES"
    E911 = "E911"
    FAX = "FAX"
    LOCATIONS = "LOCATIONS"
    ORGANIZATION = "ORGANIZATION"
    SCHEDULES = "SCHEDULES"
    SUPPORT = "SUPPORT"
    TEAMS = "TEAMS"
    VOICE = "VOICE"
