from __future__ import annotations

from enum import StrEnum


class FeatureArea(StrEnum):
    """Feature areas available for team role permissions."""

    DEVICES = "DEVICES"
    VOICE = "VOICE"
    FAX = "FAX"
    SUPPORT = "SUPPORT"
    ORGANIZATION = "ORGANIZATION"
    TEAMS = "TEAMS"
